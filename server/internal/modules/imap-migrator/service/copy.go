package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/imap-migrator/models"
)

type ConnectionManager struct {
	Src *client.Client
	Dst *client.Client
	Req models.StartRequest
	Job *Job
}

// sliceElementsMatch checks if two slices of strings contain exactly the same elements, regardless of order
func sliceElementsMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aCopy := make([]string, len(a))
	bCopy := make([]string, len(b))
	copy(aCopy, a)
	copy(bCopy, b)
	
	sort.Strings(aCopy)
	sort.Strings(bCopy)
	
	for i := range aCopy {
		if !strings.EqualFold(aCopy[i], bCopy[i]) {
			return false
		}
	}
	return true
}

type DestMeta struct {
	Uid   uint32
	Flags []string
}

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "eof") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "closed network connection") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "i/o timeout")
}

func (cm *ConnectionManager) Reconnect(ctx context.Context, folderName string) error {
	cm.Job.Emit(models.SSEEvent{Type: "INFO", Folder: folderName, Message: "Kết nối đang bị ngắt, đang cố gắng kết nối lại ..."})

	var err error
	for i := 1; i <= 3; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if cm.Src != nil {
			cm.Src.Logout()
		}
		if cm.Dst != nil {
			cm.Dst.Logout()
		}

		cm.Src, err = Connect(ctx, cm.Req.Source)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		cm.Dst, err = Connect(ctx, cm.Req.Dest)
		if err != nil {
			cm.Src.Logout()
			time.Sleep(5 * time.Second)
			continue
		}

		// Re-select active folder on source
		_, err = cm.Src.Select(folderName, true)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		cm.Job.Emit(models.SSEEvent{Type: "INFO", Folder: folderName, Message: "Kết nối thành công, tiếp tục chuyển"})
		return nil
	}

	msg := "Không thể kết nối lại quá 3 lần, ngưng kết nối cho thư mục này."
	cm.Job.Emit(models.SSEEvent{Type: "ERROR", Folder: folderName, Message: msg})
	return fmt.Errorf("không thể kết nối lại: %v", err)
}

var globalSpoolSize atomic.Int64

const (
	spoolThreshold  = 5 * 1024 * 1024   // 5MB
	maxMessageBytes = 100 * 1024 * 1024 // 100MB
	maxGlobalSpool  = 500 * 1024 * 1024 // 500MB Limit for the entire VPS
	batchSize       = 200
)

// RunMigration starts the migration background process
func RunMigration(ctx context.Context, job *Job, req models.StartRequest) {
	// MarkDone will only transition the state to "done" if it is currently "running"
	// So if an error occurred / job was cancelled, MarkDone will safely return without overwriting the status.
	defer job.MarkDone()

	src, err := Connect(ctx, req.Source)
	if err != nil {
		job.MarkError(err)
		return
	}
	defer src.Logout()

	dst, err := Connect(ctx, req.Dest)
	if err != nil {
		job.MarkError(err)
		return
	}
	defer dst.Logout()

	if strings.ToUpper(req.Source.Security) == "NONE" || strings.ToUpper(req.Dest.Security) == "NONE" {
		job.Emit(models.SSEEvent{Type: "ERROR", Message: "CẢNH BÁO: Kết nối tới máy chủ phụ thuộc giao thức không mã hoá (NONE)."})
	}

	// 1. Build Flawless Mapping
	srcMailboxes, err := FetchServerMailboxes(ctx, src)
	if err != nil {
		job.MarkError(fmt.Errorf("Lỗi quét thư mục nguồn: %v", err))
		return
	}
	dstMailboxes, err := FetchServerMailboxes(ctx, dst)
	if err != nil {
		job.MarkError(fmt.Errorf("Lỗi quét thư mục đích: %v", err))
		return
	}
	folderMap := BuildFolderMap(srcMailboxes, dstMailboxes)

	// 2. Determine target folders
	var targetFolders []string
	if req.Mode == "selected" && len(req.Folders) > 0 {
		var errExp error
		targetFolders, errExp = ExpandRecursive(ctx, src, CanonicalizeSelection(req.Folders, "/"))
		if errExp != nil {
			job.MarkError(errExp)
			return
		}
	} else {
		// All folders
		mailboxes := make(chan *imap.MailboxInfo, 20)
		done := make(chan error, 1)
		go func() { done <- src.List("", "*", mailboxes) }()
		for mb := range mailboxes {
			if !IsGmailVirtualFolder(mb.Name) {
				targetFolders = append(targetFolders, mb.Name)
			}
		}
		if err := <-done; err != nil {
			job.MarkError(err)
			return
		}
	}

	job.SetTotalFolders(len(targetFolders))

	cm := &ConnectionManager{
		Src: src,
		Dst: dst,
		Req: req,
		Job: job,
	}

	// 2. Loop through folders
	for _, folderName := range targetFolders {
		select {
		case <-ctx.Done():
			// Cancelled
			return
		default:
		}

		dstFolder := folderMap[folderName]
		if dstFolder == "" {
			dstFolder = folderName // Extremely rare edge case fallback
		}

		err := migrateSingleFolder(ctx, cm, folderName, dstFolder)
		if err != nil {
			log.Error().Err(err).Str("src", folderName).Str("dst", dstFolder).Msg("Lỗi khi migrate folder")
			job.AddError(fmt.Errorf("[%s → %s]: %v", folderName, dstFolder, err))
		}
		job.MarkFolderDone(folderName)
	}
}

func migrateSingleFolder(ctx context.Context, cm *ConnectionManager, folderName string, dstFolder string) error {
	mbox, err := cm.Src.Select(folderName, true) // Read-only
	if err != nil {
		cm.Job.Emit(models.SSEEvent{Type: "FOLDER_START", Folder: folderName, Total: 0})
		cm.Job.Emit(models.SSEEvent{Type: "FOLDER_DONE", Folder: folderName, Total: 0, Errors: 1,
			Message: fmt.Sprintf("Không thể truy cập thư mục nguồn: %s", FriendlyErrorMessage(err))})
		return err
	}

	total := mbox.Messages

	// Emit FOLDER_START immediately so all folders appear in log
	cm.Job.Emit(models.SSEEvent{Type: "FOLDER_START", Folder: folderName, Total: int(total)})

	if total == 0 {
		cm.Job.Emit(models.SSEEvent{Type: "FOLDER_DONE", Folder: folderName, Total: 0, Copied: 0})
		return nil
	}

	// Create folder at destination if not exists
	err = cm.Dst.Create(dstFolder)
	if err != nil {
		// Ignore "already exists" responses from various IMAP servers.
		// Also ignore "completed" — some servers (e.g. Dovecot/TinoMail) return
		// "CREATE completed" as an OK status for system folders, which go-imap
		// incorrectly surfaces as an error.
		msgLower := strings.ToLower(err.Error())
		isHarmless := strings.Contains(msgLower, "already exists") ||
			strings.Contains(msgLower, "mailbox exists") ||
			strings.Contains(msgLower, "alreadyexists") ||
			strings.Contains(msgLower, "exists") ||
			strings.Contains(msgLower, "completed")
		if !isHarmless {
			cm.Job.Emit(models.SSEEvent{Type: "FOLDER_DONE", Folder: folderName, Total: int(total), Errors: 1,
				Message: fmt.Sprintf("[%s → %s] Không thể tạo thư mục đích: %s", folderName, dstFolder, err.Error())})
			return err
		}
	}

	dstMbox, err := cm.Dst.Select(dstFolder, false)
	if err != nil {
		cm.Job.Emit(models.SSEEvent{Type: "FOLDER_DONE", Folder: folderName, Total: int(total), Errors: 1,
			Message: fmt.Sprintf("Không thể truy cập thư mục đích %s: %s", dstFolder, err.Error())})
		return err
	}

	// PREFLIGHT: Cache destination Message-IDs to prevent duplicates
	destMap := make(map[string]DestMeta)
	if totalDst := dstMbox.Messages; totalDst > 0 {
		seqDst := new(imap.SeqSet)
		seqDst.AddRange(1, totalDst)

		dstMetaChan := make(chan *imap.Message, batchSize)
		dstDone := make(chan error, 1)
		go func() {
			dstDone <- cm.Dst.Fetch(seqDst, []imap.FetchItem{
				imap.FetchUid, imap.FetchEnvelope, imap.FetchFlags,
			}, dstMetaChan)
		}()
		for msg := range dstMetaChan {
			if msg.Envelope != nil && msg.Envelope.MessageId != "" {
				destMap[msg.Envelope.MessageId] = DestMeta{
					Uid:   msg.Uid,
					Flags: msg.Flags,
				}
			}
		}
		<-dstDone // Ignore fetch errors here, map will just be partial
	}

	cm.Job.SetCurrentFolder(folderName, int(total))

	var copiedCount, skippedCount, errorCount int

	// Process in batches
	for start := uint32(1); start <= total; start += batchSize {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		end := start + batchSize - 1
		if end > total {
			end = total
		}

		seqset := new(imap.SeqSet)
		seqset.AddRange(start, end)

		// Retry fetch up to 3 times on network err
		var errFetch error
		var metas []*imap.Message

		for fetchRetry := 0; fetchRetry < 3; fetchRetry++ {
			metaChan := make(chan *imap.Message, batchSize)
			done := make(chan error, 1)
			go func() {
				done <- cm.Src.Fetch(seqset, []imap.FetchItem{
					imap.FetchUid, imap.FetchFlags, imap.FetchInternalDate, imap.FetchRFC822Size, imap.FetchEnvelope,
				}, metaChan)
			}()

			metas = nil
			for msg := range metaChan {
				metas = append(metas, msg)
			}
			errFetch = <-done
			if errFetch == nil {
				break
			}
			
			if isNetworkError(errFetch) {
				if errRecon := cm.Reconnect(ctx, folderName); errRecon != nil {
					return errRecon // Abort folder on deep reconnect failure
				}
				continue // retry fetch loop
			}
			break // if valid logic error, let it pass to block below
		}

		if errFetch != nil {
			return errFetch
		}

		// Process each message in the batch individually to control resources
		for _, meta := range metas {
			select {
			case <-ctx.Done():
				return nil
			default:
			}

			if meta.Size > maxMessageBytes {
				skippedCount++
				cm.Job.UpdateProgress(0, 1, 0)
				cm.Job.Emit(models.SSEEvent{
					Type:    "EMAIL_SKIPPED",
					Folder:  folderName,
					UID:     meta.Uid,
					Size:    int64(meta.Size),
					Message: fmt.Sprintf("Email vượt ngưỡng dung lượng %d bytes", maxMessageBytes),
				})
				continue
			}

			// Normalizing source flags
			var srcFlags []string
			for _, flag := range meta.Flags {
				if !strings.EqualFold(flag, "\\Recent") && !strings.Contains(flag, "$") {
					srcFlags = append(srcFlags, flag)
				}
			}

			// CHECK IDEMPOTENCY (Avoid duplicates)
			if meta.Envelope != nil && meta.Envelope.MessageId != "" {
				if dMeta, exists := destMap[meta.Envelope.MessageId]; exists {
					// Email exists. Check if we need to sync flags only
					if !sliceElementsMatch(srcFlags, dMeta.Flags) {
						seqStore := new(imap.SeqSet)
						seqStore.AddNum(dMeta.Uid)
						item := imap.FormatFlagsOp(imap.SetFlags, true)
						errStore := cm.Dst.UidStore(seqStore, item, srcFlags, nil)
						if errStore != nil {
							log.Warn().Err(errStore).Str("MessageId", meta.Envelope.MessageId).Msg("Lỗi cập nhật Cờ ở máy đích")
						} else {
							// Update local map
							dMeta.Flags = srcFlags
							destMap[meta.Envelope.MessageId] = dMeta
						}
					}

					copiedCount++ // Treat as processed completely
					cm.Job.UpdateProgress(1, 0, 0)
					continue      // Skip downloading body
				}
			}

			// Message-level retry loop (max 3 times) for network connectivity drops
			for retryCount := 0; retryCount < 3; retryCount++ {
				err := copyMessageToDest(ctx, cm.Src, cm.Dst, dstFolder, meta, cm.Job.ID)
				if err != nil {
					if isNetworkError(err) {
						if errRecon := cm.Reconnect(ctx, folderName); errRecon != nil {
							return errRecon // Fail early out of the entire migrating batch loop
						}
						continue // Retry this email copy loop
					}
					
					// Non-network error, just skip message correctly
					errorCount++
					cm.Job.AddError(err)
					cm.Job.Emit(models.SSEEvent{
						Type:    "EMAIL_ERROR",
						Folder:  folderName,
						UID:     meta.Uid,
						Message: err.Error(),
					})
					break // break retry, go to next message
				}

				// Success
				copiedCount++
				cm.Job.UpdateProgress(1, 0, 0)
				break // break retry loop, move to next email
			}
		}

		// Emit progress
		cm.Job.Emit(models.SSEEvent{
			Type:   "PROGRESS",
			Folder: folderName,
			Copied: copiedCount,
			Total:  int(total),
		})
	}

	cm.Job.Emit(models.SSEEvent{
		Type:    "FOLDER_DONE",
		Folder:  folderName,
		Total:   int(total),
		Copied:  copiedCount,
		Skipped: skippedCount,
		Errors:  errorCount,
	})

	return nil
}

type exactLiteral struct {
	io.Reader
	length int
}

func (e *exactLiteral) Len() int {
	return e.length
}

// contextReader makes any io.Reader context-aware
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (cr *contextReader) Read(p []byte) (n int, err error) {
	select {
	case <-cr.ctx.Done():
		return 0, cr.ctx.Err()
	default:
		return cr.r.Read(p)
	}
}

func copyMessageToDest(ctx context.Context, src, dst *client.Client, dstFolder string, meta *imap.Message, jobID string) error {
	seq := new(imap.SeqSet)
	seq.AddNum(meta.Uid)

	section := &imap.BodySectionName{Peek: true}
	bodyChan := make(chan *imap.Message, 1)
	done := make(chan error, 1)

	go func() {
		done <- src.UidFetch(seq, []imap.FetchItem{section.FetchItem()}, bodyChan)
	}()

	msg := <-bodyChan
	if msg == nil {
		if err := <-done; err != nil {
			return err
		}
		return fmt.Errorf("không thể tải nội dung email UID %d", meta.Uid)
	}

	// We have the body, now get the reader
	r := msg.GetBody(section)
	if r == nil {
		return fmt.Errorf("không tìm thấy nội dung (body) của email UID %d", meta.Uid)
	}

	var bodyReader imap.Literal
	
	// Track disk/memory usage - Atomic check-and-add pattern
	for {
		current := globalSpoolSize.Load()
		if current+int64(meta.Size) > maxGlobalSpool {
			return fmt.Errorf("Hệ thống quá tải file nhớ đệm/ram trễ, vui lòng thử lại sau")
		}
		if globalSpoolSize.CompareAndSwap(current, current+int64(meta.Size)) {
			break
		}
		// CAS failed (có goroutine khác vừa update), retry loop
	}

	var actualWritten int64 = int64(meta.Size)
	var cleanupTemp func()

	if meta.Size > spoolThreshold {
		// Spool to file
		tempPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s%s-%d.eml", tempPrefix, jobID, meta.Uid))
		f, err := os.Create(tempPath)
		if err != nil {
			globalSpoolSize.Add(-int64(meta.Size))
			// Disk full or permission error
			return fmt.Errorf("không thể tạo file tạm: %w", err)
		}

		cleanupTemp = func() {
			f.Close()
			os.Remove(tempPath)
			globalSpoolSize.Add(-actualWritten)
		}
		defer cleanupTemp()

		// Limit reading to prevent unexpected memory/disk bursts
		limitedR := io.LimitReader(r, maxMessageBytes)
		ctxR := &contextReader{ctx: ctx, r: limitedR}

		written, err := io.Copy(f, ctxR)
		if err != nil {
			return fmt.Errorf("lỗi ghi file tạm (ngắt kết nối): %w", err)
		}

		// Hoàn trả phần chênh lệch do server báo láo estimate size trước đó
		globalSpoolSize.Add(written - int64(meta.Size))
		actualWritten = written

		// Reset file pointer for reading
		f.Seek(0, io.SeekStart)
		bodyReader = &exactLiteral{Reader: &contextReader{ctx: ctx, r: f}, length: int(written)}
	} else {
		// Inline buffer
		cleanupTemp = func() {
			globalSpoolSize.Add(-actualWritten)
		}
		defer cleanupTemp()
		
		buf := new(bytes.Buffer)
		limitedR := io.LimitReader(r, spoolThreshold)
		ctxR := &contextReader{ctx: ctx, r: limitedR}

		written, err := io.Copy(buf, ctxR)
		if err != nil {
			return fmt.Errorf("lỗi đọc nội dung email: %w", err)
		}
		
		globalSpoolSize.Add(written - int64(meta.Size))
		actualWritten = written
		
		bodyReader = &exactLiteral{Reader: &contextReader{ctx: ctx, r: bytes.NewReader(buf.Bytes())}, length: int(written)}
	}

	// Consume remaining from done
	if err := <-done; err != nil {
		return err
	}

	// Normalizing Flags
	var flags []string
	for _, flag := range meta.Flags {
		// Ignore \Recent and potentially problematic custom flags
		if !strings.EqualFold(flag, "\\Recent") && !strings.Contains(flag, "$") {
			flags = append(flags, flag)
		}
	}

	// Normalizing Date
	internalDate := meta.InternalDate
	if internalDate.IsZero() {
		internalDate = time.Now()
	}

	err := dst.Append(dstFolder, flags, internalDate, bodyReader)
	if err != nil {
		// Special go-imap catch: Server rejected APPEND immediately (likely Size/Quota limit)
		if strings.Contains(err.Error(), "no continuation request") {
			return fmt.Errorf("server đích từ chối nhận email này (khả năng do hòm thư đã đầy hoặc email đính kèm quá lớn vượt giới hạn tải lên của máy chủ)")
		}
		return fmt.Errorf("lỗi đẩy email sang máy chủ đích: %w", err)
	}

	return nil
}
