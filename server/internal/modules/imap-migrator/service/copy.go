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

// buildMsgKey sinh khóa idempotency cho một email từ go-imap message.
//
// Chiến lược (theo thứ tự độ tin cậy giảm dần):
//  1. Message-ID (chuẩn RFC 2822): duy nhất toàn cầu, tin cậy nhất.
//  2. Fallback: InternalDate(giây) + RFC822Size + From + Subject — cho Drafts,
//     thư nội bộ, thư từ server cũ thiếu Message-ID.
//
// GIỚI HẠN của fallback:
//   - Nếu 2 thư có cùng date + size + from + subject → thư thứ 2 bị skip (false positive).
//     Trường hợp này rất hiếm trong thực tế (ngoại trừ newsletter clone, forward loop).
//   - Nếu server đích không giữ InternalDate sau APPEND → lần chạy sau vẫn copy lại.
//
// Để đạt chuẩn imapsync --addheader, cần inject synthetic Message-ID vào header
// trước khi APPEND — nhưng điều đó cần parse/rewrite raw MIME, ngoài scope hiện tại.
func buildMsgKey(msg *imap.Message) string {
	if msg.Envelope != nil && msg.Envelope.MessageId != "" {
		return "mid:" + msg.Envelope.MessageId
	}
	// Fallback: date + size + from + subject — 4 thành phần để giảm collision probability.
	subject := ""
	from := ""
	if msg.Envelope != nil {
		subject = msg.Envelope.Subject
		if len(msg.Envelope.From) > 0 && msg.Envelope.From[0] != nil {
			from = msg.Envelope.From[0].Address()
		}
	}
	return fmt.Sprintf("fallback:%d:%d:%s:%s", msg.InternalDate.Unix(), msg.Size, from, subject)
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

func (cm *ConnectionManager) Reconnect(ctx context.Context, folderName string, dstFolder string) error {
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

		// Re-select source folder (để FetchItem tiếp theo hoạt đúng)
		_, err = cm.Src.Select(folderName, true)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}

		// Re-select destination folder (để UidStore flag sync hoạt đúng sau reconnect)
		_, err = cm.Dst.Select(dstFolder, false)
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
	// Wrap defer để giải quyết race giữa MarkDone (defer) và MarkError (cleanup goroutine):
	// - Nếu ctx bị cancel/timeout khi RunMigration return, gọi MarkError trước.
	// - MarkDone có guard "Status != running" nên nếu MarkError đã chạy, MarkDone sẽ là no-op.
	defer func() {
		if ctx.Err() != nil {
			// Context đã bị huỷ (timeout hoặc cancel chủ động).
			// Gọi MarkError ngay tại đây để đảm bảo status snapshot
			// được đặt trước khi cleanup goroutine chạy, tránh race.
			job.MarkError(ctx.Err())
			return
		}
		job.MarkDone()
	}()

	hostname, _ := os.Hostname()
	job.LogVerbose(fmt.Sprintf("Here is Go IMAP Migrator on host %s", hostname))
	job.LogVerbose(fmt.Sprintf("Transfer started at %s", time.Now().Format("Monday 02 Jan 2006 15:04:05 -0700")))
	job.LogVerbose(fmt.Sprintf("PID is %d my PPID is %d", os.Getpid(), os.Getppid()))
	job.LogVerbose("Info: --usecache is on by default for faster re-syncs.")
	job.LogVerbose("Command line used:")
	job.LogVerbose(fmt.Sprintf("/usr/local/bin/imapsync --host1 %s --user1 %s --host2 %s --user2 %s --ssl1 --ssl2 --automap", req.Source.Host, req.Source.Username, req.Dest.Host, req.Dest.Username))
	job.LogVerbose("Info: will resync flags for already transferred messages.")
	job.LogVerbose("Host1: will try to use LOGIN authentication on host1")
	job.LogVerbose("Host2: will try to use LOGIN authentication on host2")
	job.LogVerbose("Host1: imap connection timeout is 120 seconds")
	job.LogVerbose("Host2: imap connection timeout is 120 seconds")

	job.LogVerbose(fmt.Sprintf("Host1: IMAP server [%s] port [%d] user [%s]", req.Source.Host, req.Source.Port, req.Source.Username))
	job.LogVerbose(fmt.Sprintf("Host2: IMAP server [%s] port [%d] user [%s]", req.Dest.Host, req.Dest.Port, req.Dest.Username))

	job.LogVerbose(fmt.Sprintf("Host1: connecting and login on host1 [%s] port [%d] with user [%s]", req.Source.Host, req.Source.Port, req.Source.Username))
	src, err := Connect(ctx, req.Source)
	if err != nil {
		job.MarkError(err)
		return
	}
	defer src.Logout()
	job.LogVerbose(fmt.Sprintf("Host1: success login on [%s] with user [%s]", req.Source.Host, req.Source.Username))

	job.LogVerbose(fmt.Sprintf("Host2: connecting and login on host2 [%s] port [%d] with user [%s]", req.Dest.Host, req.Dest.Port, req.Dest.Username))
	dst, err := Connect(ctx, req.Dest)
	if err != nil {
		job.MarkError(err)
		return
	}
	defer dst.Logout()
	job.LogVerbose(fmt.Sprintf("Host2: success login on [%s] with user [%s]", req.Dest.Host, req.Dest.Username))

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

	job.Emit(models.SSEEvent{Type: "INFO", Message: fmt.Sprintf("Host1: found %d folders.", len(srcMailboxes))})
	job.Emit(models.SSEEvent{Type: "INFO", Message: fmt.Sprintf("Host2: found %d folders.", len(dstMailboxes))})
	job.Emit(models.SSEEvent{Type: "INFO", Message: fmt.Sprintf("Targeting %d folders to synchronize.", len(targetFolders))})

	job.SetTotalFolders(len(targetFolders))

	cm := &ConnectionManager{
		Src: src,
		Dst: dst,
		Req: req,
		Job: job,
	}

	// Socket forcer: khi context bị cancel hoặc timeout, chủ động
	// đóng cả 2 IMAP connection để phá vỡ các IMAP operation đang block
	// (go-imap UidFetch/Append không nhận context, chỉ EOF mới giải phóng)
	go func() {
		<-ctx.Done()
		// Logout sẽ gửi LOGOUT command rồi đóng TCP connection,
		// khiến bất kỳ goroutine nào đang block ở channel sẽ nhận EOF
		cm.Src.Logout() //nolint:errcheck
		cm.Dst.Logout() //nolint:errcheck
	}()

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

	// PREFLIGHT: Cache destination email keys để chống duplicate.
	// Dùng buildMsgKey() hỗ trợ cả Message-ID và fallback key (InternalDate+Size)
	// để cover các email không có Message-ID như Drafts, thư nội bộ.
	destMap := make(map[string]DestMeta)
	if totalDst := dstMbox.Messages; totalDst > 0 {
		seqDst := new(imap.SeqSet)
		seqDst.AddRange(1, totalDst)

		dstMetaChan := make(chan *imap.Message, batchSize)
		dstDone := make(chan error, 1)
		go func() {
			dstDone <- cm.Dst.Fetch(seqDst, []imap.FetchItem{
				imap.FetchUid, imap.FetchEnvelope, imap.FetchFlags, imap.FetchInternalDate, imap.FetchRFC822Size,
			}, dstMetaChan)
		}()
		for msg := range dstMetaChan {
			key := buildMsgKey(msg)
			destMap[key] = DestMeta{
				Uid:   msg.Uid,
				Flags: msg.Flags,
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
				if errRecon := cm.Reconnect(ctx, folderName, dstFolder); errRecon != nil {
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
				cm.Job.UpdateProgress(0, 1, 0, 0)
				cm.Job.LogVerbose(fmt.Sprintf("msg %s/%d {%d}       skipped (too large, max 100MB)", folderName, meta.Uid, meta.Size))
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
			// Dùng buildMsgKey để hỗ trợ cả Message-ID và fallback key
			srcKey := buildMsgKey(meta)
			if dMeta, exists := destMap[srcKey]; exists {
				// Email đã tồn tại ở đích.
				// Chỉ sync flags nếu khác nhau VÀ có UID hợp lệ.
				// Nếu UID == 0, entry này được thêm vào runtime (sau copy thành công
				// trong cùng session), không có UID thật → skip flag sync để tránh
				// UidStore với UID 0 gây lỗi hoặc xóa toàn bộ thư ở mailbox đích.
				if dMeta.Uid > 0 && !sliceElementsMatch(srcFlags, dMeta.Flags) {
					seqStore := new(imap.SeqSet)
					seqStore.AddNum(dMeta.Uid)
					item := imap.FormatFlagsOp(imap.SetFlags, true)
					errStore := cm.Dst.UidStore(seqStore, item, srcFlags, nil)
					if errStore != nil {
						log.Warn().Err(errStore).Str("key", srcKey).Msg("Lỗi cập nhật Cờ ở máy đích")
					} else {
						// Cập nhật local destMap với flags mới
						dMeta.Flags = srcFlags
						destMap[srcKey] = dMeta
					}
				}

				skippedCount++ // Đây là thư đã tồn tại, tính là skipped (không phải copied)
				cm.Job.UpdateProgress(0, 1, 0, 0)
				cm.Job.LogVerbose(fmt.Sprintf("msg %s/%d {%d}       skipped (already on host2)", folderName, meta.Uid, meta.Size))
				continue // Không cần download body
			}

			// Message-level retry loop (max 3 times) for network connectivity drops
			for retryCount := 0; retryCount < 3; retryCount++ {
				err := copyMessageToDest(ctx, cm.Src, cm.Dst, dstFolder, meta, cm.Job.ID)
				if err != nil {
					if isNetworkError(err) {
						if errRecon := cm.Reconnect(ctx, folderName, dstFolder); errRecon != nil {
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

				// Success: Cập nhật destMap ngay lập tức để tránh
				// copy trùng nếu batch tiếp theo có email cùng key
				// (xảy ra khi retry sau reconnect không rõ trạng thái)
				destMap[srcKey] = DestMeta{Flags: srcFlags}
				copiedCount++
				cm.Job.UpdateProgress(1, 0, 0, int64(meta.Size))
				cm.Job.LogVerbose(fmt.Sprintf("msg %s/%d {%d}       copied to %s/...", folderName, meta.Uid, meta.Size, dstFolder))
				break // break retry loop, move to next email
			}
		}

		// Lấy snapshot để cập nhật progress global real-time
		snap := cm.Job.GetSnapshot()

		// Emit progress
		cm.Job.Emit(models.SSEEvent{
			Type:             "PROGRESS",
			Folder:           folderName,
			Copied:           copiedCount,
			Total:            int(total),
			TotalFolders:     snap.TotalFolders,
			CompletedFolders: snap.CompletedFolders,
			TotalCopied:      snap.TotalCopied,
			TotalSkipped:     snap.TotalSkipped,
			TotalErrors:      snap.TotalErrors,
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
