package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/imap-migrator/models"
)

var globalSpoolSize atomic.Int64

const (
	spoolThreshold  = 5 * 1024 * 1024   // 5MB
	maxMessageBytes = 50 * 1024 * 1024  // 50MB
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

	// 1. Determine target folders
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

	// 2. Loop through folders
	for _, folderName := range targetFolders {
		select {
		case <-ctx.Done():
			// Cancelled
			return
		default:
		}

		err := migrateSingleFolder(ctx, job, src, dst, folderName)
		if err != nil {
			log.Error().Err(err).Str("folder", folderName).Msg("Lỗi khi migrate folder")
			job.AddError(fmt.Errorf("Lỗi folder %s: %v", folderName, err))
		}
		job.MarkFolderDone(folderName)
	}
}

func migrateSingleFolder(ctx context.Context, job *Job, src, dst *client.Client, folderName string) error {
	mbox, err := src.Select(folderName, true) // Read-only
	if err != nil {
		return err
	}

	total := mbox.Messages
	if total == 0 {
		job.Emit(models.SSEEvent{Type: "FOLDER_START", Folder: folderName, Total: 0})
		job.Emit(models.SSEEvent{Type: "FOLDER_DONE", Folder: folderName, Total: 0, Copied: 0})
		return nil
	}

	// Create folder at destination if not exists
	err = dst.Create(folderName)
	if err != nil {
		// Ignore if already exists
		msgLower := strings.ToLower(err.Error())
		if !strings.Contains(msgLower, "already exists") && !strings.Contains(msgLower, "exists") {
			return err
		}
	}

	job.SetCurrentFolder(folderName, int(total))
	job.Emit(models.SSEEvent{Type: "FOLDER_START", Folder: folderName, Total: int(total)})

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

		// Preflight Fetch: UID, Flags, InternalDate, Size
		metaChan := make(chan *imap.Message, batchSize)
		done := make(chan error, 1)
		go func() {
			done <- src.Fetch(seqset, []imap.FetchItem{
				imap.FetchUid,
				imap.FetchFlags,
				imap.FetchInternalDate,
				imap.FetchRFC822Size,
			}, metaChan)
		}()

		var metas []*imap.Message
		for msg := range metaChan {
			metas = append(metas, msg)
		}
		if err := <-done; err != nil {
			return err
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
				job.UpdateProgress(0, 1, 0)
				job.Emit(models.SSEEvent{
					Type:    "EMAIL_SKIPPED",
					Folder:  folderName,
					UID:     meta.Uid,
					Size:    int64(meta.Size),
					Message: fmt.Sprintf("Email vượt ngưỡng dung lượng %d bytes", maxMessageBytes),
				})
				continue
			}

			err := copyMessageToDest(ctx, src, dst, folderName, meta, job.ID)
			if err != nil {
				errorCount++
				job.AddError(err)
				job.Emit(models.SSEEvent{
					Type:    "EMAIL_ERROR",
					Folder:  folderName,
					UID:     meta.Uid,
					Message: FriendlyErrorMessage(err),
				})
				continue
			}

			copiedCount++
			job.UpdateProgress(1, 0, 0)
		}

		// Emit progress
		job.Emit(models.SSEEvent{
			Type:   "PROGRESS",
			Folder: folderName,
			Copied: copiedCount,
			Total:  int(total),
		})
	}

	job.Emit(models.SSEEvent{
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

func copyMessageToDest(ctx context.Context, src, dst *client.Client, folderName string, meta *imap.Message, jobID string) error {
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
	var cleanupTemp func() = func() {}

	if meta.Size > spoolThreshold {
		// Quota check
		if globalSpoolSize.Load()+int64(meta.Size) > maxGlobalSpool {
			return fmt.Errorf("Hệ thống quá tải file nhớ đệm, vui lòng thử lại sau")
		}
		globalSpoolSize.Add(int64(meta.Size))

		// Spool to file
		tempPath := filepath.Join(os.TempDir(), fmt.Sprintf("%s%s-%d.eml", tempPrefix, jobID, meta.Uid))
		f, err := os.Create(tempPath)
		if err != nil {
			globalSpoolSize.Add(-int64(meta.Size))
			// Disk full or permission error
			return fmt.Errorf("không thể tạo file tạm: %w", err)
		}

		var actualWritten int64 = int64(meta.Size)
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
		// actualWritten được cập nhật sau io.Copy để cleanupTemp dùng đúng lượng thực tế.
		// Go closure capture by reference nên defer sẽ thấy giá trị đã update.
		actualWritten = written

		// Reset file pointer for reading
		f.Seek(0, io.SeekStart)
		bodyReader = &exactLiteral{Reader: &contextReader{ctx: ctx, r: f}, length: int(written)}
	} else {
		// Inline buffer
		buf := new(bytes.Buffer)
		limitedR := io.LimitReader(r, spoolThreshold)
		ctxR := &contextReader{ctx: ctx, r: limitedR}

		written, err := io.Copy(buf, ctxR)
		if err != nil {
			return fmt.Errorf("lỗi đọc nội dung email: %w", err)
		}
		bodyReader = &exactLiteral{Reader: &contextReader{ctx: ctx, r: bytes.NewReader(buf.Bytes())}, length: int(written)}
	}

	// Consume remaining from done
	if err := <-done; err != nil {
		return err
	}

	// Wait, we need to ensure the destination accepts the APPEND without setting \Recent flag if possible,
	// but standard go-imap Append doesn't support specific flag sets perfectly if we don't pass them.
	// We pass exactly what we got from meta.Flags.
	var flags []string
	for _, flag := range meta.Flags {
		// Just to be safe, filter out any strange flags that might cause append error, like \Recent
		// Actually \Recent is read-only in some servers, let's filter it.
		if !strings.EqualFold(flag, "\\Recent") {
			flags = append(flags, flag)
		}
	}

	err := dst.Append(folderName, flags, meta.InternalDate, bodyReader)
	if err != nil {
		return fmt.Errorf("lỗi đẩy email sang máy chủ đích: %w", err)
	}

	return nil
}
