package service

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"tools.bctechvibe.com/server/internal/modules/imap-migrator/models"
)

const (
	maxRecentErrors = 20
	jobTTL          = 30 * time.Minute // Time to keep snapshot after finish/cancel
	sseHeartbeat    = 15 * time.Second // Heartbeat to keep SSE connection alive
)

type Job struct {
	ID       string
	Mutex    sync.RWMutex
	Snapshot models.JobSnapshot

	subsMu    sync.Mutex
	subs      []chan models.SSEEvent
	closeOnce sync.Once
	isClosed  bool

	LogFile *os.File // Log file handler

	CancelCtx context.Context
	CancelFn  context.CancelFunc
}

const maxConcurrentJobs = 50

var (
	jobSem   = make(chan struct{}, maxConcurrentJobs)
	ipJobMap sync.Map

	// jobStore lưu lại job sau khi xong để user có thể fetch status (hỗ trợ reconnect/reload)
	jobStore sync.Map // map[string]*Job
)

// GetRunningJobsList returns a snapshot of all currently active jobs
func GetRunningJobsList() []models.JobSnapshot {
	var list []models.JobSnapshot
	jobStore.Range(func(key, value interface{}) bool {
		job := value.(*Job)
		job.Mutex.RLock()
		snapshot := job.Snapshot
		job.Mutex.RUnlock()
		if snapshot.Status == "running" {
			list = append(list, snapshot)
		}
		return true
	})
	return list
}

type RateLimitError struct{}

func (e *RateLimitError) Error() string {
	return "IP của bạn đang có tiến trình chạy. Vui lòng chờ tiến trình hiện tại hoàn tất."
}

type ServerBusyError struct {
	Max int
}

func (e *ServerBusyError) Error() string {
	return fmt.Sprintf("Hệ thống đang bận (%d tiến trình đang chạy). Vui lòng thử lại sau.", e.Max)
}

// ─── Job Creation ─────────────────────────────────────────────────────────────

// EnqueueJob puts a new job into the SQLite queue and memory store.
func EnqueueJob(req models.StartRequest, sessionID string) (*Job, error) {
	active, _ := CountActiveJobsBySession(sessionID)
	if active >= 20 {
		return nil, fmt.Errorf("bạn đã đạt giới hạn 20 tiến trình trong hàng đợi")
	}

	jobID := uuid.NewString()
	ctx, cancel := context.WithCancel(context.Background())

	job := &Job{
		ID:        jobID,
		CancelCtx: ctx,
		CancelFn:  cancel,
		Snapshot: models.JobSnapshot{
			JobID:           jobID,
			Status:          "pending",
			Mode:            req.Mode,
			SelectedFolders: req.Folders,
			StartedAt:       time.Now(),
			RecentErrors:    make([]string, 0),
			CanReconnect:    true,
		},
	}
	job.Snapshot.Source = req.Source.Host
	job.Snapshot.SourceUser = req.Source.Username
	job.Snapshot.Dest = req.Dest.Host
	job.Snapshot.DestUser = req.Dest.Username

	// Lưu vào SQLite
	if err := CreateJob(job, req, sessionID); err != nil {
		return nil, err
	}

	// Create log file for fallback
	logDir := filepath.Join(GetDataDir(), "logs")
	os.MkdirAll(logDir, 0755)
	logFile, err := os.OpenFile(filepath.Join(logDir, "job_"+job.ID+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		job.LogFile = logFile
	}

	jobStore.Store(job.ID, job)

	// Heartbeat để giữ kết nối SSE không đứt khi đang pending
	go job.RunHeartbeat()

	return job, nil
}

// ─── Job Retrieval ────────────────────────────────────────────────────────────

func GetJob(id string) (*Job, bool) {
	if val, ok := jobStore.Load(id); ok {
		return val.(*Job), true
	}
	return nil, false
}

// ─── Job Status Updates ───────────────────────────────────────────────────────

func (j *Job) GetSnapshot() models.JobSnapshot {
	j.Mutex.RLock()
	defer j.Mutex.RUnlock()
	// Return a copy
	return j.Snapshot
}

func (j *Job) UpdateProgress(copied, skipped, errors int, bytes int64) {
	j.Mutex.Lock()
	defer j.Mutex.Unlock()
	j.Snapshot.TotalCopied += copied
	j.Snapshot.TotalSkipped += skipped
	j.Snapshot.TotalErrors += errors
	j.Snapshot.CurrentFolderCopied += copied
	j.Snapshot.TotalBytes += bytes
}

func (j *Job) SetCurrentFolder(folder string, totalMail int) {
	j.Mutex.Lock()
	defer j.Mutex.Unlock()
	j.Snapshot.CurrentFolder = folder
	j.Snapshot.CurrentFolderTotal = totalMail
	j.Snapshot.CurrentFolderCopied = 0
}

func (j *Job) MarkFolderDone(folder string) {
	j.Mutex.Lock()
	defer j.Mutex.Unlock()
	j.Snapshot.CompletedFolders++
}

func (j *Job) SetTotalFolders(total int) {
	j.Mutex.Lock()
	defer j.Mutex.Unlock()
	j.Snapshot.TotalFolders = total
}

func (j *Job) AddError(err error) {
	if err == nil {
		return
	}
	j.Mutex.Lock()
	defer j.Mutex.Unlock()

	msg := FriendlyErrorMessage(err)
	j.Snapshot.LastError = msg

	j.Snapshot.RecentErrors = append(j.Snapshot.RecentErrors, msg)
	if len(j.Snapshot.RecentErrors) > maxRecentErrors {
		// remove oldest
		j.Snapshot.RecentErrors = j.Snapshot.RecentErrors[1:]
	}
	j.Snapshot.TotalErrors++
}

func (j *Job) MarkDone() {
	j.Mutex.Lock()

	if j.Snapshot.Status != "running" {
		j.Mutex.Unlock()
		return
	}

	now := time.Now()
	j.Snapshot.Status = "done"
	j.Snapshot.FinishedAt = &now
	j.Snapshot.CanReconnect = false

	event := models.SSEEvent{
		Type:         "COMPLETE",
		TotalFolders: j.Snapshot.TotalFolders,
		TotalCopied:  j.Snapshot.TotalCopied,
		TotalSkipped: j.Snapshot.TotalSkipped,
		TotalErrors:  j.Snapshot.TotalErrors,
	}

	j.Mutex.Unlock()

	j.Emit(event)
	UpdateJobStatus(j.ID, "done", "")
	j.closeEvents()
	j.scheduleCleanup()
	AppendHistory(j) // legacy history
	j.CancelFn()
}

func (j *Job) MarkError(err error) {
	j.Mutex.Lock()

	if j.Snapshot.Status != "running" {
		j.Mutex.Unlock()
		return
	}

	now := time.Now()
	j.Snapshot.Status = "error"
	j.Snapshot.FinishedAt = &now
	j.Snapshot.LastError = FriendlyErrorMessage(err)
	j.Snapshot.CanReconnect = false

	event := models.SSEEvent{
		Type:    "ERROR",
		Message: j.Snapshot.LastError,
	}

	j.Mutex.Unlock()

	j.Emit(event)
	UpdateJobStatus(j.ID, "error", j.Snapshot.LastError)
	j.closeEvents()
	j.scheduleCleanup()
	AppendHistory(j)
	j.CancelFn()
}

func (j *Job) Cancel() {
	j.Mutex.Lock()

	status := j.Snapshot.Status
	if status == "running" || status == "pending" {
		now := time.Now()
		j.Snapshot.Status = "cancelled"
		j.Snapshot.FinishedAt = &now
		j.Snapshot.CanReconnect = false

		event := models.SSEEvent{
			Type:    "ERROR",
			Message: "Tiến trình đồng bộ đã bị hủy bỏ",
		}

		j.Mutex.Unlock()

		j.Emit(event)
		UpdateJobStatus(j.ID, "cancelled", "Bị huỷ bởi người dùng")
		j.closeEvents()
		j.scheduleCleanup()
		AppendHistory(j)
		j.CancelFn() // signals context safely after status is set
	} else {
		j.Mutex.Unlock()
	}
}

func (j *Job) scheduleCleanup() {
	CleanupJobFiles(j.ID) // synchronous best-effort local storage cleanup

	// Let job linger in memory for jobTTL so clients can fetch status
	go func(id string) {
		time.Sleep(jobTTL)
		jobStore.Delete(id)
	}(j.ID)
}

// ─── SSE Emitter & Pub-Sub ──────────────────────────────────────────────────

func (j *Job) Subscribe() chan models.SSEEvent {
	j.subsMu.Lock()
	defer j.subsMu.Unlock()
	ch := make(chan models.SSEEvent, 50)
	if j.isClosed {
		close(ch)
	} else {
		j.subs = append(j.subs, ch)
	}
	return ch
}

func (j *Job) Unsubscribe(ch chan models.SSEEvent) {
	j.subsMu.Lock()
	defer j.subsMu.Unlock()
	for i, sub := range j.subs {
		if sub == ch {
			j.subs = append(j.subs[:i], j.subs[i+1:]...)
			close(ch)
			return
		}
	}
}

func (j *Job) Emit(event models.SSEEvent) {
	// Persist every meaningful event to SQLite
	if event.Type != "HEARTBEAT" && event.Type != "PROGRESS" && event.Type != "VERBOSE" {
		msg := event.Message
		if msg == "" && event.Folder != "" {
			event.Message = fmt.Sprintf("Event %s on %s", event.Type, event.Folder)
		}

		if strings.TrimSpace(event.Message) != "" || event.Type == "COMPLETE" || event.Type == "FOLDER_DONE" {
			PersistSSEEvent(j.ID, event)
		}
	}

	// Write to legacy file
	if j.LogFile != nil && event.Type != "HEARTBEAT" && event.Type != "PROGRESS" && event.Type != "VERBOSE" {
		timestamp := time.Now().Format("15:04:05")
		logLine := ""
		switch event.Type {
		case "FOLDER_START":
			logLine = fmt.Sprintf("[%s] [START] Thư mục: %s (%d emails)\n", timestamp, event.Folder, event.Total)
		case "FOLDER_DONE":
			if event.Errors > 0 && event.Message != "" {
				logLine = fmt.Sprintf("[%s] [ERROR] Thư mục: %s\n", timestamp, event.Message)
			} else {
				logLine = fmt.Sprintf("[%s] [DONE] Thư mục: %s\n", timestamp, event.Folder)
			}
		case "EMAIL_ERROR":
			logLine = fmt.Sprintf("[%s] [ERROR] %s\n", timestamp, event.Message)
		case "EMAIL_SKIPPED":
			logLine = fmt.Sprintf("[%s] [SKIPPED] %s\n", timestamp, event.Message)
		case "INFO":
			logLine = fmt.Sprintf("[%s] [INFO] %s\n", timestamp, event.Message)
		case "ERROR":
			logLine = fmt.Sprintf("[%s] [FATAL] %s\n", timestamp, event.Message)
		case "COMPLETE":
			logLine = fmt.Sprintf("[%s] [COMPLETE] Toàn bộ hoàn tất\n", timestamp)
		}
		if logLine != "" {
			j.LogFile.WriteString(logLine)
			offset, _ := j.LogFile.Seek(0, io.SeekCurrent)
			// Phát log này dưới dạng VERBOSE realtime cho UI
			verboseEv := models.SSEEvent{Type: "VERBOSE", Message: logLine, Offset: offset}
			j.subsMu.Lock()
			if !j.isClosed {
				for _, sub := range j.subs {
					select {
					case sub <- verboseEv:
					default:
					}
				}
			}
			j.subsMu.Unlock()
		}
	}

	// Sync progress occasionally
	if event.Type == "PROGRESS" || event.Type == "FOLDER_DONE" {
		UpdateJobProgress(j.ID, j.Snapshot)
	}

	j.subsMu.Lock()
	defer j.subsMu.Unlock()
	if j.isClosed {
		return
	}
	for _, sub := range j.subs {
		select {
		case sub <- event:
		default:
			// events channel full, drop safely
		}
	}
}

func (j *Job) closeEvents() {
	j.closeOnce.Do(func() {
		j.subsMu.Lock()
		defer j.subsMu.Unlock()
		j.isClosed = true
		for _, sub := range j.subs {
			close(sub)
		}
		j.subs = nil
	})
}

// RunHeartbeat starts a periodic heartbeat loop that emits ping events
// so that the browser SSE connection does not drop due to timeout
func (j *Job) RunHeartbeat() {
	ticker := time.NewTicker(sseHeartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-j.CancelCtx.Done():
			return
		case <-ticker.C:
			// Check if still running
			j.Mutex.RLock()
			status := j.Snapshot.Status
			j.Mutex.RUnlock()
			if status != "running" {
				return
			}

			j.Emit(models.SSEEvent{
				Type: "HEARTBEAT",
			})
		}
	}
}

// LogVerbose writes a raw string to the file and broadcasts to SSE clients.
// It skips SQLite to prevent DB bloat.
func (j *Job) LogVerbose(msg string) {
	var offset int64 = 0
	if j.LogFile != nil {
		j.LogFile.WriteString(fmt.Sprintf("%s\n", msg))
		offset, _ = j.LogFile.Seek(0, io.SeekCurrent)
	}
	j.Emit(models.SSEEvent{
		Type:    "VERBOSE",
		Message: msg,
		Offset:  offset,
	})
}
