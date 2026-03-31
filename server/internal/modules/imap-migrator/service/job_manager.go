package service

import (
	"context"
	"fmt"
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
	ID        string
	Mutex     sync.RWMutex
	Snapshot  models.JobSnapshot

	subsMu    sync.Mutex
	subs      []chan models.SSEEvent
	closeOnce sync.Once
	isClosed  bool

	CancelCtx context.Context
	CancelFn  context.CancelFunc
}

const maxConcurrentJobs = 3

var (
	jobSem   = make(chan struct{}, maxConcurrentJobs)
	ipJobMap sync.Map
	
	// jobStore lưu lại job sau khi xong để user có thể fetch status (hỗ trợ reconnect/reload)
	jobStore sync.Map // map[string]*Job
)

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

// CreateAndStartJob starts a new job subject to concurrency and IP limits.
func CreateAndStartJob(req models.StartRequest, clientIP string) (*Job, error) {
	// Check per-IP limit atomically to avoid race condition
	if _, loaded := ipJobMap.LoadOrStore(clientIP, ""); loaded {
		return nil, &RateLimitError{}
	}

	// Check global concurrent limit
	select {
	case jobSem <- struct{}{}:
	default:
		// Rollback IP claim if system is busy
		ipJobMap.Delete(clientIP)
		return nil, &ServerBusyError{Max: maxConcurrentJobs}
	}

	const maxJobDuration = 4 * time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), maxJobDuration)

	job := &Job{
		ID:        uuid.NewString(),
		CancelCtx: ctx,
		CancelFn:  cancel,
		Snapshot: models.JobSnapshot{
			JobID:           "", // Set below
			Status:          "running",
			Mode:            req.Mode,
			SelectedFolders: req.Folders,
			StartedAt:       time.Now(),
			RecentErrors:    make([]string, 0),
			CanReconnect:    true,
		},
	}
	job.Snapshot.JobID = job.ID

	ipJobMap.Store(clientIP, job.ID)
	jobStore.Store(job.ID, job)

	// Start a single heartbeat routine for this job
	go job.RunHeartbeat()

	// Cleanup goroutine to release semaphore and IP lock when job is done/cancelled
	go func() {
		<-job.CancelCtx.Done()
		<-jobSem
		ipJobMap.Delete(clientIP)
	}()

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

func (j *Job) UpdateProgress(copied, skipped, errors int) {
	j.Mutex.Lock()
	defer j.Mutex.Unlock()
	j.Snapshot.TotalCopied += copied
	j.Snapshot.TotalSkipped += skipped
	j.Snapshot.TotalErrors += errors
}

func (j *Job) SetCurrentFolder(folder string, totalMail int) {
	j.Mutex.Lock()
	defer j.Mutex.Unlock()
	j.Snapshot.CurrentFolder = folder
	// We don't track totalMail in Snapshot here, but we could if we wanted to
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
	j.closeEvents()
	j.CancelFn()
	j.scheduleCleanup()
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
	j.closeEvents()
	j.CancelFn()
	j.scheduleCleanup()
}

func (j *Job) Cancel() {
	j.Mutex.Lock()
	
	if j.Snapshot.Status == "running" {
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
		j.closeEvents()
		j.scheduleCleanup()
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
