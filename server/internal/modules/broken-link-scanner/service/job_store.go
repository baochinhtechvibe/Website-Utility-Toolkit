package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"
)

const (
	jobTTL         = 30 * time.Minute
	progressBufSize = 64
)

// Job holds the complete state of one async scan job.
type Job struct {
	ID         string
	Status     models.JobStatus
	Req        models.ScanRequest
	Data       *models.ScanData
	Err        error
	ProgressCh chan models.ProgressEvent // closed when job finishes
	CancelFn   context.CancelFunc
	CreatedAt  time.Time
	FinishedAt time.Time
	CacheFn    func(models.ScanData) // callback to cache result when done

	mu        sync.Mutex
	closeOnce sync.Once
}

func (j *Job) setDone(data models.ScanData) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.Status == models.JobStatusCanceled {
		return
	}
	j.Status = models.JobStatusDone
	j.Data = &data
	j.FinishedAt = time.Now()
	j.closeOnce.Do(func() { close(j.ProgressCh) })
}

func (j *Job) setError(err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.Status == models.JobStatusCanceled {
		return
	}
	j.Status = models.JobStatusError
	j.Err = err
	j.FinishedAt = time.Now()
	j.closeOnce.Do(func() { close(j.ProgressCh) })
}

func (j *Job) Cancel() {
	j.mu.Lock()
	if j.Status == models.JobStatusDone || j.Status == models.JobStatusError || j.Status == models.JobStatusCanceled {
		j.mu.Unlock()
		return
	}
	j.Status = models.JobStatusCanceled
	j.Err = context.Canceled
	j.FinishedAt = time.Now()
	j.mu.Unlock()

	if j.CancelFn != nil {
		j.CancelFn()
	}
	j.closeOnce.Do(func() { close(j.ProgressCh) })
}

func (j *Job) sendProgress(ev models.ProgressEvent) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.Status == models.JobStatusCanceled || j.Status == models.JobStatusDone || j.Status == models.JobStatusError {
		return
	}
	// Non-blocking: drop if consumer is slow, never block the worker
	select {
	case j.ProgressCh <- ev:
	default:
	}
}

// JobStore is a thread-safe in-memory store for async jobs.
type JobStore struct {
	mu   sync.RWMutex
	jobs map[string]*Job
}

var globalJobStore = &JobStore{jobs: make(map[string]*Job)}

func init() {
	// Background cleaner: evicts expired jobs and orphans every 30 seconds
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			globalJobStore.evictExpired()
		}
	}()
}

func (s *JobStore) create(req models.ScanRequest) *Job {
	id := newJobID()
	// Dummy cancel so we don't panic if cancelled while queued
	_, cancel := context.WithCancel(context.Background())
	job := &Job{
		ID:         id,
		Status:     models.JobStatusQueued,
		Req:        req,
		ProgressCh: make(chan models.ProgressEvent, progressBufSize),
		CancelFn:   cancel,
		CreatedAt:  time.Now(),
	}
	// Do NOT launch goroutine immediately. Wait for subscriber to call Start()
	s.mu.Lock()
	s.jobs[id] = job
	s.mu.Unlock()
	return job
}

func (s *JobStore) get(id string) (*Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	return j, ok
}

// Start triggers the execution of a queued job. Returns true if it was queued.
func (s *JobStore) Start(id string) bool {
	s.mu.RLock()
	j, ok := s.jobs[id]
	s.mu.RUnlock()
	if !ok {
		return false
	}

	j.mu.Lock()
	if j.Status != models.JobStatusQueued {
		j.mu.Unlock()
		return false
	}
	j.Status = models.JobStatusRunning
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	j.CancelFn = cancel // override with running context cancel
	j.mu.Unlock()

	go runJob(ctx, j)
	return true
}

func (s *JobStore) evictExpired() {
	cutoff := time.Now().Add(-jobTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, j := range s.jobs {
		j.mu.Lock()
		status := j.Status
		finished := j.FinishedAt
		createdAt := j.CreatedAt
		j.mu.Unlock()
		
		if !finished.IsZero() && finished.Before(cutoff) {
			j.Cancel()
			delete(s.jobs, id)
		} else if status == models.JobStatusQueued && time.Since(createdAt) > 30*time.Second {
			// Orphan job: submitted but never subscribed within 30s
			j.Cancel()
			delete(s.jobs, id)
		}
	}
}

// CreateJob is the public entry point used by handlers.
func CreateJob(req models.ScanRequest) *Job {
	return globalJobStore.create(req)
}

// GetJob looks up a job by ID.
func GetJob(id string) (*Job, bool) {
	return globalJobStore.get(id)
}

// StartJob explicitly starts a queued job.
func StartJob(id string) bool {
	return globalJobStore.Start(id)
}

func newJobID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// runJob executes ProcessScanWithProgress in background, forwarding progress events.
func runJob(ctx context.Context, job *Job) {
	// Status is already set to JobStatusRunning in Start()

	progressFn := func(pagesCrawled, linksChecked int, currentURL string) {
		job.sendProgress(models.ProgressEvent{
			PagesCrawled: pagesCrawled,
			LinksFound:   linksChecked,
			CurrentURL:   currentURL,
		})
	}

	data, err := ProcessScanWithProgress(ctx, job.Req, progressFn)
	if err != nil {
		job.setError(err)
		return
	}
	job.setDone(data)

	// Cache the result here so it is saved regardless of whether the client is still connected.
	if job.CacheFn != nil {
		job.CacheFn(data)
	}
}
