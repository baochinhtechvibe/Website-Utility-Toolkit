package service

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/imap-migrator/models"
)

var (
	workerCount = 3 // Số lượng tiến trình chạy song song tối đa (Concurrency)
	workerWG    sync.WaitGroup
)

// StartWorkerPool initializes the background workers that poll SQLite for pending jobs.
func StartWorkerPool(ctx context.Context) {
	// Validate secret key exactly once on startup to fail fast
	_ = getSecretKey()

	log.Info().Int("workers", workerCount).Msg("Starting IMAP Migrator Worker Pool")
	for i := 1; i <= workerCount; i++ {
		workerID := fmt.Sprintf("worker-%d", i)
		workerWG.Add(1)
		go runWorker(ctx, workerID)
	}
}

// WaitWorkers blocks until all workers finish their current job and exit.
func WaitWorkers() {
	workerWG.Wait()
}

func runWorker(ctx context.Context, workerID string) {
	defer workerWG.Done()

	for {
		select {
		case <-ctx.Done():
			log.Info().Str("worker", workerID).Msg("Worker shutting down")
			return
		default:
		}

		// Attempt to claim a job
		jobID, req, err := ClaimPendingJob(workerID)
		if err != nil {
			log.Error().Err(err).Str("worker", workerID).Msg("Worker failed to claim job")
			time.Sleep(5 * time.Second) // backoff on error
			continue
		}

		if jobID == "" {
			// No pending jobs, sleep and poll again
			time.Sleep(2 * time.Second)
			continue
		}

		log.Info().Str("worker", workerID).Str("job_id", jobID).Msg("Worker claimed pending job")

		// We must reuse the Job struct from jobStore if it exists, so SSE clients stay connected.
		// If it's not in jobStore (e.g., server restarted), we create and store it.
		// Prepare Cancel Context BEFORE marking it running to avoid race condition if user cancels exactly now
		jobCtx, cancel := context.WithCancel(ctx)

		var job *Job
		if val, ok := GetJob(jobID); ok {
			job = val
			job.Mutex.Lock()
			job.Snapshot.Status = "running"
			job.CancelCtx = jobCtx
			job.CancelFn = cancel
			job.Mutex.Unlock()
		} else {
			job = &Job{
				ID:        jobID,
				CancelCtx: jobCtx,
				CancelFn:  cancel,
				Snapshot: models.JobSnapshot{
					JobID:  jobID,
					Status: "running",
				},
			}
			jobStore.Store(jobID, job)
		}

		// Create log file for legacy compatibility until UI fully moves to SQLite
		// This will be replaced entirely by DB logs, but kept to prevent breaking copy.go
		AddJobLog(jobID, "info", fmt.Sprintf("Worker %s started migration", workerID))

		// Execute Migration
		RunMigration(jobCtx, job, *req)

		log.Info().Str("worker", workerID).Str("job_id", jobID).Msg("Worker finished job")
	}
}
