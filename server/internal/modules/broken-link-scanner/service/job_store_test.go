package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"
)

func TestJobStore_Lifecycle(t *testing.T) {
	// Sử dụng IP nội bộ để SSRF blocker chặn ngay lập tức, không cho phép call network thật ra ngoài
	req := models.ScanRequest{URL: "http://127.0.0.1/dummy"}

	t.Run("Create and Start", func(t *testing.T) {
		job := CreateJob(req)
		assert.Equal(t, models.JobStatusQueued, job.Status)
		assert.NotEmpty(t, job.ID)

		started := StartJob(job.ID)
		assert.True(t, started)

		job.mu.Lock()
		status := job.Status
		job.mu.Unlock()
		assert.NotEqual(t, models.JobStatusQueued, status)

		// Double start should be false since it's no longer queued
		startedTwice := StartJob(job.ID)
		assert.False(t, startedTwice)

		// Cleanup
		job.Cancel()
	})

	t.Run("Cancel Queued Job", func(t *testing.T) {
		job := CreateJob(req)
		job.Cancel()

		job.mu.Lock()
		assert.Equal(t, models.JobStatusCanceled, job.Status)
		assert.Equal(t, context.Canceled, job.Err)
		job.mu.Unlock()

		// Start should fail since it's canceled
		started := StartJob(job.ID)
		assert.False(t, started)

		// Progress channel should be closed
		_, ok := <-job.ProgressCh
		assert.False(t, ok)
	})

	t.Run("Evict Orphan Job", func(t *testing.T) {
		job := CreateJob(req)
		
		// Artificially age the job to simulate orphan timeout
		job.mu.Lock()
		job.CreatedAt = time.Now().Add(-35 * time.Second)
		job.mu.Unlock()

		// Run eviction
		globalJobStore.evictExpired()

		// Should not exist anymore
		_, ok := GetJob(job.ID)
		assert.False(t, ok)

		// And it should have been canceled
		job.mu.Lock()
		status := job.Status
		job.mu.Unlock()
		assert.Equal(t, models.JobStatusCanceled, status)
	})
}
