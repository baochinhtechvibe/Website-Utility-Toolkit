package service

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tools.bctechvibe.com/server/internal/modules/imap-migrator/models"
)

func resetGlobalState() {
	ipJobMap.Range(func(key, value any) bool {
		ipJobMap.Delete(key)
		return true
	})
	
	// drain jobSem if any
	for {
		select {
		case <-jobSem:
		default:
			goto done
		}
	}
done:
	jobStore.Range(func(key, value any) bool {
		jobStore.Delete(key)
		return true
	})
}

func TestCreateAndStartJob_SameIP(t *testing.T) {
	resetGlobalState()
	defer resetGlobalState()

	req := models.StartRequest{}
	ip := "192.168.1.1"

	job1, err := CreateAndStartJob(req, ip)
	require.NoError(t, err)
	require.NotNil(t, job1)

	// Second request from same IP should fail with RateLimitError
	job2, err := CreateAndStartJob(req, ip)
	assert.Error(t, err)
	assert.Nil(t, job2)
	assert.IsType(t, &RateLimitError{}, err)

	// Cancel job1, wait for cleanup goroutine to release lock
	job1.Cancel()
	time.Sleep(100 * time.Millisecond)

	// Third request from same IP should now succeed
	job3, err := CreateAndStartJob(req, ip)
	assert.NoError(t, err)
	assert.NotNil(t, job3)
	
	// Cleanup at the end
	job3.Cancel()
	time.Sleep(10 * time.Millisecond)
}

func TestCreateAndStartJob_MaxConcurrent(t *testing.T) {
	resetGlobalState()
	defer resetGlobalState()

	req := models.StartRequest{}

	var jobs []*Job
	// Fill all max slots
	for i := 1; i <= maxConcurrentJobs; i++ {
		job, err := CreateAndStartJob(req, fmt.Sprintf("10.0.0.%d", i))
		require.NoError(t, err)
		require.NotNil(t, job)
		jobs = append(jobs, job)
	}

	// Request exceeding maxConcurrentJobs should fail with ServerBusyError
	jobExtra, err := CreateAndStartJob(req, "10.0.0.99")
	assert.Error(t, err)
	assert.Nil(t, jobExtra)
	assert.IsType(t, &ServerBusyError{}, err)
	
	// Clean up jobs
	for _, j := range jobs {
		j.Cancel()
	}
	time.Sleep(100 * time.Millisecond)
}
