package service

import "tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"

// GetResult returns a snapshot of the job's final state (status, data, error).
// Exported for use by handlers without requiring direct field access.
func (j *Job) GetResult() (status models.JobStatus, data *models.ScanData, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.Status, j.Data, j.Err
}
