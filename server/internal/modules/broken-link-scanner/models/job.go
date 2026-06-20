package models

// JobStatus represents the lifecycle state of an async scan job.
type JobStatus string

const (
	JobStatusQueued  JobStatus = "queued"
	JobStatusRunning JobStatus = "running"
	JobStatusDone     JobStatus = "done"
	JobStatusError    JobStatus = "error"
	JobStatusCanceled JobStatus = "canceled"
)

// ProgressEvent is sent over SSE during an active scan.
type ProgressEvent struct {
	PagesCrawled int    `json:"pages_crawled"`
	LinksFound   int    `json:"links_found"`
	CurrentURL   string `json:"current_url,omitempty"`
}
