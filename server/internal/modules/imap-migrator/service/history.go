package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

var (
	historyMutex sync.RWMutex
	historyList  []JobSummary
	historyPath  string
)

type JobSummary struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	Source    string    `json:"source"`
	Dest      string    `json:"dest"`
	Total     int       `json:"total"`
	Errors    int       `json:"errors"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
}

func init() {
	cwd, _ := os.Getwd()
	historyPath = filepath.Join(cwd, "data", "imap-history", "history.json")
	os.MkdirAll(filepath.Dir(historyPath), 0755)

	data, err := os.ReadFile(historyPath)
	if err == nil {
		json.Unmarshal(data, &historyList)
	}
}

// AppendHistory saves completed/failed/cancelled jobs to history and persists to JSON.
func AppendHistory(job *Job) {
	historyMutex.Lock()
	defer historyMutex.Unlock()

	summary := JobSummary{
		ID:        job.ID,
		Status:    job.Snapshot.Status,
		Source:    job.Snapshot.Source,
		Dest:      job.Snapshot.Dest,
		Total:     0, // Computed below
		Errors:    job.Snapshot.TotalErrors,
		StartedAt: job.Snapshot.StartedAt,
		EndedAt:   time.Now(),
	}
	
	// Derive Total processed if TotalEmails doesn't exist
	summary.Total = job.Snapshot.TotalCopied + job.Snapshot.TotalSkipped

	// If source/dest wasn't populated during connection failure, set blank
	if summary.Source == "" {
		summary.Source = "N/A"
	}
	if summary.Dest == "" {
		summary.Dest = "N/A"
	}

	// Insert at beginning
	historyList = append([]JobSummary{summary}, historyList...)

	// Keep max 500
	if len(historyList) > 500 {
		historyList = historyList[:500]
	}

	data, err := json.MarshalIndent(historyList, "", "  ")
	if err == nil {
		tmp := historyPath + ".tmp"
		if errWrite := os.WriteFile(tmp, data, 0644); errWrite == nil {
			os.Rename(tmp, historyPath)
		} else {
			log.Warn().Err(errWrite).Msg("Không thể ghi file lịch sử history.tmp")
		}
	} else {
		log.Warn().Err(err).Msg("Không thể encode JSON cho history")
	}
}

// GetHistory returns a copy of the history array
func GetHistory() []JobSummary {
	historyMutex.RLock()
	defer historyMutex.RUnlock()

	res := make([]JobSummary, len(historyList))
	copy(res, historyList)
	return res
}
