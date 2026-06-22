package service

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/imap-migrator/models"
)

// CreateJob inserts a new job into SQLite with "pending" status and securely stores passwords.
func CreateJob(job *Job, req models.StartRequest, sessionID string) error {
	db := GetDB()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	selectedFoldersJSON, _ := json.Marshal(req.Folders)

	// Ensure passwords are never stored plaintext
	srcPassEnc, err := EncryptAES(req.Source.Password)
	if err != nil {
		return err
	}
	destPassEnc, err := EncryptAES(req.Dest.Password)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`
		INSERT INTO jobs (
			id, session_id, status, 
			source_host, source_port, source_user, source_security,
			dest_host, dest_port, dest_user, dest_security,
			mode, selected_folders, total_folders, queued_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		job.ID, sessionID, "pending",
		req.Source.Host, req.Source.Port, req.Source.Username, req.Source.Security,
		req.Dest.Host, req.Dest.Port, req.Dest.Username, req.Dest.Security,
		req.Mode, string(selectedFoldersJSON), len(req.Folders), time.Now(),
	)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`
		INSERT INTO job_secrets (job_id, source_pass_enc, dest_pass_enc) 
		VALUES (?, ?, ?)
	`, job.ID, srcPassEnc, destPassEnc)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// UpdateJobStatus changes job status and cleans up secrets if terminal state.
func UpdateJobStatus(jobID, status, lastError string) error {
	db := GetDB()
	now := time.Now()

	var err error
	if status == "running" {
		_, err = db.Exec(`UPDATE jobs SET status = ?, started_at = ?, updated_at = ? WHERE id = ?`, status, now, now, jobID)
	} else if status == "done" || status == "error" || status == "cancelled" {
		_, err = db.Exec(`UPDATE jobs SET status = ?, finished_at = ?, last_error = ?, updated_at = ? WHERE id = ?`, status, now, lastError, now, jobID)

		// Clean up secrets for terminal states to minimize blast radius
		if err == nil {
			DeleteJobSecrets(jobID)
		}
	} else {
		_, err = db.Exec(`UPDATE jobs SET status = ?, updated_at = ? WHERE id = ?`, status, now, jobID)
	}
	return err
}

// UpdateJobProgress updates the live counters for a running job in SQLite.
func UpdateJobProgress(jobID string, snap models.JobSnapshot) error {
	db := GetDB()
	_, err := db.Exec(`
		UPDATE jobs
		SET total_folders = ?, current_folder = ?, completed_folders = ?, 
		    current_folder_copied = ?, current_folder_total = ?,
		    total_copied = ?, total_skipped = ?, total_errors = ?, total_bytes = ?
		WHERE id = ?
	`, snap.TotalFolders, snap.CurrentFolder, snap.CompletedFolders,
		snap.CurrentFolderCopied, snap.CurrentFolderTotal,
		snap.TotalCopied, snap.TotalSkipped, snap.TotalErrors, snap.TotalBytes, jobID,
	)
	return err
}

// DeleteJobSecrets deletes the encrypted credentials once the job is no longer running.
func DeleteJobSecrets(jobID string) {
	db := GetDB()
	_, err := db.Exec(`DELETE FROM job_secrets WHERE job_id = ?`, jobID)
	if err != nil {
		log.Error().Err(err).Str("job_id", jobID).Msg("Failed to delete job secrets")
	}
}

// AddJobLog inserts a log entry into job_logs.
func AddJobLog(jobID, level, message string) {
	ev := models.SSEEvent{
		Type:    "INFO",
		Message: message,
	}
	if level == "error" {
		ev.Type = "ERROR"
	}
	b, _ := json.Marshal(ev)
	_, err := GetDB().Exec(`INSERT INTO job_logs (job_id, level, message, event_data) VALUES (?, ?, ?, ?)`, jobID, level, message, string(b))
	if err != nil {
		log.Error().Err(err).Str("job_id", jobID).Msg("Failed to insert job log")
	}
}

// PersistSSEEvent directly stores the raw event data to replay later
func PersistSSEEvent(jobID string, event models.SSEEvent) {
	level := "info"
	if event.Type == "ERROR" || event.Type == "EMAIL_ERROR" || event.Type == "FOLDER_ERROR" {
		level = "error"
	} else if event.Type == "COMPLETE" || event.Type == "FOLDER_DONE" {
		level = "success"
	}
	b, _ := json.Marshal(event)
	_, err := GetDB().Exec(`INSERT INTO job_logs (job_id, level, message, event_data) VALUES (?, ?, ?, ?)`, jobID, level, event.Message, string(b))
	if err != nil {
		log.Error().Err(err).Str("job_id", jobID).Msg("Failed to insert job log")
	}
}

// CountActiveJobsBySession checks how many jobs are currently pending/running for a session.
func CountActiveJobsBySession(sessionID string) (int, error) {
	db := GetDB()
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE session_id = ? AND status IN ('pending', 'running')`, sessionID).Scan(&count)
	return count, err
}

// ClaimPendingJob atomic claim: attempts to pick the oldest pending job and mark it as running for a specific worker.
// Returns the jobID and credentials if successful. Returns empty string if no pending jobs.
func ClaimPendingJob(workerID string) (string, *models.StartRequest, error) {
	db := GetDB()
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation: sql.LevelSerializable}) // Ensure strong isolation
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()

	// Find the oldest pending job
	var jobID, srcHost, srcUser, srcSec, destHost, destUser, destSec, mode, selectedFoldersJSON string
	var srcPort, destPort int
	err = tx.QueryRow(`
		SELECT id, source_host, source_port, source_user, source_security, 
		       dest_host, dest_port, dest_user, dest_security, mode, selected_folders 
		FROM jobs WHERE status = 'pending' ORDER BY queued_at ASC LIMIT 1
	`).Scan(&jobID, &srcHost, &srcPort, &srcUser, &srcSec, &destHost, &destPort, &destUser, &destSec, &mode, &selectedFoldersJSON)

	if err == sql.ErrNoRows {
		return "", nil, nil // No pending jobs
	} else if err != nil {
		return "", nil, err
	}

	// Read secrets
	var srcPassEnc, destPassEnc string
	err = tx.QueryRow(`SELECT source_pass_enc, dest_pass_enc FROM job_secrets WHERE job_id = ?`, jobID).Scan(&srcPassEnc, &destPassEnc)
	if err != nil {
		return "", nil, err // Can't proceed without secrets
	}

	srcPass, err := DecryptAES(srcPassEnc)
	if err != nil {
		return "", nil, err
	}
	destPass, err := DecryptAES(destPassEnc)
	if err != nil {
		return "", nil, err
	}

	// Parse folders
	var folders []string
	json.Unmarshal([]byte(selectedFoldersJSON), &folders)

	req := &models.StartRequest{
		Source:  models.MigrationEndpoint{Host: srcHost, Port: srcPort, Username: srcUser, Password: srcPass, Security: srcSec},
		Dest:    models.MigrationEndpoint{Host: destHost, Port: destPort, Username: destUser, Password: destPass, Security: destSec},
		Mode:    mode,
		Folders: folders,
	}

	// Claim it atomically
	now := time.Now()
	res, err := tx.Exec(`
		UPDATE jobs SET status = 'running', worker_id = ?, claimed_at = ?, started_at = ?, updated_at = ? 
		WHERE id = ? AND status = 'pending'
	`, workerID, now, now, now, jobID)
	if err != nil {
		return "", nil, err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return "", nil, err
	}
	if rows == 0 {
		return "", nil, nil // another worker claimed it first
	}

	if err := tx.Commit(); err != nil {
		return "", nil, err
	}

	return jobID, req, nil
}

// GetJobSessionID returns the session ID associated with a job.
func GetJobSessionID(jobID string) (string, bool, error) {
	db := GetDB()
	var sessionID string
	err := db.QueryRow(`SELECT session_id FROM jobs WHERE id = ?`, jobID).Scan(&sessionID)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	return sessionID, true, nil
}

// GetJobsBySession returns the most recent jobs for a given session, newest first.
func GetJobsBySession(sessionID string, limit int) []models.JobSnapshot {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	var jobs []models.JobSnapshot
	db := GetDB()
	rows, err := db.Query(`
		SELECT id, status, source_host, source_user, dest_host, dest_user, mode, selected_folders,
		       total_folders, current_folder, completed_folders, current_folder_copied, current_folder_total,
		       total_copied, total_skipped, total_errors, total_bytes, last_error,
		       started_at, finished_at
		FROM jobs WHERE session_id = ? ORDER BY created_at DESC LIMIT ?
	`, sessionID, limit)
	if err != nil {
		return jobs
	}
	defer rows.Close()
	for rows.Next() {
		var snap models.JobSnapshot
		var selectedFoldersJSON, lastErr sql.NullString
		var startedAt, finishedAt sql.NullTime
		if err := rows.Scan(
			&snap.JobID, &snap.Status, &snap.Source, &snap.SourceUser, &snap.Dest, &snap.DestUser, &snap.Mode, &selectedFoldersJSON,
			&snap.TotalFolders, &snap.CurrentFolder, &snap.CompletedFolders, &snap.CurrentFolderCopied, &snap.CurrentFolderTotal,
			&snap.TotalCopied, &snap.TotalSkipped, &snap.TotalErrors, &snap.TotalBytes, &lastErr,
			&startedAt, &finishedAt,
		); err != nil {
			continue
		}
		if selectedFoldersJSON.Valid {
			json.Unmarshal([]byte(selectedFoldersJSON.String), &snap.SelectedFolders)
		}
		if lastErr.Valid {
			snap.LastError = lastErr.String
		}
		if startedAt.Valid {
			snap.StartedAt = startedAt.Time
		}
		if finishedAt.Valid {
			snap.FinishedAt = &finishedAt.Time
		}
		snap.RecentErrors = []string{}
		snap.CanReconnect = (snap.Status == "running" || snap.Status == "pending")
		jobs = append(jobs, snap)
	}
	return jobs
}

// GetJobSnapshot reconstructs a job snapshot directly from SQLite.
func GetJobSnapshot(jobID string) (models.JobSnapshot, bool) {
	db := GetDB()
	var snap models.JobSnapshot
	var selectedFoldersJSON, lastErr sql.NullString
	var startedAt, finishedAt sql.NullTime

	err := db.QueryRow(`
		SELECT id, status, source_host, source_user, dest_host, dest_user, mode, selected_folders,
		       total_folders, current_folder, completed_folders, current_folder_copied, current_folder_total,
		       total_copied, total_skipped, total_errors, total_bytes, last_error,
		       started_at, finished_at
		FROM jobs WHERE id = ?
	`, jobID).Scan(
		&snap.JobID, &snap.Status, &snap.Source, &snap.SourceUser, &snap.Dest, &snap.DestUser, &snap.Mode, &selectedFoldersJSON,
		&snap.TotalFolders, &snap.CurrentFolder, &snap.CompletedFolders, &snap.CurrentFolderCopied, &snap.CurrentFolderTotal,
		&snap.TotalCopied, &snap.TotalSkipped, &snap.TotalErrors, &snap.TotalBytes, &lastErr,
		&startedAt, &finishedAt,
	)

	if err != nil {
		return snap, false
	}

	if selectedFoldersJSON.Valid {
		json.Unmarshal([]byte(selectedFoldersJSON.String), &snap.SelectedFolders)
	}
	if lastErr.Valid {
		snap.LastError = lastErr.String
	}
	if startedAt.Valid {
		snap.StartedAt = startedAt.Time
	}
	if finishedAt.Valid {
		snap.FinishedAt = &finishedAt.Time
	}

	// Fetch recent errors
	snap.RecentErrors = []string{}
	rows, err := db.Query(`SELECT message FROM job_logs WHERE job_id = ? AND level = 'error' ORDER BY id DESC LIMIT 20`, jobID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var msg string
			if err := rows.Scan(&msg); err == nil {
				// prepend to keep chronological if wanted, or just append
				snap.RecentErrors = append(snap.RecentErrors, msg)
			}
		}
	}

	snap.CanReconnect = (snap.Status == "running" || snap.Status == "pending")
	return snap, true
}

// CancelJobInDB directly updates a pending job to cancelled in the database.
func CancelJobInDB(jobID string) bool {
	res, err := GetDB().Exec(`UPDATE jobs SET status = 'cancelled' WHERE id = ? AND status = 'pending'`, jobID)
	if err != nil {
		return false
	}
	rows, _ := res.RowsAffected()
	if rows > 0 {
		DeleteJobSecrets(jobID) // Wipe secrets
		return true
	}
	return false
}

// RecoverStaleJobs marks any jobs that were 'running' when the server crashed as 'error'.
func RecoverStaleJobs() {
	db := GetDB()
	rows, err := db.Query(`SELECT id FROM jobs WHERE status = 'running'`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				DeleteJobSecrets(id)
				AddJobLog(id, "error", "Tiến trình bị gián đoạn do hệ thống máy chủ khởi động lại")
			}
		}
	}
	db.Exec(`UPDATE jobs SET status = 'error', last_error = 'Tiến trình bị gián đoạn do khởi động lại máy chủ' WHERE status = 'running'`)
}

// GetJobLogs retrieves all logs for a job to replay via SSE.
func GetJobLogs(jobID string) []models.SSEEvent {
	var events []models.SSEEvent
	db := GetDB()
	rows, err := db.Query(`SELECT level, message, event_data FROM job_logs WHERE job_id = ? ORDER BY id ASC`, jobID)
	if err != nil {
		return events
	}
	defer rows.Close()
	for rows.Next() {
		var level, message string
		var eventData sql.NullString
		if err := rows.Scan(&level, &message, &eventData); err == nil {
			if eventData.Valid && eventData.String != "" {
				var ev models.SSEEvent
				if err := json.Unmarshal([]byte(eventData.String), &ev); err == nil {
					events = append(events, ev)
					continue
				}
			}
			// Fallback if event_data is missing (old logs)
			evType := "INFO"
			if level == "error" {
				evType = "ERROR"
			} else if level == "success" {
				evType = "FOLDER_DONE"
			}
			events = append(events, models.SSEEvent{
				Type:    evType,
				Message: message,
			})
		}
	}
	return events
}

// TailJobLog reads lines from the .log file efficiently.
// If fromOffset == 0, it reads up to the last 64KB and returns the last numLines, with endOffset.
// If fromOffset > 0, it reads a chunk (up to 64KB) starting from fromOffset.
// It aligns the chunk to the last newline to avoid splitting lines.
// It returns the lines and the new offset for the next read.
func TailJobLog(jobID string, numLines int, fromOffset int64) ([]string, int64) {
	logPath := filepath.Join(GetDataDir(), "logs", "job_"+jobID+".log")
	f, err := os.Open(logPath)
	if err != nil {
		return nil, fromOffset
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil || stat.Size() == 0 {
		return nil, fromOffset
	}

	fileSize := stat.Size()
	maxRead := int64(64 * 1024)

	if fromOffset > 0 {
		if fromOffset >= fileSize {
			return nil, fileSize
		}

		readSize := fileSize - fromOffset
		if readSize > maxRead {
			readSize = maxRead
		}

		f.Seek(fromOffset, 0)
		buf := make([]byte, readSize)
		n, _ := f.Read(buf)
		if n == 0 {
			return nil, fromOffset
		}

		lastNewlineIdx := bytes.LastIndexByte(buf[:n], '\n')
		var newOffset int64
		var readBuf []byte

		if lastNewlineIdx >= 0 {
			readBuf = buf[:lastNewlineIdx]
			newOffset = fromOffset + int64(lastNewlineIdx) + 1 // skip newline
		} else {
			// No newline found in 64KB, which is weird but handle it
			readBuf = buf[:n]
			newOffset = fromOffset + int64(n)
		}

		lines := strings.Split(string(readBuf), "\n")
		var validLines []string
		for _, l := range lines {
			if l != "" {
				validLines = append(validLines, l)
			}
		}
		return validLines, newOffset
	}

	// fromOffset == 0: read last 64KB
	readStart := fileSize - maxRead
	if readStart < 0 {
		readStart = 0
	}

	f.Seek(readStart, 0)
	buf := make([]byte, fileSize-readStart)
	n, _ := f.Read(buf)

	lines := strings.Split(string(buf[:n]), "\n")
	if readStart > 0 && len(lines) > 0 {
		lines = lines[1:] // drop the first truncated line
	}

	var validLines []string
	for _, l := range lines {
		if l != "" {
			validLines = append(validLines, l)
		}
	}

	if len(validLines) > numLines {
		validLines = validLines[len(validLines)-numLines:]
	}

	return validLines, fileSize
}
