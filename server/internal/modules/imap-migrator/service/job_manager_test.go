package service

import (
	"context"
	"os"
	"testing"

	"tools.bctechvibe.com/server/internal/modules/imap-migrator/models"
)

func TestCryptoAES(t *testing.T) {
	// Set test environment variable for AES key
	// Key must be exactly 32 bytes base64 encoded
	os.Setenv("APP_SECRET_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")

	original := "p@ssw0rd123"

	enc, err := EncryptAES(original)
	if err != nil {
		t.Fatalf("EncryptAES failed: %v", err)
	}

	if enc == original {
		t.Fatalf("Encrypted string is same as original")
	}

	dec, err := DecryptAES(enc)
	if err != nil {
		t.Fatalf("DecryptAES failed: %v", err)
	}

	if dec != original {
		t.Fatalf("Expected '%s', got '%s'", original, dec)
	}
}

func TestJobUpdateProgress(t *testing.T) {
	job := &Job{
		ID:        "test-job",
		CancelCtx: context.Background(),
	}

	job.UpdateProgress(10, 5, 2, 1024)

	snap := job.GetSnapshot()
	if snap.TotalCopied != 10 {
		t.Errorf("Expected TotalCopied 10, got %d", snap.TotalCopied)
	}
	if snap.TotalSkipped != 5 {
		t.Errorf("Expected TotalSkipped 5, got %d", snap.TotalSkipped)
	}
	if snap.TotalErrors != 2 {
		t.Errorf("Expected TotalErrors 2, got %d", snap.TotalErrors)
	}
	if snap.TotalBytes != 1024 {
		t.Errorf("Expected TotalBytes 1024, got %d", snap.TotalBytes)
	}
	if snap.CurrentFolderCopied != 10 {
		t.Errorf("Expected CurrentFolderCopied 10, got %d", snap.CurrentFolderCopied)
	}
}

func TestJobSetCurrentFolder(t *testing.T) {
	job := &Job{
		ID: "test-job-folder",
	}

	job.SetCurrentFolder("INBOX", 100)
	snap := job.GetSnapshot()

	if snap.CurrentFolder != "INBOX" {
		t.Errorf("Expected CurrentFolder INBOX, got %s", snap.CurrentFolder)
	}
	if snap.CurrentFolderTotal != 100 {
		t.Errorf("Expected CurrentFolderTotal 100, got %d", snap.CurrentFolderTotal)
	}
	if snap.CurrentFolderCopied != 0 {
		t.Errorf("Expected CurrentFolderCopied 0, got %d", snap.CurrentFolderCopied)
	}
}

func setupTestDB(t *testing.T) {
	os.Setenv("IMAP_DATA_DIR", t.TempDir())
	ResetTestDB()
	InitTestDB()

	// Ensure DB is empty before test
	GetDB().Exec("DELETE FROM job_logs; DELETE FROM jobs")

	t.Cleanup(func() {
		GetDB().Exec("DELETE FROM job_logs; DELETE FROM jobs")
		ResetTestDB()
	})
}

func TestJobCancel(t *testing.T) {
	setupTestDB(t)

	ctx, cancel := context.WithCancel(context.Background())
	job := &Job{
		ID:        "test-cancel-job",
		CancelCtx: ctx,
		CancelFn:  cancel,
		Snapshot: models.JobSnapshot{
			JobID:  "test-cancel-job",
			Status: "running",
		},
	}

	// Insert into DB first so Cancel can update status without failing
	GetDB().Exec(`INSERT INTO jobs (id, session_id, status) VALUES (?, 'test-session', 'running')`, job.ID)

	if job.CancelCtx.Err() != nil {
		t.Errorf("Expected context not canceled initially")
	}

	job.Cancel()

	if job.CancelCtx.Err() == nil {
		t.Errorf("Expected context to be canceled")
	}

	snap := job.GetSnapshot()
	if snap.Status != "cancelled" {
		t.Errorf("Expected status to be cancelled, got %s", snap.Status)
	}

	// Check if DB updated
	var status string
	GetDB().QueryRow(`SELECT status FROM jobs WHERE id = ?`, job.ID).Scan(&status)
	if status != "cancelled" {
		t.Errorf("Expected DB status to be cancelled, got %s", status)
	}
}
