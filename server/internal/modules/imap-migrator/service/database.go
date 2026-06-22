package service

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	_ "modernc.org/sqlite"
)

var (
	db   *sql.DB
	once sync.Once
)

// InitDB initializes the SQLite database connection and creates tables if they don't exist.
func InitDB() {
	once.Do(func() {
		// Ensure data directory exists
		dataDir := GetDataDir()
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			log.Fatal().Err(err).Msg("Failed to create data directory")
		}

		dbPath := filepath.Join(dataDir, "imap_migrator.db")

		// Connect to SQLite (modernc.org/sqlite uses driver name "sqlite")
		// Enable WAL mode via pragma for better concurrency
		dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)", dbPath)
		database, err := sql.Open("sqlite", dsn)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to open SQLite database")
		}

		// Test connection
		if err := database.Ping(); err != nil {
			log.Fatal().Err(err).Msg("Failed to ping SQLite database")
		}

		db = database
		log.Info().Str("path", dbPath).Msg("SQLite Database initialized (WAL mode)")

		runMigrations(db)
	})
}

// GetDB returns the initialized database connection
func GetDB() *sql.DB {
	if db == nil {
		log.Fatal().Msg("Database not initialized. Call InitDB first.")
	}
	return db
}

// ResetTestDB closes current connection and resets sync.Once for testing isolation.
// Only use this in tests.
func ResetTestDB() {
	if db != nil {
		db.Close()
		db = nil
	}
	once = sync.Once{}
}

// InitTestDB initializes an in-memory SQLite database for testing purposes.
func InitTestDB() {
	once.Do(func() {
		database, err := sql.Open("sqlite", "file::memory:?cache=shared")
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to open test SQLite database")
		}
		db = database
		runMigrations(db)
	})
}

// CloseDB gracefully closes the SQLite database connection
func CloseDB() {
	if db != nil {
		if err := db.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close SQLite database")
		} else {
			log.Info().Msg("SQLite Database connection closed")
		}
	}
}

func runMigrations(database *sql.DB) {
	// Table: jobs
	// Stores the overall state and progress of a migration job
	createJobsTable := `
	CREATE TABLE IF NOT EXISTS jobs (
		id TEXT PRIMARY KEY,
		session_id TEXT NOT NULL,
		status TEXT NOT NULL, -- pending, running, done, error, cancelled
		source_host TEXT,
		source_port INTEGER,
		source_user TEXT,
		source_security TEXT,
		dest_host TEXT,
		dest_port INTEGER,
		dest_user TEXT,
		dest_security TEXT,
		mode TEXT,
		selected_folders TEXT, -- JSON array
		total_folders INTEGER DEFAULT 0,
		current_folder TEXT DEFAULT '',
		completed_folders INTEGER DEFAULT 0,
		current_folder_copied INTEGER DEFAULT 0,
		current_folder_total INTEGER DEFAULT 0,
		total_copied INTEGER DEFAULT 0,
		total_skipped INTEGER DEFAULT 0,
		total_errors INTEGER DEFAULT 0,
		total_bytes INTEGER DEFAULT 0,
		last_error TEXT DEFAULT '',
		started_at DATETIME,
		finished_at DATETIME,
		queued_at DATETIME,
		claimed_at DATETIME,
		heartbeat_at DATETIME,
		worker_id TEXT,
		attempts INTEGER DEFAULT 0,
		cancel_requested_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
	CREATE INDEX IF NOT EXISTS idx_jobs_session_id ON jobs(session_id);
	`

	// Table: job_secrets
	// Temporarily stores credentials for pending jobs, deleted when job finishes
	createSecretsTable := `
	CREATE TABLE IF NOT EXISTS job_secrets (
		job_id TEXT PRIMARY KEY,
		source_pass_enc TEXT NOT NULL,
		dest_pass_enc TEXT NOT NULL,
		FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
	);
	`

	// Table: job_logs
	// Stores historical log messages to reconstruct the UI on reconnect
	createLogsTable := `
	CREATE TABLE IF NOT EXISTS job_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		job_id TEXT NOT NULL,
		level TEXT NOT NULL, -- info, error, success
		message TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_job_logs_job_id_id ON job_logs(job_id, id);
	`

	tx, err := database.Begin()
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to begin migration transaction")
	}

	for _, stmt := range []string{createJobsTable, createSecretsTable, createLogsTable} {
		if _, err := tx.Exec(stmt); err != nil {
			tx.Rollback()
			log.Fatal().Err(err).Msg("Failed to execute migration statement")
		}
	}

	if err := tx.Commit(); err != nil {
		log.Fatal().Err(err).Msg("Failed to commit migration transaction")
	}

	// Upgrade Schema: Add missing columns if upgrading from Phase 1
	upgradeStmts := []string{
		"ALTER TABLE jobs ADD COLUMN source_port INTEGER;",
		"ALTER TABLE jobs ADD COLUMN source_security TEXT;",
		"ALTER TABLE jobs ADD COLUMN dest_port INTEGER;",
		"ALTER TABLE jobs ADD COLUMN dest_security TEXT;",
		"ALTER TABLE job_logs ADD COLUMN event_data TEXT;",
		"ALTER TABLE jobs ADD COLUMN current_folder_copied INTEGER DEFAULT 0;",
		"ALTER TABLE jobs ADD COLUMN current_folder_total INTEGER DEFAULT 0;",
		"ALTER TABLE jobs ADD COLUMN total_bytes INTEGER DEFAULT 0;",
	}
	for _, stmt := range upgradeStmts {
		_, err := database.Exec(stmt)
		if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			log.Fatal().Err(err).Msg("Failed to apply schema migration: " + stmt)
		}
	}

	RecoverStaleJobs()
	log.Info().Msg("Database migrations applied successfully")
}
