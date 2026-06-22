package service

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
)

// tempPrefix is the prefix used for all spool files
const tempPrefix = "imap-migrator-"

// StartupCleanup removes any orphan temp files left over from a previous crash
func StartupCleanup() {
	tempDir := os.TempDir()

	files, err := os.ReadDir(tempDir)
	if err != nil {
		log.Warn().Err(err).Msg("Không thể đọc thư mục Temp để dọn dẹp file di cư IMAP")
		return
	}

	cleaned := 0
	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), tempPrefix) {
			path := filepath.Join(tempDir, f.Name())
			if err := os.Remove(path); err != nil {
				log.Debug().Err(err).Str("file", path).Msg("Không thể xóa thư mục tạm mồ côi")
			} else {
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		log.Info().Int("count", cleaned).Msg("Đã dọn dẹp file tạm IMAP mồ côi lúc khởi động")
	}
}

// CleanupJobFiles removes all temp files associated with a specific job
func CleanupJobFiles(jobID string) {
	tempDir := os.TempDir()

	// Format is imap-migrator-<jobID>-*
	prefix := tempPrefix + jobID + "-"

	files, err := os.ReadDir(tempDir)
	if err != nil {
		return
	}

	for _, f := range files {
		if !f.IsDir() && strings.HasPrefix(f.Name(), prefix) {
			path := filepath.Join(tempDir, f.Name())
			_ = os.Remove(path) // ignore err on best-effort cleanup
		}
	}
}
