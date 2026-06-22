package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
)

const cleanupInterval = 24 * time.Hour
const retainDays = 30

func init() {
	go runCronCleanup()
}

func runCronCleanup() {
	// Chờ 5p sau khi khởi động server cho ổn định rồi mới chạy lần đầu
	time.Sleep(5 * time.Minute)

	for {
		cleanOldLogsAndHistory()
		time.Sleep(cleanupInterval)
	}
}

func cleanOldLogsAndHistory() {
	log.Info().Msg("Bắt đầu dọn dẹp log và history cũ (cron)...")

	historyDir := GetDataDir()
	logDir := filepath.Join(historyDir, "logs")

	cutoff := time.Now().AddDate(0, 0, -retainDays)

	// Dọn logs files
	entries, err := os.ReadDir(logDir)
	var deletedLogs int
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				info, err := entry.Info()
				if err == nil && info.ModTime().Before(cutoff) {
					errDel := os.Remove(filepath.Join(logDir, entry.Name()))
					if errDel == nil {
						deletedLogs++
					}
				}
			}
		}
	}

	// Dọn history.json — dùng Write lock suốt để tránh TOCTOU race
	// (AppendHistory có thể chen vào giữa RUnlock và Lock trong pattern cũ)
	ensureHistoryLoaded()
	historyMutex.Lock()
	var newHistory []JobSummary
	needUpdate := false
	for _, summary := range historyList {
		if !summary.EndedAt.Before(cutoff) {
			newHistory = append(newHistory, summary)
		} else {
			needUpdate = true
		}
	}
	var data []byte
	if needUpdate {
		historyList = newHistory
		data, _ = json.MarshalIndent(historyList, "", "  ")
	}
	historyMutex.Unlock()

	// Write file bên ngoài lock để tránh giữ lock trong quá trình disk I/O
	if needUpdate {
		tmp := historyPath + ".tmp"
		if errWrite := os.WriteFile(tmp, data, 0644); errWrite == nil {
			os.Rename(tmp, historyPath)
		}
	}

	// Clean up SQLite DB
	db := GetDB()
	if db != nil {
		_, errLog := db.Exec(`DELETE FROM job_logs WHERE job_id IN (SELECT id FROM jobs WHERE finished_at < ?)`, cutoff)
		resJob, errJob := db.Exec(`DELETE FROM jobs WHERE finished_at < ?`, cutoff)
		if errLog == nil && errJob == nil {
			deletedDBJobs, _ := resJob.RowsAffected()
			if deletedDBJobs > 0 {
				log.Info().Int64("deleted_jobs", deletedDBJobs).Msg("Đã xóa dữ liệu jobs cũ khỏi SQLite. Đang dồn mảnh VACUUM...")
				if _, errVacuum := db.Exec("VACUUM"); errVacuum != nil {
					log.Warn().Err(errVacuum).Msg("Không thể dồn mảnh (VACUUM) SQLite lúc này")
				} else {
					log.Info().Msg("Đã hoàn tất dồn mảnh VACUUM")
				}
			}
		} else {
			log.Error().Err(errJob).Msg("Lỗi khi dọn dẹp SQLite jobs")
		}
	}

	log.Info().Int("deleted_logs", deletedLogs).Msg("Hoàn tất dọn dẹp dữ liệu cũ định kỳ.")
}
