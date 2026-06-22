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

// JobSummary lưu thông tin tóm tắt của một job đã hoàn thành.
// Bao gồm TotalBytes thực tế, CompletedFolders, TotalFolders để
// admin dashboard hiển thị chính xác thay vì ước tính.
type JobSummary struct {
	ID               string    `json:"id"`
	Status           string    `json:"status"`
	Source           string    `json:"source"`
	SourceUser       string    `json:"source_user"`
	Dest             string    `json:"dest"`
	DestUser         string    `json:"dest_user"`
	TotalCopied      int       `json:"total_copied"`  // Số thư mới được copy
	TotalSkipped     int       `json:"total_skipped"` // Số thư đã tồn tại (bỏ qua)
	Total            int       `json:"total"`         // Tổng = copied + skipped (backward compat)
	TotalBytes       int64     `json:"total_bytes"`
	Errors           int       `json:"errors"`
	TotalFolders     int       `json:"total_folders"`
	CompletedFolders int       `json:"completed_folders"`
	StartedAt        time.Time `json:"started_at"`
	EndedAt          time.Time `json:"ended_at"`
}

// GetDataDir trả về thư mục lưu trữ dữ liệu chính.
// Hỗ trợ ghi đè qua IMAP_DATA_DIR trong môi trường production.
func GetDataDir() string {
	dir := os.Getenv("IMAP_DATA_DIR")
	if dir != "" {
		return dir
	}
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, "data", "imap-history")
}

var historyOnce sync.Once

func ensureHistoryLoaded() {
	historyOnce.Do(func() {
		historyPath = filepath.Join(GetDataDir(), "history.json")
		os.MkdirAll(filepath.Dir(historyPath), 0755)

		data, err := os.ReadFile(historyPath)
		if err == nil {
			json.Unmarshal(data, &historyList)
		}
	})
}

// AppendHistory lưu job đã hoàn thành/lỗi/hủy vào history và persist xuống file JSON.
func AppendHistory(job *Job) {
	ensureHistoryLoaded()
	historyMutex.Lock()
	defer historyMutex.Unlock()

	summary := JobSummary{
		ID:               job.ID,
		Status:           job.Snapshot.Status,
		Source:           job.Snapshot.Source,
		SourceUser:       job.Snapshot.SourceUser,
		Dest:             job.Snapshot.Dest,
		DestUser:         job.Snapshot.DestUser,
		TotalCopied:      job.Snapshot.TotalCopied,
		TotalSkipped:     job.Snapshot.TotalSkipped,
		Total:            job.Snapshot.TotalCopied + job.Snapshot.TotalSkipped,
		TotalBytes:       job.Snapshot.TotalBytes,
		Errors:           job.Snapshot.TotalErrors,
		TotalFolders:     job.Snapshot.TotalFolders,
		CompletedFolders: job.Snapshot.CompletedFolders,
		StartedAt:        job.Snapshot.StartedAt,
		EndedAt:          time.Now(),
	}

	// Nếu source/dest chưa được điền (lỗi kết nối ngay từ đầu), để là N/A
	if summary.Source == "" {
		summary.Source = "N/A"
	}
	if summary.Dest == "" {
		summary.Dest = "N/A"
	}

	// Thêm vào đầu danh sách (mới nhất lên trên)
	historyList = append([]JobSummary{summary}, historyList...)

	// Giữ tối đa 500 bản ghi
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

// GetHistory trả về bản sao của danh sách lịch sử
func GetHistory() []JobSummary {
	ensureHistoryLoaded()
	historyMutex.RLock()
	defer historyMutex.RUnlock()

	res := make([]JobSummary, len(historyList))
	copy(res, historyList)
	return res
}
