package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/imap-migrator/models"
	"tools.bctechvibe.com/server/internal/modules/imap-migrator/service"
	"tools.bctechvibe.com/server/internal/response"
)

// uuidRegex dùng để validate UUID format tránh path traversal
var uuidRegex = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func isValidUUID(s string) bool {
	return uuidRegex.MatchString(strings.ToLower(s))
}

// HandleTestConnection tests the connection to a single IMAP endpoint
func HandleTestConnection(c *gin.Context) {
	var req models.TestConnectionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Payload không hợp lệ")
		return
	}

	if err := service.TestConnection(c.Request.Context(), req.Endpoint); err != nil {
		response.Error(c, http.StatusBadRequest, service.FriendlyErrorMessage(err))
		return
	}

	if strings.ToUpper(req.Endpoint.Security) == "NONE" {
		response.SuccessWithMessage(c, nil, "Thành công (CẢNH BÁO: Kết nối chưa mã hoá TLS)")
	} else {
		response.SuccessWithMessage(c, nil, "Kết nối thành công tới máy chủ IMAP")
	}
}

// HandleListFolders retrieves the folder structure from a single endpoint
func HandleListFolders(c *gin.Context) {
	var req models.ListFoldersRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Payload không hợp lệ")
		return
	}

	resp, err := service.ListFolders(c.Request.Context(), req.Endpoint)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, service.FriendlyErrorMessage(err))
		return
	}

	response.SuccessNoMeta(c, resp)
}

// HandleStart kicks off a migration job
func HandleStart(c *gin.Context) {
	var req models.StartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "Payload không hợp lệ")
		return
	}

	if req.Mode == "selected" && len(req.Folders) == 0 {
		response.Error(c, http.StatusBadRequest, "Vui lòng chọn ít nhất 1 thư mục")
		return
	}

	clientIP := c.ClientIP()
	sessionID := c.GetHeader("X-Session-ID")
	if sessionID == "" {
		sessionID = clientIP
	}

	job, err := service.EnqueueJob(req, sessionID)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, service.FriendlyErrorMessage(err))
		return
	}

	response.SuccessWithMessage(c, gin.H{"jobId": job.ID}, "Đã đưa tiến trình vào hàng đợi")
}

// HandleStatus returns the snapshot of a running or recently finished job
func HandleStatus(c *gin.Context) {
	jobID := c.Query("jobId")
	if jobID == "" {
		response.Error(c, http.StatusBadRequest, "Thiếu tham số jobId")
		return
	}

	sessionID := c.GetHeader("X-Session-ID")
	if sessionID == "" {
		sessionID = c.ClientIP()
	}

	jobSessionID, found, err := service.GetJobSessionID(jobID)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Lỗi kiểm tra quyền truy cập")
		return
	}
	if !found {
		response.Error(c, http.StatusNotFound, "Không tìm thấy Job hoặc Job đã hết hạn")
		return
	}
	if jobSessionID != sessionID {
		response.Error(c, http.StatusForbidden, "Không có quyền truy cập tiến trình này")
		return
	}

	job, ok := service.GetJob(jobID)
	if !ok {
		// Fallback to SQLite
		snap, dbOk := service.GetJobSnapshot(jobID)
		if !dbOk {
			response.Error(c, http.StatusNotFound, "Không tìm thấy Job hoặc Job đã hết hạn")
			return
		}
		response.SuccessNoMeta(c, snap)
		return
	}

	snapshot := job.GetSnapshot()
	response.SuccessNoMeta(c, snapshot)
}

// HandleCancel stops an active job
func HandleCancel(c *gin.Context) {
	jobID := c.Query("jobId")
	if jobID == "" {
		response.Error(c, http.StatusBadRequest, "Thiếu tham số jobId")
		return
	}

	sessionID := c.GetHeader("X-Session-ID")
	if sessionID == "" {
		sessionID = c.ClientIP()
	}

	jobSessionID, found, err := service.GetJobSessionID(jobID)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Lỗi kiểm tra quyền truy cập")
		return
	}
	if !found {
		response.Error(c, http.StatusNotFound, "Không tìm thấy Job hoặc Job đã hoàn tất")
		return
	}
	if jobSessionID != sessionID {
		response.Error(c, http.StatusForbidden, "Không có quyền hủy tiến trình này")
		return
	}

	job, ok := service.GetJob(jobID)
	if !ok {
		// Try to cancel in DB directly if it's still pending
		if cancelled := service.CancelJobInDB(jobID); cancelled {
			response.SuccessWithMessage(c, nil, "Đã hủy tiến trình trong hàng đợi")
			return
		}
		response.Error(c, http.StatusNotFound, "Không tìm thấy Job hoặc Job đã hoàn tất")
		return
	}

	job.Cancel()
	response.SuccessWithMessage(c, nil, "Đã gửi lệnh dừng tiến trình sao chép")
}

// HandleStream provides SSE updates for a running job
func HandleStream(c *gin.Context) {
	jobID := c.Query("jobId")
	if jobID == "" {
		response.Error(c, http.StatusBadRequest, "Thiếu tham số jobId")
		c.Abort()
		return
	}

	sessionID := c.Query("sessionId")
	if sessionID == "" {
		sessionID = c.ClientIP()
	}

	jobSessionID, found, err := service.GetJobSessionID(jobID)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, "Lỗi kiểm tra quyền truy cập")
		c.Abort()
		return
	}
	if !found {
		response.Error(c, http.StatusNotFound, "Không tìm thấy Job")
		c.Abort()
		return
	}
	if jobSessionID != sessionID {
		response.Error(c, http.StatusForbidden, "Không có quyền truy cập tiến trình này")
		c.Abort()
		return
	}

	// Parse offset from query
	offsetStr := c.Query("fromOffset")
	var fromOffset int64 = 0
	if offsetStr != "" {
		fmt.Sscanf(offsetStr, "%d", &fromOffset)
	}

	job, ok := service.GetJob(jobID)
	if !ok {
		// Thử kiểm tra trong SQLite
		snap, dbOk := service.GetJobSnapshot(jobID)
		if !dbOk {
			response.Error(c, http.StatusNotFound, "Không tìm thấy Job")
			c.Abort()
			return
		}

		// Nếu Job đã kết thúc / lỗi / cancelled, ta chỉ cần replay log cũ và đóng kết nối SSE
		c.Writer.Header().Set("Content-Type", "text/event-stream")
		c.Writer.Header().Set("Cache-Control", "no-cache")
		c.Writer.Header().Set("Connection", "keep-alive")
		c.Writer.Header().Set("X-Accel-Buffering", "no")
		c.Writer.WriteHeaderNow()

		streamLogChunks(c, jobID, fromOffset)

		events := service.GetJobLogs(jobID)
		for _, ev := range events {
			c.Render(-1, sseEventRender{Event: ev})
			c.Writer.Flush()
		}

		// Emit final event to close UI nicely
		if snap.Status == "done" {
			c.Render(-1, sseEventRender{Event: models.SSEEvent{Type: "COMPLETE"}})
		} else if snap.Status == "error" || snap.Status == "cancelled" {
			c.Render(-1, sseEventRender{Event: models.SSEEvent{Type: "ERROR", Message: snap.LastError}})
		}
		c.Writer.Flush()
		return
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	c.Writer.WriteHeaderNow()

	clientGone := c.Request.Context().Done()

	// 1. Subscribe to pub-sub events TRƯỚC để không miss event mới
	ch := job.Subscribe()
	defer job.Unsubscribe(ch)

	// 2. Replay real-time raw logs từ file vật lý (sẽ tự động đọc từ fromOffset)
	streamLogChunks(c, jobID, fromOffset)

	// 4. Luôn gửi toàn bộ state event cũ (INFO, START, DONE) để replay UI Progress Bar
	pastEvents := service.GetJobLogs(jobID)
	for _, ev := range pastEvents {
		c.Render(-1, sseEventRender{Event: ev})
		c.Writer.Flush()
	}

	for {
		select {
		case <-clientGone:
			return // Client disconnected
		case ev, ok := <-ch:
			if !ok {
				// Channel closed means job is completely done/error/cancelled
				// Job internally emits COMPLETE / ERROR before closing.
				return
			}

			// SSE format requires starting with "data: " and ending with "\n\n"
			c.Render(-1, sseEventRender{Event: ev})
			c.Writer.Flush()
		}
	}
}

func streamLogChunks(c *gin.Context, jobID string, fromOffset int64) {
	currentOffset := fromOffset
	for {
		lines, newOffset := service.TailJobLog(jobID, 500, currentOffset)

		// Luôn gửi CHUNK để cập nhật lastLogOffset ở Frontend, ngay cả khi lines rỗng
		if len(lines) > 0 || (newOffset > 0 && newOffset != currentOffset) {
			c.Render(-1, sseEventRender{Event: models.SSEEvent{
				Type:    "VERBOSE_CHUNK",
				Message: strings.Join(lines, "\n"),
				Offset:  newOffset,
			}})
			c.Writer.Flush()
		}

		if newOffset <= currentOffset {
			break
		}
		currentOffset = newOffset
	}
}

// sseEventRender is a custom renderer for Server-Sent Events
type sseEventRender struct {
	Event models.SSEEvent
}

func (r sseEventRender) Render(w http.ResponseWriter) error {
	r.WriteContentType(w)
	b, err := json.Marshal(r.Event)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("data: "))
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("\n\n"))
	return err
}

// WriteContentType is intentionally a no-op: Content-Type is set in HandleStream before streaming begins.
func (r sseEventRender) WriteContentType(w http.ResponseWriter) {}

// HandleMyJobs returns all jobs for the current session.
func HandleMyJobs(c *gin.Context) {
	clientIP := c.ClientIP()
	sessionID := c.GetHeader("X-Session-ID")
	if sessionID == "" {
		sessionID = clientIP
	}

	jobs := service.GetJobsBySession(sessionID, 20)

	// Khởi tạo mảng rỗng nếu nil để đảm bảo trả về JSON mảng thay vì null
	if jobs == nil {
		jobs = []models.JobSnapshot{}
	}

	response.SuccessNoMeta(c, jobs)
}

// HandleAdminHistory returns history JSON
func HandleAdminHistory(c *gin.Context) {
	response.SuccessNoMeta(c, service.GetHistory())
}

// HandleAdminRunningJobs returns active jobs
func HandleAdminRunningJobs(c *gin.Context) {
	response.SuccessNoMeta(c, service.GetRunningJobsList())
}

// HandleAdminLogFile streams log file
func HandleAdminLogFile(c *gin.Context) {
	id := c.Query("id")
	if id == "" {
		response.Error(c, http.StatusBadRequest, "Thiếu tham số ID")
		return
	}
	// Validate UUID format để tránh path traversal
	if !isValidUUID(id) {
		response.Error(c, http.StatusBadRequest, "ID không hợp lệ (phải là UUID)")
		return
	}

	logPath := filepath.Join(service.GetDataDir(), "logs", "job_"+id+".log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		response.Error(c, http.StatusNotFound, "Không tìm thấy file log (hoặc đã bị dọn dẹp)")
		return
	}
	c.File(logPath)
}
