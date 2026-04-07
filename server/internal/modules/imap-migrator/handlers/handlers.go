package handlers

import (
	"encoding/json"
	"errors"
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
	job, err := service.CreateAndStartJob(req, clientIP)
	if err != nil {
		var rateErr *service.RateLimitError
		var busyErr *service.ServerBusyError
		if errors.As(err, &rateErr) || errors.As(err, &busyErr) {
			response.Error(c, http.StatusConflict, err.Error())
			return
		}
		response.Error(c, http.StatusInternalServerError, service.FriendlyErrorMessage(err))
		return
	}

	// Start background pipeline
	go service.RunMigration(job.CancelCtx, job, req)

	response.SuccessWithMessage(c, gin.H{"jobId": job.ID}, "Đã bắt đầu tiến trình sao chép IMAP")
}

// HandleStatus returns the snapshot of a running or recently finished job
func HandleStatus(c *gin.Context) {
	jobID := c.Query("jobId")
	if jobID == "" {
		response.Error(c, http.StatusBadRequest, "Thiếu tham số jobId")
		return
	}

	job, ok := service.GetJob(jobID)
	if !ok {
		// Possibly expired or invalid
		response.Error(c, http.StatusNotFound, "Không tìm thấy Job hoặc Job đã hết hạn")
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

	job, ok := service.GetJob(jobID)
	if !ok {
		response.Error(c, http.StatusNotFound, "Không tìm thấy Job hoặc Job đã hết hạn")
		return
	}

	job.Cancel()
	response.SuccessWithMessage(c, nil, "Đã gửi lệnh dừng tiến trình sao chép")
}

// HandleStream provides SSE updates for a running job
func HandleStream(c *gin.Context) {
	jobID := c.Query("jobId")
	if jobID == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "Thiếu tham số jobId"})
		return
	}

	job, ok := service.GetJob(jobID)
	if !ok {
		c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "Không tìm thấy Job"})
		return
	}

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	c.Writer.WriteHeaderNow()

	clientGone := c.Request.Context().Done()
	
	// Subscribe to pub-sub events
	ch := job.Subscribe()
	defer job.Unsubscribe(ch)

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
	cwd, _ := os.Getwd()
	logPath := filepath.Join(cwd, "data", "imap-history", "logs", "job_"+id+".log")
	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		response.Error(c, http.StatusNotFound, "Không tìm thấy file log (hoặc đã bị dọn dẹp)")
		return
	}
	c.File(logPath)
}
