package response

import (
	"time"

	"github.com/gin-gonic/gin"
)

type Meta struct {
	Cached    bool      `json:"cached"`
	FetchedAt time.Time `json:"fetched_at"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Message string      `json:"message,omitempty"`
	Meta    *Meta       `json:"meta,omitempty"`
}

// Success trả về response thành công, có gắn thông tin Meta Cache
func Success(c *gin.Context, data interface{}, isCached bool, fetchedAt time.Time) {
	c.JSON(200, APIResponse{
		Success: true,
		Data:    data,
		Meta: &Meta{
			Cached:    isCached,
			FetchedAt: fetchedAt,
		},
	})
}

// SuccessWithMessage trả về response thành công kèm theo một thông báo (message)
func SuccessWithMessage(c *gin.Context, data interface{}, message string) {
	c.JSON(200, APIResponse{
		Success: true,
		Data:    data,
		Message: message,
		Meta: &Meta{
			Cached:    false,
			FetchedAt: time.Now(),
		},
	})
}

// SuccessNoMeta trả về response thành công mà không phải là dữ liệu từ cache (ví dụ realtime streaming)
func SuccessNoMeta(c *gin.Context, data interface{}) {
	c.JSON(200, APIResponse{
		Success: true,
		Data:    data,
		Meta: &Meta{
			Cached:    false,
			FetchedAt: time.Now(),
		},
	})
}

// Error trả về response lỗi chuẩn
func Error(c *gin.Context, status int, err string) {
	c.JSON(status, APIResponse{
		Success: false,
		Error:   err,
		Meta: &Meta{
			Cached:    false,
			FetchedAt: time.Now(),
		},
	})
}
