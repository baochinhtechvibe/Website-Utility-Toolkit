package response

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
)

// Meta chứa thông tin về nguồn gốc dữ liệu (cache hay fresh)
type Meta struct {
	Cached    bool      `json:"cached"`
	FetchedAt time.Time `json:"fetched_at"`
}

// APIResponse là cấu trúc response chuẩn cho toàn bộ hệ thống.
// Lưu ý bảo mật: KHÔNG có trường Error raw để tránh lộ thông tin nội bộ.
// - success: true/false
// - data: payload khi thành công (omitempty)
// - message: thông báo tiếng Việt cho user (đã được xử lý bởi errutil)
// - meta: thông tin cache (chỉ kèm khi có dữ liệu từ lookup)
type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Message string      `json:"message,omitempty"`
	Meta    *Meta       `json:"meta,omitempty"`
}

// Success trả về response thành công có kèm thông tin Meta Cache.
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

// SuccessWithMessage trả về response thành công kèm thông báo bổ sung cho user.
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

// SuccessNoMeta trả về response thành công không có Meta (dữ liệu realtime, không cache).
func SuccessNoMeta(c *gin.Context, data interface{}) {
	c.JSON(200, APIResponse{
		Success: true,
		Data:    data,
	})
}

// Error trả về response lỗi chuẩn hoá.
//
// QUAN TRỌNG (Bảo mật): tham số `msg` PHẢI đã được dịch sang tiếng Việt thông qua
// errutil.TranslateError() trước khi gọi hàm này.
// TUYỆT ĐỐI KHÔNG truyền err.Error() gốc vào đây — sẽ lộ thông tin nội bộ.
func Error(c *gin.Context, status int, msg string) {
	if msg == "" {
		switch status {
		case 400:
			msg = "Dữ liệu yêu cầu không hợp lệ."
		case 401:
			msg = "Không có quyền truy cập."
		case 403:
			msg = "Truy cập bị từ chối."
		case 404:
			msg = "Không tìm thấy tài nguyên."
		case 429:
			msg = "Thao tác quá nhanh, vui lòng chờ một chút rồi thử lại."
		case 500:
			msg = "Đã xảy ra lỗi máy chủ nội bộ. Vui lòng thử lại sau."
		case 502:
			msg = "Lỗi cổng vào (Bad Gateway). Vui lòng thử lại sau."
		case 503:
			msg = "Dịch vụ hiện không khả dụng. Vui lòng thử lại sau."
		case 504:
			msg = "Hết thời gian chờ (Gateway Timeout). Vui lòng thử lại sau."
		default:
			msg = fmt.Sprintf("Đã xảy ra lỗi HTTP %d. Vui lòng thử lại.", status)
		}
	}

	c.JSON(status, APIResponse{
		Success: false,
		Message: msg,
	})
}
