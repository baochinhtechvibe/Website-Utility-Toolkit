package service

import (
	"strings"
)

// FriendlyError returns a sanitized error message suitable for client display,
// hiding internal infrastructure details like IPs, raw IMAP responses, or credentials.
func FriendlyError(err error) error {
	if err == nil {
		return nil
	}

	msg := err.Error()
	lowerMsg := strings.ToLower(msg)

	// Authentication errors
	if strings.Contains(lowerMsg, "invalid credentials") || 
	   strings.Contains(lowerMsg, "login failed") ||
	   strings.Contains(lowerMsg, "authentication failed") {
		return newSanitizedError("Sai tên đăng nhập hoặc mật khẩu (Nếu dùng Gmail/Outlook, vui lòng sử dụng App Password).")
	}

	// Connection errors
	if strings.Contains(lowerMsg, "connection refused") || 
	   strings.Contains(lowerMsg, "no such host") ||
	   strings.Contains(lowerMsg, "không phân giải được hostname") {
		return newSanitizedError("Không thể phân giải hoặc kết nối tới máy chủ IMAP. Vui lòng kiểm tra lại Host và Port.")
	}

	if strings.Contains(lowerMsg, "timeout") || strings.Contains(lowerMsg, "i/o timeout") {
		return newSanitizedError("Kết nối tới máy chủ quá hạn (Timeout).")
	}

	// SSRF Protection errors
	if strings.Contains(msg, "địa chỉ IP nội bộ không được phép") {
		return newSanitizedError("Tên miền hoặc máy chủ không được phép kết nối (SSRF Protection).")
	}

	// TLS errors
	if strings.Contains(lowerMsg, "tls") || strings.Contains(lowerMsg, "certificate") {
		return newSanitizedError("Lỗi kết nối bảo mật (SSL/TLS). Vui lòng kiểm tra lại chế độ bảo mật hoặc cấu hình chứng chỉ của máy chủ.")
	}

	// Quota / Storage errors
	if strings.Contains(lowerMsg, "over quota") || strings.Contains(lowerMsg, "disk full") {
		return newSanitizedError("Hộp thư gốc hoặc đích đã đầy (Over Quota).")
	}

	// Rate limit / Too many connections
	if strings.Contains(lowerMsg, "too many connections") || strings.Contains(lowerMsg, "rate limit") || strings.Contains(lowerMsg, "bandwidth") {
		return newSanitizedError("Máy chủ IMAP giới hạn tốc độ hoặc số lượng kết nối. Vui lòng thử lại sau.")
	}

	// Default fallback (hides the original error to prevent information leakage)
	// We log the original error elsewhere if needed, but to the client we return a generic message.
	return newSanitizedError("Đã xảy ra lỗi kết nối hoặc thao tác với máy chủ IMAP.")
}

type sanitizedError struct {
	msg string
}

func (e *sanitizedError) Error() string {
	return e.msg
}

func newSanitizedError(msg string) error {
	return &sanitizedError{msg: msg}
}

// FriendlyErrorMessage extracts the string from FriendlyError safely
func FriendlyErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	if se, ok := err.(*sanitizedError); ok {
		return se.msg // already sanitized
	}
	return FriendlyError(err).Error()
}
