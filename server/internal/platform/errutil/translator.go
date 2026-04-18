package errutil

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

var (
	reDNSLookup    = regexp.MustCompile(`lookup ([a-zA-Z0-9\-\.]+): no such host`)
	reCertValidFor = regexp.MustCompile(`x509: certificate is valid for ([^,]+), not ([^\s]+)`)
)

// TranslateError dịch các lỗi mạng/hệ thống sang Tiếng Việt dễ hiểu.
// Lưu ý: hàm này KHÔNG BAO GIỜ trả lỗi gốc (err.Error()) ra ngoài client
// để tránh lộ thông tin nội bộ (path, IP, stack trace).
func TranslateError(err error) string {
	if err == nil {
		return ""
	}

	msg := err.Error()
	msgLower := strings.ToLower(msg)

	// ─── 1. DNS Errors ────────────────────────────────────────────────────────
	if strings.Contains(msgLower, "no such host") {
		match := reDNSLookup.FindStringSubmatch(msg)
		if len(match) > 1 {
			return fmt.Sprintf("Không phân giải được tên miền %s. Vui lòng kiểm tra lại địa chỉ website.", match[1])
		}
		return "Không phân giải được tên miền. Vui lòng kiểm tra lại địa chỉ website."
	}
	if strings.Contains(msgLower, "server misbehaving") || strings.Contains(msgLower, "dns lookup") {
		return "Máy chủ DNS không phản hồi hoặc gặp sự cố. Vui lòng thử lại sau."
	}

	// ─── 2. SSRF Protection ───────────────────────────────────────────────────
	if strings.Contains(msg, "SSRF Protection") {
		return "URL trỏ tới địa chỉ IP nội bộ hoặc mạng riêng, không được phép truy cập từ hệ thống."
	}

	// ─── 3. Connection Errors ─────────────────────────────────────────────────
	if strings.Contains(msgLower, "connection refused") {
		return "Kết nối bị từ chối từ máy chủ mục tiêu. Website có thể đang chặn các yêu cầu tự động hoặc đang ngoại tuyến."
	}
	if strings.Contains(msgLower, "connection reset by peer") {
		return "Kết nối bị máy chủ mục tiêu ngắt đột ngột (Connection Reset)."
	}
	if strings.Contains(msgLower, "no route to host") {
		return "Không tìm thấy đường truyền tới máy chủ (No route to host)."
	}
	if strings.Contains(msgLower, "network is unreachable") {
		return "Mạng không thể truy cập được. Kiểm tra kết nối internet hoặc thử lại sau."
	}
	if strings.Contains(msgLower, "use of closed network connection") {
		return "Kết nối mạng đã bị đóng bất ngờ. Vui lòng thử lại."
	}

	// ─── 4. EOF / Body đứt giữa chừng ────────────────────────────────────────
	if strings.Contains(msgLower, "unexpected eof") || (strings.Contains(msgLower, "eof") && !strings.Contains(msgLower, "x509")) {
		return "Máy chủ mục tiêu ngắt kết nối giữa chừng trước khi gửi hết dữ liệu. Vui lòng thử lại."
	}

	// ─── 5. Timeouts ─────────────────────────────────────────────────────────
	if strings.Contains(msgLower, "i/o timeout") {
		return "Hết thời gian chờ đọc/ghi dữ liệu (I/O Timeout). Máy chủ phản hồi quá chậm."
	}
	if strings.Contains(msgLower, "timeout") || strings.Contains(msgLower, "deadline exceeded") {
		return "Hết thời gian chờ kết nối (Timeout). Máy chủ phản hồi quá chậm hoặc đường truyền không ổn định."
	}

	// ─── 6. SSL/TLS Errors ───────────────────────────────────────────────────
	if strings.Contains(msgLower, "x509: certificate has expired") {
		return "Chứng chỉ SSL của website đã hết hạn. Vui lòng liên hệ quản trị viên website để gia hạn."
	}
	if strings.Contains(msgLower, "x509: certificate is valid for") {
		match := reCertValidFor.FindStringSubmatch(msg)
		if len(match) > 2 {
			return fmt.Sprintf("Chứng chỉ SSL không khớp tên miền. Cert hợp lệ cho %s, không phải %s.", match[1], match[2])
		}
		return "Chứng chỉ SSL không khớp với tên miền được yêu cầu."
	}
	if strings.Contains(msgLower, "certificate signed by unknown authority") || strings.Contains(msgLower, "x509: certificate") {
		return "Chứng chỉ SSL của website không hợp lệ hoặc không đáng tin cậy."
	}
	if strings.Contains(msgLower, "tls: handshake failure") || strings.Contains(msgLower, "remote error: tls") {
		return "Lỗi bắt tay SSL/TLS. Máy chủ có thể sử dụng giao thức bảo mật cũ không được hỗ trợ."
	}
	if strings.Contains(msgLower, "tls: internal error") {
		return "Lỗi nội bộ SSL/TLS từ phía máy chủ mục tiêu. Vui lòng thử lại sau."
	}

	// ─── 7. HTTP Protocol Errors ─────────────────────────────────────────────
	if strings.Contains(msgLower, "too many redirects") || strings.Contains(msgLower, "stopped after") {
		return "Website bị lỗi vòng lặp chuyển hướng (Too many redirects)."
	}
	if strings.Contains(msgLower, "server gave http response to https client") {
		return "Máy chủ không hỗ trợ HTTPS nhưng URL sử dụng giao thức https://. Hãy thử lại với http://."
	}
	if strings.Contains(msgLower, "malformed http") || strings.Contains(msgLower, "http: server closed") {
		return "Máy chủ trả về phản hồi HTTP không đúng định dạng hoặc đóng kết nối đột ngột."
	}

	// ─── 8. HTTP/2 Errors ────────────────────────────────────────────────────
	if strings.Contains(msgLower, "http2:") || strings.Contains(msgLower, "goaway") {
		return "Lỗi giao thức HTTP/2 từ máy chủ mục tiêu. Vui lòng thử lại sau."
	}

	// ─── 9. Context Cancelled ────────────────────────────────────────────────
	if strings.Contains(msgLower, "context canceled") {
		return "Yêu cầu đã bị hủy bỏ. Vui lòng thử lại."
	}

	// ─── 10. Validation & Custom Errors ──────────────────────────────────────
	if strings.Contains(msgLower, "url phải bắt đầu bằng http") {
		return "Địa chỉ website phải bắt đầu bằng http:// hoặc https://."
	}
	if strings.Contains(msgLower, "url không hợp lệ") {
		return "Địa chỉ website không hợp lệ. Vui lòng kiểm tra lại."
	}
	if strings.Contains(msgLower, "content-type không hợp lệ") {
		return "Website không trả về định dạng HTML. Công cụ này chỉ hỗ trợ quét các trang web."
	}
	if strings.Contains(msgLower, "không thể tạo request") {
		return "Không thể tạo yêu cầu quét. Vui lòng thử lại."
	}
	if strings.Contains(msgLower, "website trả về mã lỗi http") {
		return "Máy chủ website mục tiêu trả về lỗi HTTP (4xx/5xx). Không thể thu thập liên kết."
	}

	// ─── FALLBACK: Không trả lỗi gốc ra client! ─────────────────────────────
	// Log lỗi nội bộ để debug, nhưng chỉ trả message generic cho user.
	log.Warn().
		Str("original_error", msg).
		Msg("errutil.TranslateError: lỗi chưa được map, trả message generic cho client")

	return "Đã xảy ra lỗi không xác định khi xử lý yêu cầu. Vui lòng thử lại sau."
}
