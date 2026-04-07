# 🚀 Website Utility Toolkit (All-in-one Admin Suite)

[![Go Version](https://img.shields.io/github/go-mod/go-version/baochinhtechvibe/Website-Utility-Toolkit?filename=server%2Fgo.mod)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/Production-Ready-green.svg)]()

**Website Utility Toolkit** là một bộ công cụ "tất cả trong một" được thiết kế dành riêng cho Quản trị viên Website và Lập trình viên. Hệ thống được tối ưu hóa cho hiệu năng cực cao, giao diện hiện đại (Material & Glassmorphism) và tính bảo mật tuyệt đối.

---

## 🖼️ Giao Diện Công Cụ

````carousel
![DNS Lookup & Trace](file:///C:/Users/workb/.gemini/antigravity/brain/12e85586-54d8-4e84-b8bb-9385c5266ab3/media__1775499677243.png)
<!-- slide -->
![Blacklist RBL Sync](file:///C:/Users/workb/.gemini/antigravity/brain/12e85586-54d8-4e84-b8bb-9385c5266ab3/media__1775534221956.png)
<!-- slide -->
![IP Lookup & GeoIP](file:///C:/Users/workb/.gemini/antigravity/brain/12e85586-54d8-4e84-b8bb-9385c5266ab3/media__1775509265738.png)
<!-- slide -->
![JSON Data Tools](file:///C:/Users/workb/.gemini/antigravity/brain/12e85586-54d8-4e84-b8bb-9385c5266ab3/media__1775509914946.png)
````

---

## ✨ Hệ Sinh Thái Công Cụ (Full Modules)

### 🕵️‍♂️ DNS & Network Hardening
*   **Parallel DNS Lookup**: Tra cứu đồng thời A, AAAA, MX, NS, CNAME, TXT, PTR với tốc độ cực nhanh.
*   **Authoritative DNS Trace**: Truy dấu từ Root Server với cơ chế xử lý song song, giảm latency từ 18s xuống < 3s.
*   **DNSSEC Validation**: Phân tích kỹ thuật DNSKEY, DS records, RRSIG và thuật toán mã hóa.
*   **Real-time Blacklist (RBL)**: Kiểm tra trạng thái IP trên 30+ nhà cung cấp RBL uy tín thông qua SSE (Server-Sent Events).

### 🏠 IP Lookup & Geolocation
*   **Deep Geolocation**: Bản đồ tương tác, ISP, ASN, múi giờ và tọa độ DMS.
*   **Fraud Detection**: Tự động phát hiện VPN Server, Proxy và Hosting Service.
*   **Public IP Fallback**: Cơ chế tự động tìm IP thật khi chạy ở môi trường localhost/dev.

### 📧 Server & Mail Ops
*   **IMAP Migrator**: Công cụ chuyển vùng email hiệu năng cao, đa luồng (Multi-threading) với tiến trình cập nhật thời gian thực.
*   **Chmod Calculator**: Tính toán quyền hạn tệp tin kèm theo cảnh báo bảo mật về User/Group/World.
*   **Redirect Checker**: Phân tích chuỗi chuyển hướng (301, 302, 307...) và đo lường thời gian phản hồi (HTTP Timing).

### 🔒 Security Audit
*   **SSL/TLS Checker**: Phân tích chứng chỉ, ngày hết hạn và độ tin cậy của chuỗi CA (Certificate Authority).
*   **Security Headers**: Kiểm tra CSP, HSTS, X-Frame-Options và đề xuất cấu hình an toàn.
*   **Mixed Content Scanner**: Tìm kiếm các tài nguyên con không an toàn (HTTP) trên trang HTTPS.
*   **Broken Link Scanner**: Quét và phát hiện liên kết hỏng (404, 500) trên toàn trang web.

### 🛠 Developer Toolkit
*   **JSON Suite**: Định dạng, Nén, Kiểm tra lỗi cú pháp, so sánh Diff (Side-by-side) và chuyển đổi sang Go Struct/YAML.
*   **Encoder/Decoder**: Hỗ trợ Base64 (Unicode), URL Encoding và giải mã JWT (Header, Payload, Signature).

---

## 🧠 Kiến Trúc Hệ Thống (Modular Architecture)

Dự án được xây dựng theo triết lý **"Clean Logic - Rich Aesthetic"**:

*   **Backend (Go)**: Sử dụng kiến trúc Modular (Handlers-Models-Service).
    *   **SSE Streaming**: Cung cấp dữ liệu thời gian thực cho các tác vụ nặng (Blacklist, IMAP Migration, Scanner).
    *   **SSRF Protection**: Validator mạnh mẽ ngăn chặn các cuộc tấn công quét mạng nội bộ.
    *   **In-memory Cache**: Hệ thống cache định danh qua Key-Value với TTL tự động giúp giảm tải backend.
*   **Frontend (Vanilla)**:
    *   **CSS Design System**: Sử dụng chuẩn Atomic CSS via CSS Variables (Tokens) giúp giao diện nhất quán và mượt mà.
    *   **Zero Dependency JS**: 100% Vanilla Javascript (ES Modules), tối ưu hóa tốc độ tải trang và xử lý logic tại client.

---

## 🚀 Cài Đặt & Triển Khai

### 1. Chuẩn bị
*   Go 1.25 trở lên.
*   Hệ điều hành: Windows, Linux hoặc macOS.

### 2. Cài đặt Backend
```bash
git clone https://github.com/baochinhtechvibe/Website-Utility-Toolkit.git
cd Website-Utility-Toolkit/server
go mod tidy
```

### 3. Cấu hình (.env)
Tạo file `.env` tại thư mục `/server` (Tham khảo):
```env
APP_ENV=development
APP_PORT=3101
RATE_LIMIT=100
```

### 4. Khởi chạy
```bash
go run cmd/main.go
```
Truy cập `client/views/index.html` thông qua trình duyệt hoặc Live Server để sử dụng.

---

## 📄 Bản Quyền & Giấy Phép

Dự án này được phát hành dưới giấy phép **MIT License**. Xem chi tiết tại [LICENSE](file:///d:/Work%20Space/Workspace/Website-Utility-Toolkit/LICENSE).

---
*Phát triển và bảo trì bởi [Nguyễn Bảo Chính](https://github.com/baochinhtechvibe)*
