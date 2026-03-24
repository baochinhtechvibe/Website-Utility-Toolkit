# Website Utility Toolkit 🚀

[![Go Version](https://img.shields.io/github/go-mod/go-version/baochinhtechvibe/Website-Utility-Toolkit?filename=server%2Fgo.mod)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A primary "all-in-one" toolkit for Website Administrators and Developers. Built for speed, aesthetics, and production-readiness.

## 🖼️ Giao Diện Công Cụ

````carousel
![DNS Lookup Preview]
<!-- slide -->
![SSL Checker Preview]
![Redirect Checker Preview]
![Mixed Content Scanner Preview]
````

## ✨ Tính Năng Nổi Bật

### 🕵️‍♂️ DNS Lookup & Security
- **Comprehensive DNS**: Tra cứu đầy đủ A, AAAA, MX, NS, CNAME, TXT, PTR.
- **DNSSEC Validation**: Kiểm tra DNSKEY, DS, RRSIG.
- **Blacklist Check**: Đối chiếu RBL thời gian thực.
- **DNS Trace**: Truy dấu từ Root Server.

### 🏠 IP Lookup & GeoIP
- **Trình diện IP**: IP Public, User Agent, OS Info.
- **Geo-location**: Bản đồ, ISP, ASN và Proxy/VPN detection.
- **API Endpoint**: `/api/ip-lookup/my-ip`

### 🛡️ Chmod Calculator
- **Interactive**: Tính qua Octal/Symbolic/Checkbox.
- **Security Advisor**: Cảnh báo quyền nhạy cảm (777, World-writable).

### 🔒 SSL & Security Tools
- **SSL Checker**: Kiểm tra chứng chỉ, ngày hết hạn và chuỗi CA.
- **Mixed Content Scanner**: Phát hiện tài nguyên HTTP không an toàn trên HTTPS.
- **Redirect Checker**: Phân tích chuỗi chuyển hướng (301, 302, 307 etc).

## 🧠 Kiến Trúc Hệ Thống (Standardized)

Dự án được cấu trúc theo mô hình **Modular Architecture** giúp dễ dàng mở rộng:

- **`client/`**: Ứng dụng Single Page Application (SPA) thu nhỏ, sử dụng Vanilla JS mạnh mẽ, giao diện chuẩn Google Material & Glassmorphism.
- **`server/internal/modules/`**: Mỗi công cụ là một module độc lập (domain-driven), tự quản lý Route, Handler, và Service.
- **`server/internal/platform/`**: Chứa các "Core Engine" dùng chung:
    - **Cache**: Hệ thống Memory Cache hiệu năng cao với cơ chế TTL tự động.
    - **Validator**: Bộ lọc SSRF mạnh mẽ, ngăn chặn scan IP nội bộ (127.0.0.1, 192.168.x.x) và bảo mật Input.

## 📡 API Documentation (Tóm tắt)

| Endpoint | Method | Mô tả |
| :--- | :--- | :--- |
| `/api/dns/lookup` | `POST` | Tra cứu bản ghi DNS |
| `/api/ip-lookup/my-ip` | `GET` | Lấy thông tin IP người dùng |
| `/api/mixed-content/scan` | `POST` | Quét Mixed Content của Website |
| `/api/ssl/check` | `POST` | Kiểm tra chứng chỉ SSL/TLS |
| `/api/redirect-checker/analyze` | `POST` | Phân tích chuỗi chuyển hướng |

## 🛠 Công Nghệ Sử Dụng

- **Backend**: Golang 1.25+, Gin Gonic, Zerolog (Logging tốt nhất hiện nay).
- **Frontend**: Vanilla HTML5/CSS3/JS, CSS Variables (Dark/Light mode native).
- **Security**: SSRF Protection, XSS-safe rendering, Rate Limiting Middleware.

## 🚀 Cài Đặt & Chạy Thử

### 1. Clone & Setup
```bash
git clone https://github.com/baochinhtechvibe/Website-Utility-Toolkit.git
cd Website-Utility-Toolkit/server
go mod tidy
```

### 2. Chạy Ứng Dụng
```bash
go run cmd/main.go
```
Truy cập `client/views/index.html` (trực tiếp hoặc qua Live Server) để bắt đầu sử dụng.

---
*Phát triển bởi [baochinhtechvibe](https://github.com/baochinhtechvibe)*

