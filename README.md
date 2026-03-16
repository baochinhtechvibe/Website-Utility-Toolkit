# Website Utility Toolkit 🚀

[![Go Version](https://img.shields.io/github/go-mod/go-version/baochinhtechvibe/Website-Utility-Toolkit?filename=server%2Fgo.mod)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Một bộ công cụ "tất cả trong một" dành cho Quản trị viên Website và Nhà phát triển. Được thiết kế với tiêu chí: **Nhanh, Đẹp, và Chuẩn Production**.

![Tech Stack](https://img.shields.io/badge/Stack-Go%20%7C%20Gin%20%7C%20Vanilla%20JS%20%7C%20CSS-blue?style=for-the-badge)

## ✨ Tính Năng Nổi Bật

### 🕵️‍♂️ DNS Lookup & Security
- **Comprehensive DNS**: Tra cứu đầy đủ các bản ghi A, AAAA, MX, NS, CNAME, TXT, PTR.
- **DNSSEC Validation**: Kiểm tra tính xác thực của tên miền qua DNSKEY, DS, RRSIG.
- **Blacklist Check**: Kiểm tra IP/Domain có nằm trong danh sách đen (RBL) thời gian thực hay không.
- **DNS Trace**: Truy dấu bản ghi từ các Root Server.

### 🏠 My IP Lookup & GeoIP
- **Trình diện IP**: Hiển thị IP Public, User Agent, Trình duyệt và Hệ điều hành.
- **Geo-location**: Bản đồ vị trí, ISP, ASN và nhận diện Proxy/VPN.

### 🛡️ Chmod Calculator (Modern Version)
- **Interactive Logic**: Tính quyền qua Octal, Symbolic hoặc Checkbox.
- **Security Advisor**: Hệ thống cảnh báo tiếng Việt thông minh cho các quyền nhạy cảm (777, World-writable).
- **Terminal Preview**: Mô phỏng dòng lệnh `ls -l` trực quan.

### 🔒 SSL & Security Tools
- **SSL Checker**: Kiểm tra chứng chỉ, ngày hết hạn và chuỗi CA.
- **Redirect / Mixed Content**: Phân tích lỗi bảo mật trên website.

## 🛠 Công Nghệ Sử Dụng

- **Backend**: Golang & Gin Framework (Hiệu năng cực cao, gọn nhẹ).
- **Frontend**: Vanilla HTML5, CSS3 (Modern Utility-first) & JavaScript (ES6+).
- **Design System**: Hệ thống Token màu sắc (Light/Dark mode), Spacing chuẩn mực.
- **Icons**: FontAwesome 6 Pro.

## 🚀 Cài Đặt & Chạy Thử

### Yêu cầu hệ thống:
- Go 1.20+
- Node.js (Tùy chọn cho development server)

### 1. Clone Project
```bash
git clone https://github.com/baochinhtechvibe/Website-Utility-Toolkit.git
cd Website-Utility-Toolkit
```

### 2. Chạy Backend (API)
```bash
cd server
go mod tidy
go run cmd/main.go
```
*Mặc định API sẽ chạy tại `http://localhost:8080`*

### 3. Chạy Frontend
Bạn có thể mở trực tiếp các file trong thư mục `client/views/` hoặc dùng Live Server để có trải nghiệm tốt nhất.

## 📂 Cấu Trúc Dự Án
```text
├── client/          # Giao diện người dùng (HTML, CSS, JS)
│   ├── src/         # Assets, CSS Tokens, Components
│   └── views/       # Các trang công cụ chi tiết
├── server/          # Mã nguồn Backend (Go)
│   ├── cmd/         # Entry point (Main)
│   ├── internal/    # Business logic, Middleware
│   └── pkg/         # Các package dùng chung
└── README.md        # File này đây!
```

## 🤝 Đóng Góp
Mọi đóng góp (Pull Request) hoặc báo lỗi (Issue) đều được hoan nghênh. Hãy giúp bộ công cụ này trở nên hoàn thiện hơn!

## 📄 Giấy Phép
Dự án được phân phối dưới giấy phép MIT. Xem chi tiết tại [LICENSE](LICENSE).

---
*Phát triển bởi [baochinhtechvibe](https://github.com/baochinhtechvibe)*
