# Kế hoạch Refactor WHOIS Tool

## 1. Mục tiêu
Chuẩn hóa tool tra cứu WHOIS (Domain) để đạt tiêu chuẩn production (an toàn, chính xác, hiệu năng cao và đúng quy chuẩn `GEMINI.md`). Kế hoạch sẽ giải quyết tất cả các tồn đọng từ review trước đó (P1, P2, P3) và cập nhật logic hiển thị vòng đời (Timeline) theo đúng chuẩn.

## 2. Chi tiết các hạng mục triển khai

### Pha 1: Backend - Core Logic & Bảo mật (P1 & P2)
*   **Hỗ trợ Tên miền IDN (Unicode):** 
    *   Sử dụng package `golang.org/x/net/idna` để normalize các domain tiếng Việt (hoặc Unicode) sang định dạng Punycode trước khi gửi query đến máy chủ WHOIS/RDAP.
*   **Tối ưu luồng truy vấn (Query Flow) & Referral:**
    *   Sửa lỗi bỏ qua (skip) referral quá sớm đối với tên miền quốc tế. Đảm bảo query đủ sâu để lấy thông tin Registrar chi tiết (theo WHOIS RFC).
*   **Metadata Nguồn và Độ tin cậy (Confidence):**
    *   Thêm các trường `source`, `source_type`, `confidence` (high/medium/low), `authoritative_verified` vào metadata trả về.
    *   Khi sử dụng Tino làm fallback hoặc fast source, đánh dấu confidence là `medium`.
*   **Chuẩn hóa Kiến trúc (GEMINI.md):**
    *   Xóa bỏ model response cục bộ `models.APIResponse`. Sử dụng `internal/platform/response.Success()` và `Error()`.
    *   Map mã lỗi HTTP chuẩn xác: `400` (input sai/IP), `422` (lỗi logic nghiệp vụ), `504` (timeout), `502` (lỗi từ upstream), `200` (thành công hoặc có data fallback).
*   **Tối ưu Caching:**
    *   Điều chỉnh TTL: Tên miền đã đăng ký (`1h - 6h`), tên miền chưa đăng ký/Available (`5m - 10m`).
*   **Log Sanitize:**
    *   Đảm bảo các log ở backend liên quan tới domain hoặc referral URL phải được truncate (bằng `[]rune`) và loại bỏ ký tự điều khiển (`\r\n`).
*   **Test Coverage:**
    *   Thêm unit test cho các luồng xử lý: Parse IDN, Tino fallback, VNNIC timeout, RDAP/WHOIS referral logic.

### Pha 2: Frontend - Hiển thị & UX (P2, P3 & Yêu cầu mới)
*   **Sửa lỗi Fallback Registrant (Chủ sở hữu):**
    *   Cập nhật `whois.js`: Xóa logic tự động gán `"Domain Admin"` khi `data.registrant` rỗng. Thay bằng hiển thị `"Không công bố"`. (Trừ khi backend trả về rõ nội dung đó).
*   **Xử lý hiển thị vòng đời tên miền (Timeline):**
    *   Tạo hàm `getLifecyclePolicy(domain)` ở frontend (có thể kết hợp flag từ backend để xác định rõ loại tld).
    *   `.vn`: Hiển thị Timeline gốc của Việt Nam (tiêu đề: "Vòng đời tên miền .vn").
    *   **ICANN gTLD** (như .com, .net...): Hiển thị Timeline tham khảo kèm ghi chú nhắc user rằng đây là chuẩn ICANN tham khảo. Mảng `ICANN_GTLD_SET` sẽ được lưu ở JS (hoặc backend trả).
    *   **ccTLD khác / Unknown:** Ẩn hoàn toàn block Timeline.
*   **Hiển thị Metadata & Cảnh báo độ tin cậy:**
    *   Bổ sung dòng thông tin hiển thị Nguồn dữ liệu (VD: `Nguồn: Tino (Tra cứu nhanh)` hoặc `Nguồn: VNNIC`).
    *   Nếu trả về là `Available` nhưng nguồn chỉ có confidence Medium, thay đổi văn bản trên UI cẩn thận hơn (VD: "Có thể đăng ký" thay vì chốt cứng).
*   **Tối ưu UI/UX & CSS:**
    *   Dọn dẹp các lệnh `console.log` ở production.
    *   Scope chặt chẽ các selector CSS (`.card__header`, `.card__subtitle`) dưới định danh `.page--whois` hoặc class riêng biệt của tool theo BEM.

### Pha 3: Review & Test Cuối
*   Kiểm tra tổng thể các chuẩn theo `GEMINI.md` (màu sắc, component).
*   Đảm bảo không bị vỡ font chữ Tiếng Việt khi thao tác.

---
Vui lòng duyệt kế hoạch này để tao bắt đầu chuyển sang code nhé!
