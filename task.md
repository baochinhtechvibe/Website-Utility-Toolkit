# Task: Refactor WHOIS Tool

## Danh sách công việc

### Pha 1: Backend
- [x] Chuyển handler sang shared `response` package (xóa `models.APIResponse`)
- [x] Sửa logic registrant: Không tự gán "Domain Admin" khi rỗng ở backend
- [x] Thêm trường `tld_type` vào `WhoisResponse` để frontend phân biệt gTLD/ccTLD/.vn
- [x] Chuẩn hóa HTTP status code (400/502/504)

### Pha 2: Frontend
- [x] Sửa fallback registrant "Domain Admin" → "Không công bố" trong whois.js
- [x] Tạo hàm `getLifecyclePolicy()` dựa trên `tld_type` từ backend
- [x] Cập nhật `renderTimeline()` theo policy: .vn / gTLD / ẩn
- [x] Thêm ghi chú tham khảo cho timeline gTLD
- [x] Cập nhật tiêu đề timeline theo loại TLD
- [x] Dọn console.log production

### Pha 3: CSS
- [x] Scope `.card__subtitle` dưới `.page--whois`
