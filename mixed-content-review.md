# 🔍 Review Toàn Diện: Mixed Content Scanner

> Ngày review: 18/04/2026
> Phạm vi: Frontend (HTML, CSS, JS) + Backend (Go)

---

## 📊 Tổng Quan Đánh Giá

| Tiêu chí | Điểm | Ghi chú |
|---|---|---|
| Kiến trúc Backend | ⭐⭐⭐⭐ | Chuẩn module, SSRF tốt |
| Hiệu suất Backend | ⭐⭐⭐ | Có điểm cần tối ưu |
| Bảo mật Backend | ⭐⭐⭐⭐ | SSRF protection + IP check |
| Design System Compliance | ⭐⭐⭐ | Có vài chỗ vi phạm |
| JS Code Quality | ⭐⭐⭐⭐ | Gần chuẩn, vài lỗi nhỏ |
| UX/Accessibility | ⭐⭐⭐ | Thiếu vài chi tiết |

---

## 🔴 LỖI NGHIÊM TRỌNG (Phải Fix Ngay)

### 1. HTML: Vi phạm Quy tắc 13 — Inline CSS

**File:** `client/views/tools/mixed-content.html` dòng 208, 239

Dùng `style="..."` trực tiếp — vi phạm GEMINI.md quy tắc #13.

```html
<!-- ❌ Dòng 208 -->
<i class="fa-solid fa-circle-check mc-empty__icon mb-2"
    style="font-size: 2rem; color: var(--color-success-text);"></i>

<!-- ❌ Dòng 239 -->
<i class="fa-solid fa-circle-check text-success mb-4" style="font-size: 3rem;"></i>
```

**Fix:** Chuyển vào file `mixed-content.css` thành class riêng.

---

### 2. HTML: Vi phạm Quy tắc 7 — Import CSS lẻ tẻ

**File:** `client/views/tools/mixed-content.html` dòng 11

Import riêng `mixed-content.css` bằng thẻ `<link>` thay vì dùng `@import` trong `main.css`.

```html
<!-- ❌ Dòng 10-11: 2 link CSS lẻ tẻ -->
<link rel="stylesheet" href="../../src/css/main.css">
<link rel="stylesheet" href="../../src/css/tools/mixed-content.css">
```

**Fix:** Xóa dòng 11, thêm `@import url('./tools/mixed-content.css');` vào `main.css`.

---

### 3. HTML: Dùng class `text-xl` (Tailwind) — Vi phạm Quy tắc 1

**File:** `client/views/tools/mixed-content.html` dòng 240

Dùng `text-xl` — class này thuộc hệ thống Tailwind, project không có.

```html
<!-- ❌ Dòng 240 -->
<h3 class="text-success font-bold text-xl">Tuyệt vời!...</h3>
```

---

### 4. HTML: `noIssuesCard` tự chế border — Vi phạm Quy tắc 14

**File:** `client/views/tools/mixed-content.html` dòng 238

Dùng `border rounded` thay vì dùng component Card chuẩn.

```html
<!-- ❌ Dòng 238 -->
<div id="noIssuesCard" class="d-none py-10 text-center border rounded">
```

**Fix:** Bọc bằng component `.card .card--flat` hoặc `.message-card .message-card--success`.

---

### 5. JS: DOM Elements ở Global Scope — Vi phạm Quy tắc 4

**File:** `client/src/js/tools/mixed-content/mixed-content.js` dòng 18-44, 352-383

Toàn bộ DOM elements (dòng 18-44) và event listeners (dòng 352-376, 381-383) được khai báo ở **global scope**, ngoài hàm `init()`. Chỉ có `setupInteractions()` và URL auto-scan nằm trong `init()`.

```javascript
// ❌ Global scope — dòng 18-44
const form = document.getElementById("mixedContentForm");
const urlInput = document.getElementById("mixedContentUrl");
// ...

// ❌ Global scope — dòng 352-376
btnCopyLink?.addEventListener("click", async () => { ... });
btnExportCsv?.addEventListener("click", () => { ... });
btnCopyFixes?.addEventListener("click", () => { ... });

// ❌ Global scope — dòng 379-383
let isScanning = false;
urlInput?.addEventListener("input", () => { resetUI(); });
```

**Fix:** Di chuyển tất cả vào trong `init()`.

---

### 6. Backend: Lỗi bảo mật — Lộ thông tin lỗi gốc ra response

**File:** `server/internal/modules/mixed-content/handlers/handlers.go` dòng 37-40

Khi scan thất bại, trả thẳng `err.Error()` cho client. Nếu lỗi gốc chứa thông tin nội bộ (path, IP nội bộ, stack trace...) sẽ bị lộ ra ngoài.

```go
// ❌ handlers.go dòng 37-40
c.JSON(http.StatusBadRequest, gin.H{
    "success": false,
    "message": err.Error(),  // ← Lộ lỗi gốc!
})
```

**Fix:** Dùng `response.Error()` đã có sẵn, hoặc map lỗi sang message tiếng Việt chuẩn.

---

## 🟡 VẤN ĐỀ CẦN TỐI ƯU

### 7. Backend: `passiveCount` đếm sai — gộp cả Info vào Passive

**File:** `server/internal/modules/mixed-content/service/service.go` dòng 354-361

Khi đếm `activeCount` vs `passiveCount`, mọi item không phải "Active" đều bị tính là "Passive", bao gồm cả type "Info" (link, form).

```go
// ❌ service.go dòng 354-361
for _, it := range items {
    if it.Type == "Active" {
        activeCount++
    } else {
        passiveCount++  // ← Info cũng bị đếm vào đây
    }
}
```

**Fix:** Thêm nhánh đếm riêng cho Info, hoặc thêm `infoCount` vào ScanData.

---

### 8. Backend: HTTP Client không reuse — tạo mới mỗi request

**File:** `server/internal/modules/mixed-content/service/service.go` dòng 66-108, 332

Mỗi lần scan đều gọi `newSecureClient()` tạo `http.Client` + `http.Transport` mới. Điều này gây:
- Không reuse TCP connection pool
- Không tận dụng TLS session cache
- Overhead tạo Transport mỗi lần

```go
// ❌ Dòng 332 — tạo mới mỗi request
client := newSecureClient(req.IgnoreTLSErrors)
```

**Fix:** Tạo 2 client singleton (1 có TLS skip, 1 không) và reuse.

```go
var (
    defaultClient    *http.Client
    insecureClient   *http.Client
    clientOnce       sync.Once
)

func getClient(ignoreTLS bool) *http.Client {
    clientOnce.Do(func() {
        defaultClient = buildClient(false)
        insecureClient = buildClient(true)
    })
    if ignoreTLS {
        return insecureClient
    }
    return defaultClient
}
```

---

### 9. Backend: Cache Memory Leak — không có cơ chế cleanup

**File:** `server/internal/modules/mixed-content/service/service.go` dòng 39-62

`sync.Map` chỉ xóa entry khi có request trúng key đã hết hạn (`cacheGet`). Nếu user scan rất nhiều URL khác nhau rồi không bao giờ quay lại, các entry hết hạn sẽ **nằm mãi trong RAM** cho đến khi process restart.

**Fix:** Thêm goroutine cleanup định kỳ:

```go
func init() {
    go func() {
        ticker := time.NewTicker(10 * time.Minute)
        defer ticker.Stop()
        for range ticker.C {
            now := time.Now()
            cacheMap.Range(func(key, value interface{}) bool {
                if entry, ok := value.(cacheEntry); ok {
                    if now.After(entry.expiresAt) {
                        cacheMap.Delete(key)
                    }
                }
                return true
            })
        }
    }()
}
```

---

### 10. Backend: Thiếu Rate Limiting riêng cho mixed-content

**File:** `server/internal/modules/mixed-content/routes.go`

Scan mixed content là thao tác tốn tài nguyên (fetch HTML từ bên ngoài). Nếu không có rate limit, server dễ bị abuse làm proxy fetch HTML.

---

### 11. Backend: Thiếu validate Content-Type response

**File:** `server/internal/modules/mixed-content/service/service.go` dòng 341-346

Sau khi fetch URL, không kiểm tra `Content-Type` response. Nếu user nhập URL trỏ tới file binary (PDF, ZIP...), server vẫn cố parse HTML → lãng phí CPU.

**Fix:** Thêm check sau `client.Do()`:

```go
ct := resp.Header.Get("Content-Type")
if !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") {
    return nil, fmt.Errorf("URL không trả về trang HTML (Content-Type: %s)", ct), false, time.Time{}
}
```

---

### 12. Frontend: `urlInput.addEventListener("input")` xung đột với Validator — Vi phạm Quy tắc 26

**File:** `client/src/js/tools/mixed-content/mixed-content.js` dòng 381-383

Gắn listener `input` vào ô URL gọi `resetUI()` → ẩn luôn `urlError` → đè lên logic hiển thị lỗi của `createRealtimeURLValidator`.

```javascript
// ❌ Dòng 381-383
urlInput?.addEventListener("input", () => {
    resetUI();  // ← Ẩn urlError, xung đột với validator
});
```

**Fix:** Chỉ ẩn `errorCard` và `resultSection`, không ẩn `urlError`:

```javascript
urlInput?.addEventListener("input", () => {
    setDisplay(errorCard, "none");
    setDisplay(resultSection, "none");
});
```

---

## 🟢 ĐIỂM ĐÃ LÀM TỐT

| # | Điểm mạnh | Ghi chú |
|---|---|---|
| ✅ | **SSRF Protection** | `DialContext` + `IsSafeIP()` + block redirect to private IP |
| ✅ | **Body size limit** | `io.LimitReader(resp.Body, 5MB)` ngăn OOM |
| ✅ | **Max items cap** | Giới hạn 200 items, có `truncated` flag |
| ✅ | **Redirect limit** | `maxRedirects = 3` tránh loop |
| ✅ | **XSS Prevention** | `escapeHTML()` + `safeHref()` trên mọi URL render |
| ✅ | **Cache system** | Có `bypassCache`, cache notice UI đầy đủ |
| ✅ | **CSV Export** | RFC 4180 compliant, BOM prefix cho Excel |
| ✅ | **Pagination** | Client-side với page size tuỳ chọn |
| ✅ | **Share URL** | Auto-update URL bar + copy button |
| ✅ | **HTML Parser** | Bao phủ rộng: script, img, srcset, iframe, video, audio, source, object, embed, style, inline style, a, form |
| ✅ | **Custom User-Agent** | Có identifier rõ ràng |
| ✅ | **Response chuẩn** | Dùng `response.Success()` có meta |

---

## 📋 BẢNG TÓM TẮT HÀNH ĐỘNG

| # | Mức độ | Vấn đề | File |
|---|---|---|---|
| 1 | 🔴 Critical | Inline CSS (2 chỗ) | `mixed-content.html:208,239` |
| 2 | 🔴 Critical | Import CSS lẻ tẻ | `mixed-content.html:11` |
| 3 | 🔴 Critical | Class `text-xl` không tồn tại | `mixed-content.html:240` |
| 4 | 🟡 Medium | `noIssuesCard` tự chế border | `mixed-content.html:238` |
| 5 | 🔴 Critical | DOM + Events ở global scope | `mixed-content.js:18-44,352-383` |
| 6 | 🔴 Critical | Lộ lỗi gốc ra response | `handlers.go:37-40` |
| 7 | 🟡 Medium | `passiveCount` đếm sai (gộp Info) | `service.go:354-361` |
| 8 | 🟡 Medium | HTTP Client tạo mới mỗi request | `service.go:66-108,332` |
| 9 | 🟡 Medium | Cache memory leak | `service.go:39-62` |
| 10 | 🟢 Low | Thiếu rate limit riêng | `routes.go` |
| 11 | 🟡 Medium | Không check Content-Type | `service.go:341-346` |
| 12 | 🟡 Medium | Input listener xung đột validator | `mixed-content.js:381-383` |

---

> **Kết luận:** Tool mixed-content đã có nền tảng tốt (SSRF protection, HTML parser bao phủ rộng, cache system, XSS prevention). Tuy nhiên cần fix **5 lỗi Critical** liên quan Design System + bảo mật response, và **6 lỗi Medium** về hiệu suất backend + UX frontend. Khuyến nghị fix theo thứ tự bảng trên — Critical trước, Medium sau.
