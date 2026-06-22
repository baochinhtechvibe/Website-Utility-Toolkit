# CODING STANDARDS & LESSONS LEARNED

> Tài liệu này tổng hợp các nguyên tắc bắt buộc khi làm việc với codebase này, được đúc kết từ quá trình refactor thực tế. Mọi AI assistant hoặc developer khi nhận task **phải đọc toàn bộ tài liệu này trước khi bắt đầu code.**

---

## MỤC LỤC NHANH

- [Frontend – CSS & HTML](#frontend--css--html)
- [Frontend – JavaScript](#frontend--javascript)
- [Backend – Go Architecture](#backend--go-architecture)
- [Backend – Security & Performance](#backend--security--performance)
- [Quy trình làm việc](#quy-trình-làm-việc)

---

## FRONTEND – CSS & HTML

### [F-01] KHÔNG DÙNG TAILWIND CSS TÙY TIỆN

Project này **không cài đặt Tailwind CSS đầy đủ**. Tuyệt đối không tự ý dùng các class như `text-xl`, `bg-gray-50`, `text-red-500`, `hidden`, `break-all`...

**Thay thế đúng:**

- Layout/display → dùng helper có sẵn: `.d-none`, `.d-block`, `.d-flex`, `.justify-between` (trong `utilities/helper.css`)
- Typography → kiểm tra `tokens/typography/semantic.css` (VD: `text-base`, `text-secondary`)
- Spacing/background → dùng `utilities/colors.css` và `utilities/spacing.css` (VD: `.py-10`, `.mb-4`)

---

### [F-02] DÙNG ĐÚNG CSS TOKENS – KHÔNG HARDCODE GIÁ TRỊ

Không được hardcode các giá trị như `border-radius: 4px`, `box-shadow: 0 1px 3px rgba(...)`, `transition: 0.3s ease` hay tự bịa biến color CSS.

**Tokens bắt buộc phải dùng:**

- Shadow: `var(--shadow-1)`, `var(--shadow-2)` — từ `shadow/primitive.css`
- Radius: `var(--radius-xs)`, `var(--radius-md)`, `var(--radius-lg)`
- Transition: `var(--transition-base)`, `var(--transition-slow)`
- Color: chỉ được dùng token có thật trong `color/semantic.css` (VD: `--color-surface`, `--color-info`, `--color-text-muted`) hoặc `color/palette.css` (VD: `--gray-50`, `--green-500`). **Tuyệt đối không tự chế token màu mới.**

---

### [F-03] ĐỌC KỸ TOKEN VÀ CLASS TRƯỚC KHI VIẾT CSS MỚI

Trước khi viết bất kỳ CSS nào cho tool mới, **bắt buộc phải mở và đọc** các file sau:

- `client/src/css/base/` — reset và base styles
- `client/src/css/utilities/` — helper, spacing, colors
- `client/src/css/layout/` — layout patterns
- `client/src/css/components/` — tất cả UI components có sẵn
- `client/src/css/tokens/` — đặc biệt là `spacing.css`, `color/palette.css`, `color/semantic.css`

> **Nguyên tắc:** Nếu biến/class không có trong các thư mục trên → nó không tồn tại. Tự dùng bừa sẽ vỡ giao diện.

---

### [F-04] KHÔNG DÙNG INLINE CSS (`style="..."`)

Tuyệt đối không viết thuộc tính CSS trực tiếp vào thẻ HTML.

**Thay thế đúng:**

- Đóng gói vào class cục bộ trong file CSS của tool (VD: `.latency-grid`, `.latency-stat-box`)
- Tận dụng các Utility Class có sẵn trong `utilities/` cho layout nhanh (`d-flex`, `justify-center`, `py-*`)
- HTML phải sạch: dùng BEM cho component, Utility cho layout
- **Với các giá trị động tính bằng JS (VD: `width` của progress bar):** Dùng biến CSS Custom Property (`style="--width: 50%"`) và map trong file CSS (`width: var(--width)`), thay vì gán property CSS trực tiếp (`style="width: 50%"`).

---

### [F-05] KHÔNG DÙNG MÀU PALETTE TRỰC TIẾP

Tuyệt đối không dùng `var(--yellow-100)` hay `var(--gray-500)` trực tiếp trong CSS của tool.

**Thay thế đúng:** Phải map qua Semantic Token (VD: `--color-warning-bg`, `--color-text-muted`). Điều này đảm bảo hệ thống Light/Dark theme hoạt động đúng.

---

### [F-06] KHÔNG TỰ CHẾ BIẾN FONT FAMILY

Không được dùng các biến như `--font-family-primary`, `--font-family-base`, `--font-family-display` — chúng **không tồn tại** trong hệ thống.

**Chỉ 3 font token hợp lệ** (định nghĩa trong `tokens/typography/primitive.css`):

- `var(--font-family-sans)` — text thông thường, UI (Inter)
- `var(--font-family-serif)` — tiêu đề nghệ thuật (Philosopher)
- `var(--font-family-mono)` — code block, dữ liệu thô (Monospace)

---

### [F-07] CHỈ DÙNG FONT AWESOME FREE

Project chỉ tích hợp **FontAwesome Free**. Không được dùng icon của bản Pro (VD: `fa-shield-check` sẽ bị ẩn, gây lệch layout).

**Ví dụ icon Free hợp lệ:** `fa-circle-check`, `fa-shield-halved`, `fa-triangle-exclamation`, `fa-circle-xmark`, `fa-check`, `fa-bolt`, `fa-clock`

---

### [F-08] TÁI SỬ DỤNG COMPONENT – KHÔNG TỰ CHẾ

Nếu file CSS của component đã tồn tại trong `client/src/css/components/` → **đọc file đó, dùng class có sẵn, không viết CSS mới cho giao diện tương tự.**

**Bảng component cốt lõi bắt buộc dùng:**

| Component         | Class gốc                           | Cấu trúc chuẩn                                                                                                          |
| ----------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Card (khung chứa) | `.card`                             | `.card` > `.card__header` > `h2.card__title` (có icon + `.mr-2`) > `.card__body`                                        |
| Card phẳng        | `.card.card--flat`                  | Tương tự Card                                                                                                           |
| Form              | `.form`                             | `.form-field` / `.form-inline` > `.form-label` + `.form-input` / `.form-checkbox`                                       |
| Button            | `.btn`                              | Modifier: `.btn-action`, `.btn-outline`, `.btn-danger`, `.btn-warning`, `.btn-sm`, `.btn-block`                         |
| Thông báo lỗi     | `.message-card.message-card--error` | > `.message-card__header` > `.message-card__title`                                                                      |
| Code block        | `.code-block`                       | > `.code-block__header` > `.code-block__lang` + `.code-block__btn-copy` → `.code-block__body` > `code.code-block__text` |
| Kết quả           | `.result-card`                      | > `.result-card__title` + `.cache-card` (bắt buộc với tool lookup)                                                      |
| Chia sẻ URL       | `.share-card`                       | > `.share-card__input` (readonly) + `.share-card__button.share-card__button--copy`                                      |
| Badge             | `.badge.badge-default`              | Variant: `.badge-success`, `.badge-warning`. Chữ hoa: `.uppercase`                                                      |

---

### [F-09] KHÔNG LỒNG UI COMPONENT VÀO VÙNG `WHITE-SPACE: PRE-WRAP`

Không render các thẻ như `<div class="message-card">` bên trong container có `white-space: pre-wrap` (thường là vùng output code). Template literal có dấu cách/indent sẽ bị render ra màn hình, phá vỡ layout.

**Thay thế đúng:** Tách riêng container kết quả Code và container UI (VD: tạo class `.json-tools__validator-box` riêng, không tái dùng `.json-tools__output`).

---

### [F-10] BORDER PHẢI VIẾT ĐẦY ĐỦ 3 THÀNH PHẦN

Sai: `border: var(--color-border);` — trình duyệt sẽ không render vì thiếu `width` và `style`.

**Đúng:** `border: 1px solid var(--color-border);` hoặc `border: var(--border-width-1) solid var(--color-border);`

---

### [F-11] KHÔNG THÊM CLASS UTILITY THỪA VÀO COMPONENT ĐÃ CÓ LAYOUT SẴN

VD: `.cache-card` đã có `display: flex`, `justify-content: space-between`, `align-items: center` bên trong CSS của nó. Không cần thêm `.flex-row .justify-between .items-center` vào HTML.

→ Đọc CSS của component trước khi viết HTML.

---

### [F-12] CẤU TRÚC HEADER VÀ FOOTER

Khi tạo trang HTML mới, **copy nguyên xi** cấu trúc `<header>` và `<footer>` từ tool có sẵn (VD: `dns.html`). Không tự thiết kế lại.

- Footer chứa `#visit-total` và `#visit-today` cho visit counter — sai class/id sẽ vỡ counter.
- Script path phải trỏ đúng: `../../src/js/main.js`

---

### [F-13] IMPORT CSS: CHỈ MỘT THẺ LINK DUY NHẤT

Trong `<head>` của tool mới, chỉ được có **một thẻ** `<link rel="stylesheet" href="../../src/css/main.css">`.

Nếu tool cần CSS riêng: tạo file `src/css/tools/ten-tool.css`, rồi thêm `@import url('./tools/ten-tool.css');` vào `src/css/main.css`. Không dùng nhiều thẻ `<link>` lẻ.

---

### [F-14] CẬP NHẬT TRANG CHỦ KHI TẠO TOOL MỚI

Sau khi hoàn thành tool mới:

1. Trong `client/views/index.html`: copy một `tool-card` mẫu, sửa icon/title/description/link.
2. Thêm class `.tool-card--[tên-tool]` cho màu icon riêng.
3. Trong `client/src/css/components/tool-card.css`: thêm CSS variable màu icon (VD: `.tool-card--security-header { --tool-card-icon: var(--blue-500); }`).
4. Token màu phải lấy từ `client/src/css/tokens/color/palette.css` — không tự bịa.

---

### [F-15] CONNECTOR LINE TRONG UI CHUỖI / TIMELINE

Để đường nối giữa các node không bị đứt khi nội dung dài:

- Dùng pseudo-element `::after` trên container của mỗi step
- `height: 100%` (hoặc `calc(100% + gap)`) để dây phủ hết chiều cao
- Dùng `z-index` để node circle đè lên trên dây
- `left` căn theo tâm node: `calc(var(--node-size) / 2 - var(--line-width) / 2)`

---

### [F-16] HIỂN THỊ LUỒNG REDIRECT: NGUỒN TRƯỚC – ĐÍCH SAU

Dòng trên: URL Nguồn (link người dùng nhập / tìm thấy trên trang).
Dòng dưới: URL Đích kèm mũi tên `→`.

Không được hiển thị ngược lại — gây nhầm lẫn hướng chuyển hướng.

---

### [F-17] TỐI ƯU MOBILE: GRID NHIỀU CỘT CÓ TEXT DÀI

Không dùng `flex-row` hay grid nhiều cột trên mobile nếu content text dài.

**Thay thế đúng:** Media query để chuyển sang `display: block` hoặc `flex-direction: column`. Đảm bảo icon và label luôn đi cùng nhau. Màu sắc nhãn phải nhất quán Desktop ↔ Mobile.

---

## FRONTEND – JAVASCRIPT

### [J-01] MODULE JS PHẢI CÓ `init()` PATTERN

Không được chạy code hay lấy element ở global scope của file script.

**Cấu trúc bắt buộc:**

```javascript
function init() {
  // Toàn bộ logic khởi tạo, event listener, biến local ở đây
}
document.addEventListener("DOMContentLoaded", init);
```

---

### [J-02] SYNTAX HIGHLIGHTING TRONG CODE OUTPUT

Khi render code block kết quả, phải tận dụng các class highlight có sẵn trong `semantic.css`: `code-keyword`, `code-value`, `code-string`, `code-parameter`, `code-func`, `code-comment`...

---

### [J-03] QUẢN LÝ TRẠNG THÁI BUTTON VÀ LỖI REAL-TIME

Mọi form phải có:

1. Hàm `updateButtonStates()`: set `disabled = true` cho nút hành động khi input trống, tránh user nhấn mù.
2. Event listener `input` trên mọi textarea: khi user gõ phím, dọn sạch ngay lỗi cũ (xóa `errorCard`, xóa class `.is-invalid`).

---

### [J-04] KHÔNG XÓA CLASS GỐC KHI TOGGLE STATE

Khi toggle trạng thái button bằng JavaScript, chỉ thêm/bớt class Modifier (`.btn-action`, `.btn-outline`, `.active`...). **Tuyệt đối không bao giờ xóa class cấu trúc xương sống** như `.btn`, `.card`, `.message-card`.

---

### [J-05] HIGHLIGHT LỖI DÙNG NATIVE BROWSER API

Không viết thư viện CSS overlay phức tạp để highlight dòng lỗi trong textarea.

**Dùng native API:** `textarea.focus()` + `textarea.setSelectionRange(pos, pos+1)`. Tự động scroll đến đúng vị trí, không tốn dòng CSS nào. Đồng thời dịch thông báo lỗi từ tiếng Anh (V8) sang tiếng Việt dễ hiểu.

---

### [J-06] ĐỒNG BỘ VALIDATOR KHI GÁN GIÁ TRỊ BẰNG CODE

Khi normalize và gán lại `input.value = newValue` bằng JS, trình duyệt không tự phát sự kiện `input`. Validator realtime sẽ không biết giá trị đã đổi.

**Bắt buộc gọi sau mỗi lần gán:** `input.dispatchEvent(new Event('input'));`

---

### [J-07] THỐNG NHẤT CƠ CHẾ ẨN/HIỆN LỖI

Không mix `element.style.display = 'none'` (inline style) với class `.d-none`. Inline style có priority cao hơn class, khiến validator không thể hiện lại lỗi.

**Chọn một cơ chế duy nhất:** dùng `classList.add('d-none')` / `classList.remove('d-none')` để nhất quán với validator.

---

### [J-08] TRÁNH XUNG ĐỘT EVENT LISTENER VỚI VALIDATOR CHUNG

Khi dùng `createRealtimeURLValidator` từ `utils/validation.js`, không được gắn thêm listener `input` để `hideError()` vào cùng ô input — sẽ ẩn luôn thông báo lỗi của validator.

**Nguyên tắc:** Để validator tự quản lý hiện/ẩn lỗi validate. Logic tool chỉ ẩn Card kết quả cũ hoặc Card lỗi logic (lookup error) — không được đụng vào `#urlValidationError` hay element nào của validator.

---

### [J-09] XỬ LÝ CACHE NOTICE TRONG UI LOOKUP

Với mọi tool tra cứu (lookup), **bắt buộc hiển thị cache notice** dù kết quả là fresh hay từ cache.

**Logic:**

- Nếu `meta.cached = true` → hiển thị: _"Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc..."_
- Nếu `meta.cached = false` → hiển thị: _"Kết quả tra cứu mới nhất lúc..."_
- Nút "Làm mới" phải gửi request kèm `bypassCache=true`

Tham khảo cấu trúc HTML (class `.cache-card`) từ `dns.html`, logic JS từ `dns.js` hoặc `web-latency.js`.

---

### [J-10] NHẤT QUÁN UI/UX GIỮA CÁC TOOL TƯƠNG ĐỒNG

Các tool có cùng hành vi phải có UX y hệt nhau. VD: nếu DNS dùng icon `fa-bolt` cho dữ liệu mới và `fa-clock` cho cache, WHOIS phải làm y chang. Không tự thay đổi icon hay cấu trúc `cache-card` nếu không có lý do đặc biệt.

---

### [J-11] AUTO PREPEND HTTPS CHO INPUT DOMAIN

Không trả về lỗi khô khan khi user nhập `google.com` thiếu `https://`.

**Frontend:** Tự động thêm `https://` nếu thiếu protocol trước khi gửi request. **Backend:** Normalize URL để luôn có scheme đầy đủ. **Validator:** Regex phải chấp nhận hostname thuần.

---

### [J-12] DATA IMMUTABILITY: KHÔNG MUTATE API RESPONSE

Không thêm các field tính toán (`computedScore`, `isLoop`, `dnsMs`...) trực tiếp vào object `res` từ API — sẽ làm sai lệch tính năng Export JSON.

**Đúng:** Tạo bản sao bằng spread operator (`{...step}`) hoặc dùng `map` để tạo array mới.

---

### [J-13] PHÒNG CHỐNG XSS KHI RENDER URL ĐỘNG

Khi render `<img src="...">` hoặc `<a href="...">` từ dữ liệu API (VD: OG image, canonical URL), dùng `escHtml` là chưa đủ.

**Phải kiểm tra protocol:** chỉ cho phép `http:` và `https:`. Chặn `javascript:` protocol tránh XSS.

---

### [J-14] TRUNCATE CHUỖI AN TOÀN (RUNE-SAFE) TRONG JAVASCRIPT

`string.slice()` có thể cắt ngang ký tự đa byte (emoji, ký tự đặc biệt).

**Đúng:**

```javascript
function truncate(str, max) {
  const chars = [...str]; // Array spread = rune-safe
  return chars.length > max ? chars.slice(0, max - 3).join("") + "..." : str;
}
```

---

### [J-15] PHÂN ĐỊNH LỖI INPUT (400) VÀ LỖI NGHIỆP VỤ (200/FALSE) TRÊN FRONTEND

- Block `catch`: xử lý lỗi HTTP 400/500 → render `message-card--error`
- Nếu response trả về `success: false` nhưng kèm dữ liệu phụ (VD: `traceLogs`) → vẫn phải render dữ liệu đó, không chỉ hiện bảng lỗi trống.

---

### [J-16] DÙNG API_BASE_URL KHI GỌI FETCH

Tuyệt đối không hardcode endpoint dạng `fetch('/api/...')` trong các file JS. Khi user chạy giao diện qua Live Server (port 5500), nó sẽ trỏ sai host.
**Bắt buộc:** Import `API_BASE_URL` từ `../../utils/network.js` và dùng dạng `fetch(\`${API_BASE_URL}/api/...\`)`.

---

### [J-17] SỬ DỤNG ABORTCONTROLLER CHO NÚT THỰC THI

Để tránh "stale response" (phản hồi chậm từ request cũ đè lên giao diện của request mới) khi user bấm liên tục hoặc chuyển URL, mọi form tra cứu phải được cài đặt `AbortController`.
**Luôn hủy `currentAbortController.abort()` trước khi gán mới và gọi `fetch()`.** Bỏ qua lỗi `err.name === 'AbortError'` trong block catch.

---

## BACKEND – GO ARCHITECTURE

### [B-01] KIẾN TRÚC MODULE BACKEND BẮT BUỘC

Cấu trúc thư mục cho mọi tool backend phải tuân thủ:

```
server/internal/modules/[tên-tool]/
├── handlers/
│   └── handlers.go
├── models/
│   └── models.go
├── service/
│   └── service.go   ← chứa logic xử lý chính
└── router.go        ← mount endpoints
```

Không đặt tên file linh tinh như `timing_service.go`, `timing.go`. Tên file cố định là `service.go`, `models.go`, `handlers.go` — để package phân biệt.

---

### [B-02] DÙNG SHARED COMPONENTS BẮT BUỘC

| Shared component  | Cách dùng đúng                                                                                                         |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Response          | Luôn dùng `response.Success()`, `response.SuccessWithMessage()`, `response.Error()` — **không** dùng `c.JSON` thủ công |
| Error translation | Truyền lỗi qua `errutil.TranslateError(err)` trước khi trả về client — không bao giờ trả `err.Error()` gốc             |
| Cache             | Dùng Generic Cache `cache.New[K, V]` — không dùng legacy cache cũ                                                      |
| Validation        | Dùng `internal/platform/validator` cho mọi input người dùng                                                            |

---

### [B-03] PHÂN ĐỊNH MÃ LỖI HTTP

Không lạm dụng 200 OK hay 400 cho mọi tình huống.

| Mã                          | Khi nào dùng                                                                                  |
| --------------------------- | --------------------------------------------------------------------------------------------- |
| `400 Bad Request`           | Input sai định dạng, IP/hostname không hợp lệ, bị chặn SSRF                                   |
| `200 OK` + `success: false` | Hệ thống OK nhưng không tìm thấy dữ liệu (VD: không có bản ghi PTR). Cho phép kèm `traceLogs` |
| `422 Unprocessable Entity`  | Lỗi logic nghiệp vụ                                                                           |
| `429 Too Many Requests`     | Vượt rate limit                                                                               |
| `502 Bad Gateway`           | Upstream error, không kết nối được trang đích                                                 |
| `504 Gateway Timeout`       | Context timeout trong quá trình xử lý                                                         |

---

### [B-04] ĐẶC THÙ GENERIC CACHE (STRUCT BỌC)

`cache.New[K, V]` trả về `(V, bool)`, không có `FetchedAt`. Nếu tool cần hiển thị thời điểm lấy dữ liệu (Cache Notice), dùng struct bọc:

```go
type cachedResult struct {
    Data      *models.YourData
    FetchedAt time.Time
}
// Khởi tạo: cache.New[string, cachedResult](size, ttl)
// Khi Set: luôn truyền time.Now() vào FetchedAt
```

---

### [B-05] CACHE KEY PHẢI CHỨA TẤT CẢ THAM SỐ ẢNH HƯỞNG ĐẾN KẾT QUẢ

Không dùng cache key chỉ có URL. Nếu tool có tùy chọn ảnh hưởng đến kết quả (VD: `IgnoreTlsErrors`, `Scope`), phải gộp vào key:

```go
rawKey := fmt.Sprintf("%s|tls=%v|scope=%s", rawURL, req.IgnoreTLSErrors, req.Scope)
// Sau đó hash SHA256 rawKey trước khi lưu
```

---

### [B-06] SINGLETON HTTP CLIENT QUA `func init()`

Không dùng `sync.Once` trong getter function. Khởi tạo HTTP Client dùng chung một lần duy nhất trong `func init()` khi server startup — an toàn về concurrency, tối ưu connection pooling.

---

### [B-07] SINGLETON CLIENT VỚI REDIRECT CHAIN

Tool capture chuỗi redirect không được để client tự follow. Cấu hình:

```go
CheckRedirect: func(req *http.Request, via []*http.Request) error {
    return http.ErrUseLastResponse
}
```

Trong Service, dùng vòng lặp để tự quản lý từng hop và ghi lại chain.

---

### [B-08] DOUBLE-SELECT PATTERN: ƯU TIÊN KẾT QUẢ THỰC

Go `select` chọn case ngẫu nhiên — nếu goroutine xong đúng lúc timeout, handler có thể trả 504 dù data đã có.

**Dùng Double-select:**

1. `select` với `default` để check channel data/error ngay lập tức
2. Nếu chưa có, mới vào `select` chính block với `ctx.Done()`

---

### [B-09] QUẢN LÝ TIMEOUT VÀ CONTEXT

- **Handler:** tạo context có deadline: `context.WithTimeout(c.Request.Context(), 20*time.Second)`
- **Service:** các vòng lặp CPU-intensive (VD: walk DOM) phải kiểm tra `ctx.Done()` định kỳ để dừng khi request bị hủy hoặc timeout

---

### [B-10] SENTINEL ERRORS – KHÔNG SO SÁNH CHUỖI LỖI

`strings.Contains(err.Error(), "something")` dễ vỡ khi thư viện update, không an toàn với Unicode.

**Đúng:**

```go
// Service: định nghĩa sentinel error
var ErrSomething = errors.New("something_error")

// Handler: kiểm tra type-safe
errors.Is(err, service.ErrSomething)     // cho sentinel errors
errors.As(err, &target)                   // cho system errors (network, DNS)
```

---

### [B-11] THỨ TỰ CHECK `errors.As`: SPECIFIC TRƯỚC, GENERAL SAU

Nhiều struct lỗi (VD: `net.DNSError`) thực thi interface chung (VD: `net.Error`). Check interface trước sẽ "nuốt" mất struct cụ thể → dead code.

→ Luôn check struct cụ thể trước, interface chung sau.

---

### [B-12] KHỞI TẠO HELPER IMMUTABLE Ở CẤP PACKAGE

Không khởi tạo `strings.Replacer` hay `regexp.Regexp` bên trong hàm được gọi nhiều lần — gây allocation lãng phí, tăng áp lực GC.

→ Khai báo là biến cấp package (`var`). Các object này thread-safe, dùng chung giữa goroutine được.

---

### [B-13] KHÔNG OVER-COUPLING CONTEXT VÀO HELPER THUẦN

Không truyền cả `context.Context` vào hàm helper chỉ cần `ctx.Err()`.

**Đúng:** `func resolveStatus(err error, ctxErr error) int` — dễ test hơn, không phụ thuộc vào vòng đời context.

---

### [B-14] TUÂN THỦ NGHIỆP VỤ NGÀNH

Khi code tool chuyên ngành (DNS, WHOIS, SSL...), phải tra cứu chuẩn của ICANN, VNNIC, IETF trước khi implement. VD: vòng đời tên miền phải có đủ giai đoạn Redemption Period. Logic sai lệch so với thực tế làm mất uy tín hệ thống.

---

### [B-15] CHUẨN HÓA URL TRƯỚC KHI VALIDATE Ở BACKEND

Frontend validation thường tự động thêm protocol (`https://`) vào trước domain trần để hỗ trợ UX. Handler backend cũng phải **dùng chung logic normalize này** (prepend `https://` nếu thiếu) trước khi parse `url.ParseRequestURI()`, để tránh tình trạng frontend báo hợp lệ nhưng backend lại reject.

---

## BACKEND – SECURITY & PERFORMANCE

### [S-01] SSRF PROTECTION: BẮT BUỘC VỚI MỌI TOOL NHẬN DOMAIN/IP

Mọi tool nhận input là domain hoặc IP đều có nguy cơ bị dùng để scan mạng nội bộ.

**Cú pháp chuẩn trong handler:**

```go
u, err := url.Parse(inputURL)
if err != nil || !validator.IsSafeHostname(u.Hostname()) {
    response.Error(c, http.StatusBadRequest, "URL không an toàn hoặc trỏ vào địa chỉ nội bộ")
    return
}
```

Không dùng hàm không tồn tại như `validator.IsSafeURL`. Phải parse URL trước, sau đó check hostname.

---

### [S-09] SSRF GUARD CHO HEADLESS BROWSER (CHROMEDP)

Khi dùng `chromedp`, browser sẽ tự động follow redirect và load hàng loạt subresources (image, iframe, css...). Không đủ an toàn nếu chỉ check URL đầu vào ở Handler.
**Bắt buộc:** Phải chặn SSRF ở tầng Browser Network bằng cách bật `fetch.Enable()` và intercept sự kiện `fetch.EventRequestPaused`. Sau đó kiểm tra `validator.IsSafeHostname(u.Hostname())` trước khi gọi `fetch.ContinueRequest()`.

---

### [S-02] SSRF PROTECTION Ở TẦNG HTTP CLIENT

Singleton HTTP Client phải dùng `DialContext` tùy chỉnh để kiểm tra IP qua `validator.IsSafeIP` trước khi kết nối. Không được phép kết nối tới IP nội bộ (192.168.x.x, 10.x.x.x, 127.0.0.1...).

---

### [S-03] COOKIE ISOLATION

Mỗi request phải khởi tạo một `http.CookieJar` riêng bên trong hàm Service. Không dùng chung Jar cho singleton client — tránh rò rỉ session giữa các user.

---

### [S-04] SECURE CACHE KEY (SHA256 HASH)

Nếu cache key chứa thông tin từ Header người dùng (User-Agent) hoặc tham số tùy chọn, bắt buộc hash SHA256 trước khi lưu — chống Cache Poisoning/Injection.

---

### [S-05] GIỚI HẠN DUNG LƯỢNG RESPONSE BODY

Đọc data từ website ngoài mà không giới hạn → nguy cơ OOM.

```go
// Kiểm tra Content-Length trước khi đọc
// Dùng io.LimitReader khi đọc body
body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB
```

10MB đủ dư dả cho 99% trang HTML thuần.

---

### [S-06] BẢO MẬT IP CLIENT – SETTRUSTEDPROXIES

Gin mặc định tin tưởng `X-Forwarded-For` — attacker có thể giả mạo IP để bypass rate limit.

```go
// Trong router.go
r.SetTrustedProxies(nil) // Không tin tưởng bất kỳ proxy nào theo mặc định
// Cấu hình proxy tin cậy qua biến môi trường TRUSTED_PROXIES
```

---

### [S-07] `isSafeURL` Ở FRONTEND PHẢI ĐẦY ĐỦ

Không chỉ check protocol `http/https`. Còn phải:

- Chặn URL có thông tin định danh: `http://user:pass@domain.com`
- Chặn đường dẫn tương đối: `/`, `./` (nếu tool quét website bên ngoài)

---

### [S-08] KHÔNG DÙNG TRAILING SLASH NORMALIZATION TRONG LOOP DETECTION

`/blog` và `/blog/` là hai URL khác nhau trong HTTP. Xóa trailing slash khi check loop sẽ gây False Positive — báo lỗi "vòng lặp" oan cho redirect chuẩn hóa của server.

---

### [P-01] CONNECTION POOLING: TĂNG `MaxIdleConnsPerHost`

Với tool truy vấn nhiều lần tới cùng domain (VD: Redirect Checker), tăng `MaxIdleConnsPerHost` lên 10-20 (mặc định là 2) trong `http.Transport`.

---

### [P-02] LAZY LOGGING – LOG SAU KHI KIỂM TRA CACHE

Không thực hiện sanitization/mapping chuỗi log trước khi kiểm tra cache — lãng phí nếu cache hit.

Mọi log lỗi (`log.Error()`) phải đính kèm field `request_id` từ context để trace lỗi trong production.

---

### [P-03] BẢO MẬT LOG – TRÁNH LOG INJECTION

Không log trực tiếp data từ người dùng (URL, query string).

**Đúng:**

- Truncate độ dài (xem [P-04] bên dưới)
- Loại bỏ ký tự điều khiển `\r`, `\n` bằng `strings.Map`
- Dùng structured logging: `.Str("url", safeURL)` thay vì cộng chuỗi vào message

---

### [P-04] TRUNCATE CHUỖI AN TOÀN TRONG GO (RUNE-SAFE)

Không dùng byte slicing `s[:253]` — có thể cắt ngang ký tự đa byte (Tiếng Việt, emoji).

**Đúng:** Ép sang `[]rune`, cắt trên rune slice, rồi ép ngược về string. Sanitize `\r`, `\n` bằng `strings.Map` **trước khi** cắt.

---

## QUY TRÌNH LÀM VIỆC

### [W-01] IMPLEMENTATION PLAN TRƯỚC KHI CODE

Khi nhận yêu cầu tạo tool mới hoặc tính năng lớn, **không được tự ý code ngay**.

**Quy trình bắt buộc:**

1. Tạo file `implementation_plan.md` phân tích: giải pháp, các bước, design sẽ dùng, rủi ro
2. Trình bày plan và chờ xác nhận từ user
3. **Chỉ bắt đầu code khi user đồng ý.** Trong quá trình làm, tạo thêm `task.md` để track tiến độ.

---

### [W-02] NGÔN NGỮ: TIẾNG VIỆT XUYÊN SUỐT

Mọi giao tiếp, tài liệu (`implementation_plan.md`, `task.md`, `walkthrough.md`...) đều phải viết bằng **Tiếng Việt**. Không dùng tiếng Anh cho tiêu đề task hay nội dung kế hoạch.

---

### [W-03] ĐỒNG BỘ CLASS KHI REFACTOR

Khi đổi tên class CSS, phải dùng Search toàn project để cập nhật mọi nơi gọi tới class cũ (HTML, JS). Kiểm tra giao diện thực tế ngay sau khi đổi tên.

---

### [W-04] ENCODING UTF-8 KHI EDIT TRÊN WINDOWS

PowerShell/CMD Windows rất dễ làm sai Codepage, biến Tiếng Việt thành rác (`Ã´`, `áº`...).

**Nguyên tắc:**

- Editor và script luôn dùng `UTF-8 (No BOM)`
- Không dùng redirect `>` hay `Set-Content` trong PowerShell không có `-Encoding utf8`
- Nếu bắt buộc: dùng `[System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)` và `WriteAllText` tương ứng
- Nếu phát hiện file bị lỗi font: dùng Python script để fix hàng loạt (không sửa tay)
- Sau mỗi lần refactor tự động: mở file Go kiểm tra string Tiếng Việt còn nguyên vẹn không

---

### [W-05] KHÔNG CHẠY SCRIPT XÓA FILE TỰ ĐỘNG

Không tạo script Cleanup/Mass Deletion dựa trên pattern RegEx hay quét thẻ HTML — rủi ro xóa nhầm file độc lập (VD: trang admin không link từ homepage).

Mọi thao tác xóa file phải được user xác nhận từng file/thư mục, sau khi đã kiểm tra dependency.

---

### [W-06] THÔNG BÁO LỖI CHO USER: TIẾNG VIỆT, DỄ HIỂU

Mọi thông báo lỗi, hướng dẫn trả về cho user phải bằng Tiếng Việt. Không trả lỗi gốc tiếng Anh từ hệ thống.

- Dùng `errutil.TranslateError(err)` để dịch lỗi
- Nếu lỗi đặc thù của tool: định nghĩa thêm trong `translator.go` hoặc xử lý riêng bằng Tiếng Việt

---

### [W-07] XƯNG HÔ VÀ GIAO TIẾP

Trong mọi quá trình giao tiếp, giải thích code hoặc báo cáo tiến độ, AI Assistant bắt buộc phải xưng hô là **"em"** và gọi user là **"anh"**.
Tuyệt đối không sử dụng các cách xưng hô khác như "mày - tao" hay "tôi - bạn".

---

_Tài liệu này cần được cập nhật mỗi khi phát hiện thêm bài học mới từ quá trình phát triển._
