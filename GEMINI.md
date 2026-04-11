# MỘT SỐ NGUYÊN TẮC VÀ LƯU Ý KHI CODE (Rút kinh nghiệm từ các file/tools trước)

## Rút kinh nghiệm từ quá trình Refactor:
Để tránh việc làm hỏng bộ UI/UX hiện tại và vi phạm cấu trúc Design System, cần TUYỆT ĐỐI GHI NHỚ những bài học sau:

### 1. TUYỆT ĐỐI KHÔNG DÙNG THÓI QUEN TAILWIND CSS BỪA BÃI
- **Lỗi đã mắc:** Tự ý gõ các class kiểu `text-xl`, `bg-gray-50`, `text-red-500`, `.hidden`, `break-all`... theo thói quen mặc dù project KHÔNG cài đặt framework Tailwind đầy đủ.
- **Cách khắc phục đúng:**
  - Về layout/display: Dùng các helper đã có (như `.d-none` thay cho `.hidden`, `.d-block`, `.d-flex`, v.v.).
  - Về typography: Kiểm tra trong `tokens/typography/semantic.css` (VD: dùng text-base, text-secondary).
  - Về background: Check `utilities/colors.css` hoặc dùng trực tiếp file CSS của tool để mapping tới các biến Token hợp lệ.

### 2. SỬ DỤNG ĐÚNG VÀ ĐỦ CSS TOKENS, KHÔNG HARDCODE
- **Lỗi đã mắc:** Hardcode các thông số như `border-radius: 4px;`, `box-shadow: 0 1px 3px rgba(...)`, `transition: 0.3s ease;` ngay trong các file `.css` của tool. Ngoài ra, tự bịa ra các biến color CSS mông lung (ví dụ: `var(--color-primary-600)`) làm vỡ hệ thống token.
- **Cách khắc phục đúng:** 
  - Shadow: Bắt buộc dùng `var(--shadow-1)`, `var(--shadow-2)` (từ `shadow/primitive.css`).
  - Radius: Bắt buộc dùng `var(--radius-xs)`, `var(--radius-md)`, `var(--radius-lg)`.
  - Motion (Transition): Dùng `var(--transition-base)`, `var(--transition-slow)`.
  - Colors: Tuyệt đối chỉ map tới đúng Token có trong `color/semantic.css` (ví dụ: `--color-surface`, `--color-info`, `--color-text-muted`) hoặc `color/palette.css` (`--gray-50`, `--green-500`). Tuyệt đối không tự chế Token color mới.

### 3. SỬ DỤNG LẠI CÁC STRUCTURE/PATTERN ĐÃ CHUẨN HOÁ TRONG HTML
- **Lỗi đã mắc:** Tự nghĩ ra cấu trúc wrapper kết quả riêng, quên thêm các thành phần quan trọng theo chuẩn chung.
- **Cách khắc phục đúng:** 
  - Phần header kết quả tìm kiếm cần phải bám chặt HTML pattern `result-card__title` (có icon).
  - Phải tích hợp đủ `share-card` kèm icon và chức năng Copy URL chia sẻ ở dưới component (Tham khảo mẫu của `dns.html`).
  - Khi render kết quả lỗi, sử dụng đúng `message-card` và `message-card--error`.

### 4. MODULE JS SAU KHI TẠO PHẢI CÓ `INIT()` PATTERN
- **Lỗi đã mắc:** Chạy code, lấy element thẳng ở Global scope của file script.
- **Cách khắc phục đúng:** Đóng gói toàn bộ logic khởi tạo event listener và biến local vào trong hàm `function init() { ... }`, gọi callback này qua `document.addEventListener("DOMContentLoaded", init);`. Không pollute global scope.

### 5. SYNTAX HIGHLIGHTING TRONG KẾT QUẢ GEN CODE
- **Lỗi đã mắc:** Render code-block bằng toàn màu basic, không hề sử dụng bộ highlight đã được thiết kế sẵn.
- **Cách khắc phục đúng:** Trong các thành phần trả về sinh code, cần tận dụng triệt để semantic.css cho Code Highlighting như `code-keyword`, `code-value`, `code-string`, `code-parameter`, `code-func`, `code-comment`... cho output thêm sinh động.

### 6. CẤU TRÚC HEADER VÀ FOOTER CỦA TRANG HTML
- **Lưu ý quan trọng:** Khi tạo một trang HTML cho tool mới, bắt buộc phải copy nguyên mẫu cấu trúc của `<header>` và `<footer>` từ các tool có sẵn (VD: `security-headers.html` hay `dns.html`).
- **Cách khắc phục đúng:**
  - Không tự thiết kế lại Header và Footer để đảm bảo tính đồng bộ (consistency) với các layout chung của hệ thống.
  - Footer chứa các tracking id như `#visit-total` và `#visit-today`, nếu tự vẽ lại sai class/id sẽ dẫn đến lỗi hiển thị visit counter. Chẳng hạn đối với link tới file config, scripts, luôn đảm bảo đường dẫn tương đối trỏ về `../../src/js/main.js` một cách chuẩn xác để plugin tracker hoạt động nha.

### 7. IMPORT FILE STYLE (CSS) CHO TOOL MỚI
- **Lưu ý quan trọng:** Cần quy định cách import CSS cho tool mới để duy trì hiệu suất và nguyên tắc "1 file CSS duy nhất".
- **Cách khắc phục đúng:**
  - Trong trang HTML của tool mới, CHỈ ĐƯỢC PHÉP có duy nhất một thẻ import CSS ở `<head>`: `<link rel="stylesheet" href="../../src/css/main.css">`. Tuyệt đối không dùng nhiều thẻ `<link>` lẻ tẻ.
  - Nếu tool mới cần file CSS custom riêng chứa các logic layout phức tạp, hãy tạo file đó (VD: `src/css/tools/ten-tool.css`), và sau đó mở file `src/css/main.css` để **gắn câu lệnh `@import`** vào trong đó (VD: `@import url('./tools/ten-tool.css');`). Bằng cách này, mọi style sẽ được gộp chung vào 1 entry point duy nhất.

### 8. CẬP NHẬT TRANG CHỦ KHI TẠO TOOL MỚI
- **Lưu ý quan trọng:** Khi hoàn thành một tool mới, phải bổ sung đường dẫn và thông tin tool đó ra ngoài trang chủ (`index.html`) để user có thể truy cập được.
- **Cách khắc phục đúng:**
  - Trong file `client/views/index.html`, copy một mẫu component `tool-card` có sẵn (với đầy đủ icon, badge, title, description, footer truy cập) và sửa lại thông tin, link cho công cụ mới.
  - Phải đặt một class riêng để định dạng màu icon cho tool đó (ví dụ: `.tool-card--[tên-tool]`).
  - Mở file `client/src/css/components/tool-card.css` và thêm CSS variable cho màu icon tương ứng với class vừa đặt (Ví dụ: `.tool-card--security-header { --tool-card-icon: var(--blue-500); }`).
  - **TUYỆT ĐỐI CHÚ Ý:** Token màu phải được lấy CHÍNH XÁC từ mảng biến có thật bên trong file `client/src/css/tokens/color/palette.css`. Không bao giờ được bịa ra những class như `var(--brand-red)` hay `var(--teal-500)` nếu nó không tồn tại!

### 9. QUY TRÌNH IMPLEMENTATION PLAN & TASK LIST
- **Quy tắc bất di bất dịch:** Khi được yêu cầu tạo tool mới hoặc tính năng lớn, **KHÔNG ĐƯỢC TỰ Ý CODE NGAY**.
- **Cách làm việc chuẩn:**
  1. Mày phải tạo file `implementation_plan.md` phân tích kỹ lưỡng giải pháp, các bước thực hiện, design sẽ dùng, rủi ro, etc.
  2. Dừng lại và hỏi xem tao có đồng ý với plan đó không.
  3. **CHỈ KHI NÀO** tao comment "OK, code đi mày" (hoặc câu trả lời đồng ý tương tự) thì mới được bắt tay vào tạo file và viết code thực sự. Quá trình làm thì tạo thêm file `task.md` để tick tiến trình cho tao dễ theo dõi.

### 10. TUÂN THỦ KIẾN TRÚC BACKEND (GOLANG MODULE)
- **Lưu ý quan trọng:** Cấu trúc model, service, và handler của backend không được tự ý sáng tạo hay thay đổi tên.
- **Cách khắc phục đúng:**
  - Back-end của một tool **bắt buộc** phải đặt trong `server/internal/modules/[tên-tool]`.
  - Bên trong đó bắt buộc chia thành 3 thư mục: `handlers/` (chứa `handlers.go`), `models/` (chứa `models.go`), và `service/` (chứa các logic xử lý chính).
  - Tên struct request, response hay tên hàm nên dựa theo template chung. Không đặt tên linh tinh như `timing_service.go`, `timing.go`,... cứ dùng đúng `service.go`, `models.go`, `handlers.go` và để package phân biệt.
  - Phải có file `router.go` ở ngoài cùng thư mục tool để mount endpoints.

### 11. XỬ LÝ CACHE NOTICE TRONG UI KẾT QUẢ
- **Lưu ý quan trọng:** Với các tool mang tính chất "tra cứu" (lookup), tao yêu cầu LUÔN LUÔN có phần thông báo kết quả cache notice, bất kể kết quả đó là lấy dữ liệu mới (fresh) hay lấy từ cache ra.
- **Cách khắc phục đúng:** 
  - Trong HTML, chèn thêm khối `result-card__cache-notice` bên trong `result-card` (tham khảo cấu trúc của `dns.html`).
  - Trong JS, xử lý logic LUÔN hiển thị banner nếu có `meta.fetched_at`. Nếu `meta.cached = true` thì hiển thị: *"Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc..."*. Nếu `meta.cached = false` thì hiển thị: *"Kết quả tra cứu mới nhất lúc..."* (tham khảo logic trong `dns.js` hoặc `web-latency.js`).
  - Gắn sự kiện cho nút "Làm mới" gửi request kèm `bypassCache=true` lên backend để ép tải lại dữ liệu mới nhất. Trừ những tool đặc biệt không làm việc bằng cache (như chmod) thì mới bỏ qua bước này.

### 12. BẮT BUỘC ĐỌC KỸ TOKENS VÀ CLASS TRƯỚC KHI SỬ DỤNG
- **Lưu ý quan trọng:** Không được phép tự vẽ ra biến CSS hoặc class mới dựa trên trí nhớ hoặc suy đoán (ví dụ: `--spacing-X`, `--color-surface-hover`, `--teal-500`).
- **Cách khắc phục đúng:** LUÔN LUÔN mở và đọc các file định nghĩa CSS của project TRƯỚC KHI viết code CSS mới cho một tool:
  - Cấu trúc `client/src/css/base/`
  - Tiện ích `client/src/css/utilities/`
  - Bố cục `client/src/css/layout/`
  - Thành phần UI `client/src/css/components/` (phải check kỹ trước, tuyệt đối không tự chế lại badge, button, form, v.v. nếu đã có sẵn).
  - Các biến hệ thống `client/src/css/tokens/` (đặc biệt là `spacing.css`, `color/palette.css`, `color/semantic.css`)
- **Nguyên tắc:** Nếu tao không định nghĩa trong mấy thư mục đó, nghĩa là biến đó không tồn tại. Mày dùng bậy là vỡ giao diện ráng chịu!

### 13. TUYỆT ĐỐI KHÔNG DÙNG INLINE CSS (`style="..."`)
- **Lỗi đã mắc:** Viết chèn trực tiếp các thuộc tính CSS vào thẻ HTML (ví dụ: `style="display: grid; gap: var(--space-4);"` hoặc `style="background-color: var(--color-surface);"`).
- **Cách khắc phục đúng:** 
  - Đóng gói thuộc tính vào các class cục bộ bên trong file CSS của tool (VD: `.latency-grid`, `.latency-stat-box`).
  - Sử dụng chung các CSS Helper/Utility đã cài đặt sẵn nếu có.
  - Mã HTML phải sạch sẽ, chỉ chứa class name.

### 14. TÁI SỬ DỤNG COMPONENT CHO CÁC KHỐI KẾT QUẢ
- **Lỗi đã mắc:** Tự ý chế ra các box bọc ngoài như `.info-card p-4 rounded border` cho các khối thông tin phụ. Ngoài ra ráp nhầm cấu trúc cho `.card__header` (quên dán chữ trắng/icon) làm layout bị ẩn hoặc vỡ.
- **Cách khắc phục đúng:** LUÔN LUÔN dùng component Card (`components/card.css`) làm chuẩn cho bất kỳ một mảng khối nào trên UI thay vì tự đắp border và padding:
  - Bọc bằng cụm: `<div class="card card--flat"> ... </div>`
  - Khu vực tiêu đề bọc bằng: `<div class="card__header"><h4 class="card__title"><i class="..."></i> Tiêu đề</h4></div>`
  - Khu vực nội dung bọc bằng: `<div class="card__body"> ... </div>`

### 15. KHÔNG LỒNG COMPONENT UI VÀO TRONG CLASS CHỨA `WHITE-SPACE: PRE-WRAP`
- **Lỗi đã mắc:** Render `<div class="message-card">` vào thẳng bên trong vùng chứa có class của code output (thường có thuộc tính định dạng `white-space: pre-wrap`). Do dùng template literal chứa dấu cách/thụt đầu dòng, trình duyệt đã render cả đống dấu cách đó ra màn hình làm vỡ nát layout thẻ `message-card`.
- **Cách khắc phục đúng:** Các thẻ UI Component bắt buộc phải được đặt trong vùng không gian có `white-space: normal` mặc định. Tách bạch vùng chứa kết quả Code và vùng chứa kết quả UI (Ví dụ: tạo class container riêng `.json-tools__validator-box` thay vì tái sử dụng hộp `.json-tools__output`).

### 16. QUẢN LÝ TRẠNG THÁI BUTTON (ENABLE/DISABLE) VÀ THÔNG BÁO LỖI REAL-TIME
- **Lưu ý quan trọng:** Bất kỳ thao tác xử lý form nào cũng phải có UX tốt nhất.
- **Cách khắc phục đúng:** 
  - Phải luôn có hàm ví dụ `updateButtonStates()` quét nội dung của input. Nút hành động tương ứng (như Format, Translate, Validate...) phải chuyển qua tính năng `disabled = true` nếu ô input trống, tránh việc user nhấn "mù" tạo lỗi API.
  - Phải cài event listener `input` vào mọi ô textarea, để khi người dùng sửa dữ liệu, lập tức dọn sạch mọi UI báo lỗi trước đó (như global `errorCard` hoặc xóa class `.is-invalid`), giúp họ không bị phân tâm.

### 17. GIỮ LẠI CLASS GỐC KHI TOGGLE STATE CỦA COMPONENT
- **Lỗi đã mắc:** Xóa luôn định dạng `.btn` gốc khi người dùng bấm vào chuyển trạng thái nút `Split / Unified View`. Việc này làm mất padding, radius và format chuẩn của cốt lõi.
- **Cách khắc phục đúng:** Khi cấu hình UI bằng Javascript, chỉ thêm/bớt các class Modifier (như `.btn-action`, `.btn-outline`, `.active` v.v.). **TUYỆT ĐỐI KHÔNG BAO GIỜ** được đụng vô class cấu trúc xương sống như `.btn`, `.card`, `.message-card`.

### 18. UX BẮT LỖI GỠ RỐI DÙNG NATIVE HIGHTLIGHT THAY VÌ CSS OVERLAY (HACK)
- **Lưu ý quan trọng:** Đừng cố viết thư viện Custom HTML/CSS phức tạp chèn vào `<textarea>` chỉ nhằm mục đích Highlight bôi đỏ một dòng bị lỗi nào đó. Rất nặng nề, dễ bug khi scroll/zoom window.
- **Cách làm chuẩn:** Tận dụng tối đa API native xịn xò của trình duyệt với cú pháp cực đơn giản: `textarea.focus()` kết hợp `textarea.setSelectionRange(pos, pos+1)`. Phương thức này tốn 0 dòng CSS, lại tự động cuộn (scroll) màn hình trỏ chuột đến chuẩn xác dòng chữ chứa lỗi ở ngay cả file khổng lồ! Đồng thời, luôn Translate các thông báo lỗi thuần túy của native compiler (JS V8 - "English") ra tiếng Việt rõ ràng cho người dùng phổ thông cực kỳ dễ hiểu.

### 19. TUYỆT ĐỐI KHÔNG TỰ CHẾ BIẾN FONT FAMILY (TYPOGRAPHY TOKENS)
- **Lỗi đã mắc:** Tự ý sử dụng các biến CSS font-family theo thói quen hoặc suy đoán như `--font-family-primary`, `--font-family-base`, `--font-family-display`... trong khi chúng KHÔNG tồn tại trong hệ thống.
- **Cách khắc phục đúng:** 
  - Chỉ được phép sử dụng các token đã định nghĩa trong `client/src/css/tokens/typography/primitive.css`.
  - Hiện tại hệ thống chỉ có 3 bộ font chính:
    - `var(--font-family-sans)`: Dùng cho text thông thường, UI (Inter).
    - `var(--font-family-serif)`: Dùng cho tiêu đề mang tính chất nghệ thuật (Philosopher).
    - `var(--font-family-mono)`: Dùng cho code-block, dữ liệu thô (Monospace).
  - Mọi biến font khác đều là "biến ma", tuyệt đối không được tự tiện sử dụng.

### 20. CHỈ SỬ DỤNG FONT AWESOME FREE ICONS
- **Lỗi đã mắc:** Sử dụng các class icon độc quyền của bản Pro (ví dụ: `fa-shield-check`) khiến icon bị "tàng hình" trên giao diện. Điều này không những mất thẩm mỹ mà còn gây lỗi hiển thị khoảng trắng thừa (gap) làm méo/lệch layout của Component.
- **Cách khắc phục đúng:** 
  - Project này chỉ tích hợp **FontAwesome Free**. Mọi icon sử dụng phải có mặt trong bộ Free (Ví dụ: `fa-circle-check`, `fa-shield-halved`, `fa-triangle-exclamation`, `fa-circle-xmark`...).
  - Tuyệt đối không nhét bừa tên icon dựa trên trí nhớ hoặc phiên bản cũ/Pro. Nếu cần icon Check, xài `fa-check`, `fa-check-circle` hoặc `fa-circle-check`.

### 21. CẨN TRỌNG VỚI ENCODING KHI DÙNG SCRIPT XỬ LÝ FILE BÀNG TERMINAL
- **Lỗi đã mắc:** Khi viết bash/PowerShell script để duyệt và format file hàng loạt, việc tự ý dùng lệnh như `Get-Content` rồi pipe sang `Set-Content -Encoding UTF8` mà không khai báo rõ Encoding đầu vào đã gây ra hiệu ứng sai lệch Codepage. Do PowerShell mặc định decode bằng ANSI (Windows-1258 với môi trường Việt Nam), toàn bộ string Tiếng Việt dạng UTF-8 đã bị đọc sai và lưu lại thành rác mã hóa (ví dụ: màn hình xuất hiện các ký tự `Ã`, `Ä`, `PhÃ¢n tÃ­ch`).
- **Cách khắc phục đúng:** 
  - Hạn chế tối đa việc sử dụng script PowerShell/bash để Read/Write nội dung hàng loạt nếu không nắm vững về Codepage của OS mục tiêu. Thay vào đó, hãy dùng chức năng của môi trường runtime an toàn như Node.js (luôn mặc định Buffer UTF-8) hoặc các công cụ native của Code Editor / Tool Build có sẵn.
  - Nếu bắt buộc dùng PowerShell để sửa nội dung file, phải khai báo tuyệt đối tường minh cả lúc đọc lẫn lúc ghi: `[System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)` và `[System.IO.File]::WriteAllText($path, $text, $utf8NoBom)`.

### 22. TUYỆT ĐỐI KHÔNG DÙNG SCRIPT QUÉT VÀ XÓA FILE TỰ ĐỘNG
- **Lỗi đã mắc:** Chạy script PowerShell tự động dò tìm các file "không được import ở đâu" rồi xóa hàng loạt khiến một số công cụ độc lập (ví dụ: `imaptool-admin.html` là trang quản trị không link ngoài trang chủ) bị xóa oan uổng và phải làm lại từ đầu.
- **Cách khắc phục đúng:** 
  - KHÔNG BAO GIỜ tự tiện tạo ra các script Cleanup/Mass Deletion để xóa file source code dựa trên các pattern tìm kiếm RegEx hay quét thẻ HTML, vì độ rủi ro sai sót cực lớn.
  - Mọi thao tác xóa file dư thừa phải được xác nhận tường minh bởi tao (User) cho từng file hoặc từng thư mục vụn vặt và phải kiểm tra chéo độ phụ thuộc. Đừng thấy "có vẻ không dùng" là tiện tay xóa luôn!

### 23. TỔNG HỢP CÁC COMPONENT & CLASS ĐÃ REFACTOR KỸ (BẢNG TRA CỨU BẮT BUỘC DÙNG)
- **Tuyệt đối tuân thủ Design System thay vì viết CSS mới.** Dưới đây là danh sách các Component CỐT LÕI đã được chuẩn hóa, CHỈ ĐƯỢC PHÉP DÙNG LẠI, không tự chế thêm:
  - **Khung giao diện (Layout & Card):** Tất cả các khối phải bọc trong `.card`. Cấu trúc chuẩn là `.card` > `.card__header` (chứa `h2.card__title` có kèm icon cách ra một khoảng bằng class `.mr-2`) > `.card__body`. (Không tự pad hay border tùy tiện).
  - **Form nhập liệu (`form.css`):** Form luôn dùng `.form`. Từng dòng bọc bởi `.form-field` hoặc `.form-inline` (nếu nằm ngang). Label dùng `.form-label`, Textbox dùng `.form-input` và Checkbox dùng `.form-checkbox`.
  - **Nút bấm (`button.css`):** Mọi nút đều có gốc là `.btn`. Biến thể gồm: `.btn-action` (màu chính), `.btn-outline` (viền mỏng), `.btn-danger`, `.btn-warning`, `.btn-sm`, `.btn-block` (chiếm 100% width).
  - **Thông báo (`message-card.css`):** Dùng cho lỗi hoặc cảnh báo nổi bật. Cấu trúc `.message-card.message-card--error` > `.message-card__header` > `.message-card__title`. (Tuyệt đối không nhét thẻ này vào trong một div có `white-space: pre-wrap` để tránh bị lệch layout).
  - **Hiển thị code (`code-block.css`):** Khu vực in code phải bọc ngoài `.code-block`, phần header có class `.code-block__header` > `.code-block__lang` và nút copy `button.code-block__btn-copy`. Mã code in ra cần nhét vào `.code-block__body` > `code.code-block__text`.
  - **Kết quả trả về (`result-card.css`):** Bất cứ tool nào cũng cần render kết quả trong `.result-card`. Tiêu đề nằm trong `.result-card__title`. Banner báo lấy từ cache bắt buộc nằm trong class `.result-card__cache-notice` > nút `.cache-notice__btn-refresh`.
  - **Thẻ chia sẻ URL (`share-card.css`):** Khối chia sẻ gắn class `.share-card`. Trong đó có input text readonly `.share-card__input` và nút copy `.share-card__button.share-card__button--copy`.
  - **Nhãn dán (`badge.css`):** Để ghi chú tĩnh, dùng `.badge.badge-default` (hoặc `.badge-success`, `.badge-warning`). Biến chữ in hoa `.uppercase`. Không dùng `font-size` để chỉnh.

### 24. CẨN THẬN KHI XÓA COMMENT TRONG CSS LÀM MẤT NGOẶC NHỌN CỦA BLOCK
- **Lỗi đã mắc:** Khi sửa CSS để gỡ bỏ một thuộc tính (như `overflow: hidden;`), đã comment out cả dấu đóng ngoặc nhọn `}` hoặc vô tình xóa mất dấu `}` của selector đó. Hậu quả là trình duyệt hiểu sai toàn bộ phần CSS bên dưới, làm vỡ khung giao diện, mất màu nền, ẩn hiện loạn xạ.
- **Cách khắc phục đúng:** 
  - Khi xóa hoặc comment bất kỳ dòng CSS nào, ĐẶC BIỆT chú ý đến các dấu ngoặc nhọn mở `{` và đóng `}`.
  - Phải chắc chắn rằng mỗi block CSS đều có đủ các cặp dấu. Việc comment một thuộc tính không bao giờ được phép "nuốt" luôn vách ngăn của class đó.

- **Quy tắc cuối:** "Nếu tao (User) đã có file ở `client/src/css/components/`, tức là mọi chức năng của Component đó đã hoàn thiện. Việc của mày là MỞ XEM FILE ĐÓ, đọc danh sách class, và mang ra xài, **KHÔNG VIẾT THÊM CSS MỚI CHO GIAO DIỆN TƯƠNG TỰ!**"
