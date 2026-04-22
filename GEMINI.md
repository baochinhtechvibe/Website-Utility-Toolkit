# MỘT SỐ NGUYÊN TẮC VÀ LƯU Ý KHI CODE (Rút kinh nghiệm từ các file/tools trước)

## Rút kinh nghiệm từ quá trình Refactor:
Để tránh việc làm hỏng bộ UI/UX hiện tại và vi phạm cấu trúc Design System, cần TUYỆT ĐỐI GHI NHỚ những bài học sau:

### 1. TUYỆT ĐỐI KHÔNG DÙNG THÓI QUEN TAILWIND CSS BỪA BÃI
- **Lỗi đã mắc:** Tự ý gõ các class kiểu `text-xl`, `bg-gray-50`, `text-red-500`, `.hidden`, `break-all`... theo thói quen mặc dù project KHÔNG cài đặt framework Tailwind đầy đủ.
- **Cách khắc phục đúng:**
  - Về layout/display: Dùng các helper đã có (như `.d-none` thay cho `.hidden`, `.d-block`, `.d-flex`, `.justify-between`, v.v. trong `utilities/helper.css`).
  - Về typography: Kiểm tra trong `tokens/typography/semantic.css` (VD: dùng text-base, text-secondary).
  - Về background/spacing: Sử dụng các class tiện ích trong `utilities/colors.css` và `utilities/spacing.css` (VD: `.py-10`, `.mb-4`). Tuyệt đối không tự chế class kiểu Tailwind nếu project chưa có.

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
  - If tool mới cần file CSS custom riêng chứa các logic layout phức tạp, hãy tạo file đó (VD: `src/css/tools/ten-tool.css`), và sau đó mở file `src/css/main.css` để **gắn câu lệnh `@import`** vào trong đó (VD: `@import url('./tools/ten-tool.css');`). Bằng cách này, mọi style sẽ được gộp chung vào 1 entry point duy nhất.

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
  - Trong HTML, chèn thêm khối `cache-card` bên trong `result-card` (tham khảo cấu trúc của `dns.html`).
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
  - Sử dụng chung các CSS Helper/Utility đã cài đặt sẵn trong thư mục `client/src/css/utilities/` (như `helper.css`, `spacing.css`, `colors.css`). Đây là các class "chuẩn" được phép dùng trực tiếp trong HTML để xử lý layout nhanh (d-flex, justify-center, py-*, v.v.).
  - Mã HTML phải sạch sẽ, phối hợp giữa BEM cho component và Utility cho layout.

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
  - **Kết quả trả về (`result-card.css`):** Bất cứ tool nào cũng cần render kết quả trong `.result-card`. Tiêu đề nằm trong `.result-card__title`. Banner báo lấy từ cache bắt buộc nằm trong class `.cache-card` (Tham khảo `components/cache-card.css`) > nút `.cache-card__btn`.
    - **Lưu ý cấu trúc:** Cụm `.result-card` phải được đặt bên trong `.card__body` của main card. Phần `.card__header` của main card phải có cấu trúc tương tự tool DNS (Tiêu đề căn giữa, có icon và text rõ ràng).
  - **Thẻ chia sẻ URL (`share-card.css`):** Khối chia sẻ gắn class `.share-card`. Trong đó có input text readonly `.share-card__input` và nút copy `.share-card__button.share-card__button--copy`.
  - **Nhãn dán (`badge.css`):** Để ghi chú tĩnh, dùng `.badge.badge-default` (hoặc `.badge-success`, `.badge-warning`). Biến chữ in hoa `.uppercase`. Không dùng `font-size` để chỉnh.

### 25. CÚ PHÁP BORDER BẮT BUỘC PHẢI ĐẦY ĐỦ (SHORTHAND)
- **Lỗi đã mắc:** Viết kiểu `border: var(--color-border);` hoặc `border: var(--color-border-subtle);`. Trình duyệt sẽ không render border vì thiếu độ dày (width) và kiểu dáng (style).
- **Cách khắc phục đúng:** LUÔN LUÔN viết đầy đủ 3 thành phần: `border: 1px solid var(--color-border);`. Nếu muốn dùng độ dày từ token thì: `border: var(--border-width-1) solid var(--color-border);`.

### 26. TRÁNH XUNG ĐỘT EVENT LISTENER KHI DÙNG VALIDATOR CHUNG
- **Lỗi đã mắc:** Gắn thêm listener `input` vào ô URL để `hideError()` nhưng lại vô tình ẩn luôn cả thông báo lỗi của `createRealtimeURLValidator` mỗi khi người dùng gõ phím.
- **Cách khắc phục đúng:** Khi dùng các hàm Validator trong `utils/validation.js`, hãy để chúng tự quản lý việc hiện/ẩn lỗi validate. Logic riêng của tool chỉ nên can thiệp vào việc ẩn các Card kết quả cũ hoặc Card lỗi logic (lookup error), tránh đè lên element báo lỗi của Validator (`#urlValidationError`, v.v.).

### 27. VẼ ĐƯỜNG NỐI (CONNECTOR LINE) TRONG UI DẠNG CHUỖI (CHAIN/TIMELINE)
- **Lưu ý quan trọng:** Để các "nút" (nodes) trong chuỗi chuyển hướng hoặc timeline trông liền mạch, sợi dây nối không được phép bị đứt đoạn khi nội dung bước đó dài ra.
- **Cách làm chuẩn:** 
  - Sử dụng pseudo-element `::after` trên container của mỗi bước (`.step`).
  - Thiết lập `height: 100%` (hoặc `calc(100% + gap)`) để sợi dây phủ hết chiều cao của bước đó, tự động chạm tới điểm bắt đầu của bước tiếp theo.
  - Dùng `z-index` để đảm bảo hình tròn của node nằm đè lên trên sợi dây.
  - Căn chỉnh `left` chính xác theo tâm của node (Ví dụ: `calc(var(--node-size) / 2 - var(--line-width) / 2)`).

### 28. NGÔN NGỮ GIAO TIẾP VÀ TÀI LIỆU
- **Quy tắc bắt buộc:** Mọi giao tiếp giữa tao và mày, cũng như các tài liệu phụ trợ như `implementation_plan.md`, `task.md`, `walkthrough.md`... đều phải được viết bằng **Tiếng Việt**.
- **Cách khắc phục đúng:** Không được dùng Tiếng Anh cho các tiêu đề task hay nội dung kế hoạch triển khai. Hãy dùng tiếng Việt rõ ràng, dễ hiểu và đúng tinh thần "Mày - Tao" thân mật.

### 29. TUYỆT ĐỐI ĐỒNG BỘ CLASS KHI REFACTOR
- **Lưu ý quan trọng:** Việc đổi tên class cho "sang" hơn trong CSS mà quên cập nhật HTML/JS là lỗi sơ đẳng gây lãng phí Token và thời gian.
- **Cách khắc phục đúng:** Khi rewrite một khối CSS, phải dùng chức năng Search toàn project để đảm bảo mọi nơi gọi tới class cũ đều đã được cập nhật sang class mới. Luôn kiểm tra lại giao diện thực tế ngay sau khi đổi tên.

### 30. KHÔNG DÙNG CLASS LAYOUT DƯ THỪA KHI COMPONENT ĐÃ CÓ SẴN
- **Lỗi đã mắc:** Thêm các class utility như `.flex-row`, `.justify-between`, `.items-center` vào thẻ HTML của `.cache-card` trong khi file `components/cache-card.css` đã định nghĩa sẵn các thuộc tính này (sử dụng `!important`).
- **Cách khắc phục đúng:** LUÔN LUÔN đọc nội dung file CSS của component trước khi viết HTML. Nếu component đã có sẵn layout bên trong, chỉ cần dùng đúng class tên component đó là đủ. Việc nhồi nhét thêm class utility chỉ làm rối mã nguồn và gây khó khăn khi bảo trì.

### 31. TÍNH NHẤT QUÁN UI/UX GIỮA CÁC CÔNG CỤ TƯƠNG ĐỒNG
- **Lưu ý quan trọng:** Các công cụ có chung hành vi (như tra cứu/lookup) phải có trải nghiệm người dùng y hệt nhau.
- **Cách khắc phục đúng:** 
  - Nếu tool DNS dùng icon sét (`fa-bolt`) cho dữ liệu mới và icon đồng hồ (`fa-clock`) cho dữ liệu cache, thì tool WHOIS cũng phải làm y chang. 
  - Không được tự ý thay đổi bộ icon hoặc cấu trúc thông báo (`cache-card`) nếu không có lý do cực kỳ đặc biệt.

### 32. TUÂN THỦ TIÊU CHUẨN NGHIỆP VỤ (BUSINESS LOGIC) CỦA NGÀNH
- **Lỗi đã mắc:** Thiết lập vòng đời tên miền (lifecycle) theo cảm tính hoặc thiếu các giai đoạn quan trọng (ví dụ: thiếu "Giai đoạn Chuộc - Redemption Period" của tên miền quốc tế).
- **Cách khắc phục đúng:** Khi code các công cụ chuyên ngành (DNS, WHOIS, SSL...), phải tra cứu kỹ quy chuẩn của các tổ chức quốc tế (ICANN, VNNIC, IETF...). Một công cụ đẹp nhưng logic sai lệch so với thực tế sẽ làm mất uy tín của hệ thống.

### 33. TIÊU CHUẨN BACKEND PRODUCTION (SHARED COMPONENTS)
- **Lưu ý quan trọng:** Để đảm bảo tính bảo mật, hiệu suất và đồng bộ dữ liệu, mọi tool backend mới PHẢI tuân thủ bộ khung Shared Components đã được refactor.
- **Cách khắc phục đúng:**
  - **Phản hồi chuẩn:** LUÔN LUÔN dùng package `internal/response` (hàm `Success`, `SuccessWithMessage`, `Error`) để trả về dữ liệu. Tuyệt đối không dùng `c.JSON` thủ công cho các endpoint API.
  - **Dịch lỗi bảo mật:** LUÔN LUÔN truyền lỗi qua `errutil.TranslateError(err)` trước khi trả về cho user. Không bao giờ được trả lỗi `err.Error()` gốc ra client để tránh lộ lọt thông tin hệ thống (path, IP, stack trace).
  - **Bộ nhớ tạm (Cache):** Sử dụng bộ Cache Generics mới (`cache.New[K, V]`) thay vì các legacy cache cũ. Đảm bảo có logic bypass cache (`bypassCache=true`) cho các tool tra cứu.
  - **Kiểm tra dữ liệu (Validation):** Sử dụng `internal/platform/validator` cho mọi input từ người dùng. Đặc biệt lưu ý dùng `IsSafeHostname` để chống tấn công SSRF (quét mạng nội bộ).
  - **Mã lỗi HTTP:** Trả về đúng Status Code theo ngữ cảnh (400: Input sai, 429: Too many requests, 422: Lỗi logic nghiệp vụ, 500: Lỗi server). Đừng lạm dụng 200 OK cho mọi trường hợp `success: false`.

### 34. PHÒNG TRÁNH LỖI ENCODING (FONT) KHI EDIT TRÊN WINDOWS
- **Lưu ý quan trọng:** Môi trường Windows (PowerShell/CMD) rất dễ làm sai lệch Codepage, dẫn đến việc các chuỗi Tiếng Việt UTF-8 bị biến thành rác (VD: `Ã´`, `áº`, `ờ‹`). Một khi file đã bị lỗi font, việc dùng các tool Search/Replace thông thường sẽ rất khó khớp dữ liệu.
- **Cách khắc phục đúng:**
  - **Mặc định UTF-8:** Luôn đảm bảo Editor và các script xử lý file sử dụng Encoding là `UTF-8 (No BOM)`.
  - **Cẩn trọng với Scripts:** Tuyệt đối không dùng lệnh redirect `>` hoặc `Set-Content` của PowerShell để ghi file chứa Tiếng Việt nếu không khai báo rõ `-Encoding utf8`.
  - **Xử lý khi bị lỗi:** Nếu phát hiện lỗi font (xuất hiện các ký tự lạ trên UI), không nên cố sửa thủ công bằng tay vì dễ sót. Hãy dùng script Python (môi trường xử lý chuỗi cực tốt) để quét và replace hàng loạt dựa trên bảng mã map UTF-8 chuẩn.
  - **Kiểm tra sau khi Edit:** Sau khi dùng các công cụ tự động để refactor code backend, phải mở file kiểm tra tận mắt các chuỗi String trong file Go xem có còn nguyên vẹn Tiếng Việt hay không trước khi commit/chạy server.

### 35. NGÔN NGỮ PHẢN HỒI (TIẾNG VIỆT) VÀ ENCODING UTF-8
- **Lưu ý quan trọng:** Mọi thông báo lỗi, hướng dẫn hoặc kết quả trả về cho người dùng PHẢI sử dụng Tiếng Việt rõ ràng, dễ hiểu. Tránh dùng thuật ngữ kỹ thuật khô khan hoặc lỗi gốc tiếng Anh từ hệ thống.
- **Cách làm chuẩn:**
  - Sử dụng `internal/platform/errutil.TranslateError(err)` để dịch lỗi.
  - Nếu lỗi mang tính chất đặc thù của tool, hãy định nghĩa thêm trong `translator.go` hoặc xử lý riêng tại tool đó bằng Tiếng Việt.
  - **TUYỆT ĐỐI TUÂN THỦ ENCODING:** Mọi file chứa ký tự Tiếng Việt (Go, HTML, JS) phải được lưu ở định dạng **UTF-8 (No BOM)**. Khi sửa file trên Windows, phải cực kỳ cẩn thận để không làm biến thành rác mã hóa (ví dụ: `Ã´`, `áº`).

### 36. CHẶN TRUY CẬP NỘI BỘ (SSRF PROTECTION) CHO MỌI TOOL
- **Lưu ý quan trọng:** Mọi tool nhận input là Domain hoặc IP (DNS, SSL, Redirect, etc.) đều tiềm ẩn rủi ro hacker dùng để thăm dò mạng nội bộ của server.
- **Cách làm chuẩn:**
  - Tại Backend, trước khi thực hiện bất kỳ logic nào, phải gọi `validator.IsSafeHostname(req.Hostname)` (hoặc `IsSafeIP`).
  - Nếu kết quả trả về là `false`, lập tức trả về lỗi `400 Bad Request` kèm thông báo chặn truy cập nội bộ rõ ràng. Không bao giờ được "thả cửa" cho tra cứu IP Private trừ khi có lý do cực kỳ đặc biệt.

### 37. ĐỒNG BỘ VALIDATOR KHI GÁN GIÁ TRỊ BẰNG JAVASCRIPT
- **Lỗi đã mắc:** Khi chuẩn hóa giá trị (normalize) và gán lại vào `input.value = newValue`, trình duyệt không tự phát ra sự kiện `input`, khiến các validator realtime không biết giá trị đã thay đổi (vẫn hiện lỗi đỏ dù giá trị mới đã đúng).
- **Cách khắc phục đúng:** Sau mỗi dòng lệnh gán giá trị cho input bằng code, bắt buộc phải gọi: `input.dispatchEvent(new Event('input'));` để kích hoạt lại logic kiểm tra của validator.

### 38. THỐNG NHẤT CƠ CHẾ ẨN/HIỆN LỖI TRONG UI
- **Lỗi đã mắc:** Validator dùng class `.d-none` để ẩn hiện, nhưng hàm `resetUI` lại dùng `element.style.display = 'none'`. Việc này gây xung đột (style display có độ ưu tiên cao hơn class) khiến validator không thể hiện lại lỗi sau khi đã reset.
- **Cách khắc phục đúng:** Thống nhất sử dụng cơ chế của validator. Trong hàm `resetUI`, hãy ẩn bảng lỗi bằng cách gọi `errorEl.classList.add('d-none')` và xóa class `is-invalid` trên ô input.

### 39. PHÂN ĐỊNH LỖI INPUT (400) VÀ LỖI NGHIỆP VỤ (200/FALSE)
- **Quy tắc Backend:** 
  - Trả về mã **400 Bad Request** khi: Định dạng sai, IP không hợp lệ, IP bị chặn (SSRF). Đây là những lỗi do người dùng nhập sai.
  - Trả về mã **200 OK** kèm `success: false` khi: Hệ thống hoạt động tốt nhưng không tìm thấy dữ liệu (ví dụ: Không có bản ghi PTR cho IP hợp lệ). Việc trả về 200 cho phép gửi kèm các dữ liệu phụ như `traceLogs` để người dùng hiểu tại sao không có kết quả.
- **Quy tắc Frontend:** 
  - Trong block `catch`, xử lý các lỗi 400/500 thành `message-card--error`.
  - Trong logic xử lý response, nếu nhận được `success: false` nhưng có dữ liệu phụ (trace), vẫn phải render các dữ liệu đó thay vì chỉ hiện một bảng lỗi trống trơn.

### 40. BẢO MẬT LOG VÀ TRÁNH LOG INJECTION
- **Lưu ý quan trọng:** Việc log trực tiếp dữ liệu từ người dùng (URL, Query String...) mà không qua xử lý có thể tạo điều kiện cho hacker tấn công Log Injection hoặc làm giả file log.
- **Cách làm chuẩn:**
  - Luôn sanitize input trước khi log: Cắt tỉa độ dài (truncate), loại bỏ các ký tự điều khiển như xuống dòng (`\n`, `\r`).
  - Sử dụng structured logging (zerolog) với các field riêng biệt (`.Str("url", safeURL)`) thay vì cộng chuỗi vào message.

### 41. QUẢN LÝ TIMEOUT VÀ CONTEXT TRONG HANDLER
- **Lưu ý quan trọng:** Các tool có thời gian xử lý lâu (fetch trang web, parse DOM phức tạp) có thể làm treo goroutine nếu không giới hạn thời gian thực thi.
- **Cách làm chuẩn:**
  - **Tầng Handler:** Phải tạo một context có deadline (ví dụ `context.WithTimeout(c.Request.Context(), 20*time.Second)`) cho mọi flow scan.
  - **Tầng Service:** Các vòng lặp hoặc quá trình xử lý CPU-intensive (như walk DOM) phải kiểm tra `ctx.Done()` định kỳ để dừng ngay lập tức nếu request bị hủy hoặc timeout.

### 42. PHÂN LOẠI MÃ LỖI HTTP CHI TIẾT (FAIL-SAFE)
- **Lưu ý quan trọng:** Việc chỉ trả về 400 cho mọi lỗi khiến frontend khó xử lý logic thông minh và người dùng khó hiểu vấn đề.
- **Cách làm chuẩn:** Phải phân loại lỗi cụ thể dựa trên error type:
  - `429 Too Many Requests`: Khi user vượt quá rate limit (ví dụ bấm Làm mới quá nhanh).
  - `504 Gateway Timeout`: Khi xử lý phía backend bị quá giờ (context timeout).
  - `502 Bad Gateway`: Khi trang web đích không thể kết nối hoặc trả về lỗi mạng (upstream error).
  - `400 Bad Request`: Chỉ dùng cho lỗi input, sai định dạng, hoặc bị chặn bởi SSRF.

### 43. QUY CHUẨN ĐẶT CACHE KEY (UNIQUE IDENTIFIER)
- **Lưu ý quan trọng:** Sử dụng cache key quá đơn giản (chỉ mỗi URL) sẽ dẫn đến việc trả về kết quả sai nếu người dùng yêu cầu các tùy chọn khác nhau (ví dụ: quét có bỏ qua SSL hay không).
- **Cách làm chuẩn:**
  - Cache key phải bao gồm tất cả các tham số ảnh hưởng đến kết quả đầu ra.
  - Ví dụ: `fmt.Sprintf("%s|tls=%v", rawURL, req.IgnoreTLSErrors)`.

### 44. BẢO MẬT IP CLIENT (SETTRUSTEDPROXIES)
- **Lưu ý quan trọng:** Gin mặc định tin tưởng header `X-Forwarded-For`, cho phép attacker giả mạo IP để bypass rate limit nếu không cấu hình đúng.
- **Cách làm chuẩn:**
  - Trong `router.go`, luôn phải gọi `r.SetTrustedProxies(nil)` để mặc định không tin tưởng header nào.
  - Chỉ cấu hình danh sách IP proxy tin cậy (như Nginx nội bộ) qua biến môi trường `TRUSTED_PROXIES`.

### 45. ƯU TIÊN SENTINEL ERRORS THAY VÌ SO SÁNH CHUỖI
- **Lưu ý quan trọng:** So sánh chuỗi lỗi (`strings.Contains`) rất dễ vỡ khi thư viện update và không an toàn với Unicode (Tiếng Việt).
- **Cách làm chuẩn:**
    - Định nghĩa các lỗi cố định ở tầng Service: `var ErrSomething = errors.New("something_error")`.
    - Tại Handler, sử dụng `errors.Is(err, service.ErrSomething)` để kiểm tra.
    - Đối với các lỗi hệ thống (Network, DNS), sử dụng `errors.As(err, &target)` để kiểm tra type-safe.

### 46. HẠN CHẾ OVER-COUPLING CONTEXT TRONG HELPER
- **Lưu ý quan trọng:** Không nên truyền cả `context.Context` vào các hàm helper thuần túy (tính toán, phân loại mã lỗi) nếu chỉ cần lấy `ctx.Err()`.
- **Cách làm chuẩn:**
    - Hàm helper nên nhận các tham số cụ thể cần thiết: `func resolveStatus(err error, ctxErr error) int`.
    - Điều này giúp hàm dễ test hơn và không bị phụ thuộc vào vòng đời của context.

### 47. THỨ TỰ CHECK ERRORS.AS (INTERFACE VS STRUCT)
- **Lưu ý quan trọng:** Nhiều struct lỗi (như `net.DNSError`) thực thi các interface chung (như `net.Error`). Nếu check interface trước, struct con sẽ bị "nuốt" mất, dẫn đến dead code ở các branch sau.
- **Cách làm chuẩn:**
    - Luôn check các struct lỗi cụ thể (Specialized) TRƯỚC khi check interface chung (Generalized).
    - Hoặc nếu cả hai đều trả về cùng một kết quả, hãy gộp chung vào check interface để code gọn sạch.

### 48. TỐI ƯU HÓA ALLOCATION CHO CÁC HELPER IMMUTABLE
- **Lưu ý quan trọng:** Việc khởi tạo các đối tượng immutable như `strings.Replacer` hay `regexp.Regexp` bên trong hàm được gọi thường xuyên sẽ gây lãng phí tài nguyên và tăng áp lực cho Garbage Collector (GC).
- **Cách làm chuẩn:**
    - Khởi tạo các đối tượng này một lần duy nhất dưới dạng biến cấp package (`var`).
    - Các đối tượng này của Go thường là thread-safe, nên có thể dùng chung giữa các goroutine mà không cần khóa (mutex).

- **Quy tắc cuối:** "Nếu tao (User) đã có file ở `client/src/css/components/`, tức là mọi chức năng của Component đó đã hoàn thiện. Việc của mày là MỞ XEM FILE ĐÓ, đọc danh sách class, và mang ra xài, **KHÔNG VIẾT THÊM CSS MỚI CHO GIAO DIỆN TƯƠNG TỰ!**"
