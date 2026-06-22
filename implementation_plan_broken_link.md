# Kế hoạch refactor Broken Link Scanner

## 1. Đánh giá hiện trạng

Tool hiện tại phù hợp hơn với tên **Page Link & Asset Checker**: nhập một URL, tải đúng một trang HTML, trích xuất link/asset trên trang đó, rồi kiểm tra trạng thái HTTP của từng URL.

Điểm đang làm tốt:

- Có frontend riêng, hiển thị thống kê, bộ lọc, phân trang, cache notice, xuất Excel.
- Backend đã có giới hạn tài nguyên: timeout tổng, giới hạn 500 URL, worker pool, per-host semaphore.
- Có SSRF guard ở tầng HTTP client bằng `DialContext` và `validator.IsSafeIP`.
- Có cơ chế HEAD rồi fallback GET cho các server/CDN không hỗ trợ HEAD.
- Có xử lý redirect thủ công, redirect depth, loop detection, timeout và cache từng asset.

Vấn đề cần refactor:

- Chưa phải broken link scanner đúng nghĩa vì chỉ quét một trang, không crawl các trang nội bộ trong website.
- Không lưu `source_page`, nên khi một link hỏng được phát hiện, user chưa biết link đó nằm ở trang nào trong site.
- Cảnh báo "Giới hạn số lượng liên kết" đang gom chung hai trường hợp: vượt 500 link và link ngoài phạm vi hostname.
- Backend chưa normalize URL trần (`example.com`) trước binding/validate nếu API được gọi trực tiếp.
- Chưa phân loại rõ internal link, external link, resource asset, canonical/meta/link stylesheet/script/image.
- Chưa parse link trong CSS, stylesheet ngoài, `srcset` nâng cao, `picture/source`, `meta refresh`.
- Chưa có soft 404 detection.
- Progress bar trên UI chưa phản ánh tiến độ thật vì backend trả kết quả một lần sau khi scan xong.
- Chưa có test coverage cho crawler, redirect, SSRF, scope, dedupe, cache, timeout.

## 2. Mục tiêu refactor

Đổi tool thành **Broken Link Scanner** đúng nghĩa theo hướng các tool lớn như Dr. Link Check, Screaming Frog và Ahrefs:

- Crawl nhiều trang nội bộ bắt đầu từ URL gốc.
- Kiểm tra link nội bộ, link ngoài, asset và redirect.
- Báo rõ link hỏng nằm ở trang nguồn nào.
- Có cấu hình phạm vi crawl, độ sâu, số trang tối đa, số link tối đa, tốc độ quét.
- Có báo cáo dễ sửa lỗi: source page, target URL, anchor/source tag, loại link, status, redirect chain, lỗi chi tiết.
- Giữ an toàn SSRF, timeout, giới hạn tài nguyên và rate limit.

## 3. Phạm vi tính năng

### Bản chuẩn nên có

- Input:
  - URL website.
  - Phạm vi: `same-host`, `same-domain`, `all-external-check-only`.
  - Max pages crawl, max depth, max links checked.
  - Max workers và per-host concurrency.
  - Ignore TLS errors.
  - Bypass cache.

- Crawl:
  - Hàng đợi URL nội bộ.
  - Dedupe theo canonical normalized URL nhưng không xóa trailing slash.
  - Tôn trọng depth limit.
  - Không crawl external pages, chỉ kiểm tra status external target.
  - Ghi `source_page` cho từng link tìm thấy.

- Extract:
  - HTML: `a[href]`, `link[href]`, `img[src/srcset]`, `script[src]`, `iframe[src]`, `source[src/srcset]`, `video[src/poster]`, `audio[src]`, `embed[src]`, `object[data]`, `track[src]`, `form[action]`, `meta[http-equiv=refresh]`.
  - CSS inline và CSS file cùng site: `url(...)`, `@import`.
  - Bỏ qua scheme không kiểm tra được: `mailto:`, `tel:`, `javascript:`, `data:`, `blob:`.

- Check:
  - HEAD trước, fallback GET có giới hạn body.
  - Status classes: `ok`, `redirect`, `broken`, `blocked`, `timeout`, `skipped`.
  - Redirect chain lưu đầy đủ theo thứ tự nguồn trước, đích sau.
  - Soft 404 heuristic: status 200 nhưng title/body có tín hiệu không tìm thấy.
  - Distinguish `404`, `410`, `401/403`, `429`, `5xx`, DNS error, TLS error, timeout.

- Report:
  - Tổng quan: pages crawled, total links found, unique targets checked, broken, redirects, blocked, timeout, skipped.
  - Bảng lỗi ưu tiên broken trước.
  - Mỗi dòng có: `source_page`, `target_url`, `final_url`, `link_type`, `source_tag`, `anchor_text`, `status_code`, `status_text`, `status_class`, `redirect_count`, `redirect_chain`, `response_ms`, `error`.
  - Filter theo status, link type, internal/external/resource, source page.
  - Export CSV/XLSX/JSON.

## 4. Thiết kế backend

### Cấu trúc module

Giữ đúng chuẩn `GEMINI.md`:

```text
server/internal/modules/broken-link-scanner/
├── handlers/
│   └── handlers.go
├── models/
│   └── models.go
├── service/
│   └── service.go
└── router.go
```

Nếu cần tách file nội bộ trong `service`, vẫn giữ tên có chủ đích rõ ràng:

- `crawler.go`: queue, depth, page crawl.
- `extractor.go`: HTML/CSS extraction.
- `checker.go`: HTTP status checker.
- `client.go`: safe HTTP clients.
- `cache.go`: cache key và cached verdict.
- `normalize.go`: URL normalization.
- `soft404.go`: soft 404 heuristic.

### Flow xử lý

1. Handler bind request nhẹ, normalize URL trước khi validate, kiểm tra SSRF hostname.
2. Tạo context timeout tổng.
3. Service tạo crawler state:
   - queue page URLs.
   - visited pages.
   - discovered link records.
   - checked target cache.
4. Worker crawl page:
   - GET HTML với `SafeBasePageClient`.
   - Validate content type và size limit.
   - Extract links.
   - Enqueue internal HTML pages nếu trong scope và depth còn cho phép.
5. Worker check target:
   - Dedupe target URL.
   - HEAD/GET status check.
   - Redirect chain.
   - Soft 404 nếu cần.
6. Aggregate result theo source page.
7. Trả response chuẩn qua `response.Success()`.

### An toàn và giới hạn

- SSRF ở cả:
  - URL đầu vào.
  - URL redirect.
  - URL asset/link được check.
  - CSS `url(...)` và `@import`.
- `DialContext` tiếp tục check IP sau DNS resolve.
- Không dùng shared cookie jar.
- Body limit:
  - HTML page: 10MB.
  - CSS file: 2MB.
  - GET fallback cho link check: đọc tối thiểu hoặc không đọc body nếu không cần.
- Mặc định đề xuất:
  - `max_pages`: 50.
  - `max_depth`: 2.
  - `max_links`: 1000.
  - `max_workers`: 25.
  - per-host concurrency: 5.
  - tổng timeout: 90 giây.

## 5. Thiết kế frontend

### Đổi tên và mô tả

- Nếu refactor đầy đủ: giữ tên **Broken Link Scanner**.
- Mô tả mới: "Crawl website, phát hiện liên kết hỏng, asset lỗi, redirect chain và soft 404."
- Nếu chưa refactor xong thì tạm đổi label hiện tại thành **Page Link & Asset Checker** để tránh sai kỳ vọng.

### Cấu hình UI

- URL input.
- Scope:
  - Cùng hostname.
  - Cùng registrable domain.
  - Kiểm tra cả external links nhưng không crawl external.
- Depth limit.
- Max pages.
- Max links.
- Workers.
- Ignore TLS.
- Bypass cache.

### Báo cáo UI

- Summary cards:
  - Pages crawled.
  - Links found.
  - Unique checked.
  - Broken.
  - Redirect.
  - Blocked.
  - Timeout.
- Warning tách riêng:
  - Vượt giới hạn link/page.
  - Bỏ qua ngoài phạm vi.
  - Bị robots/noindex nếu sau này hỗ trợ.
- Table columns:
  - Trạng thái.
  - Trang nguồn.
  - URL đích.
  - Loại link.
  - Redirect.
  - Độ trễ.
  - Lỗi.
- Row details mở rộng:
  - Source tag.
  - Anchor text.
  - Redirect chain.

### Progress

Giai đoạn 1 có thể giữ sync response nhưng sửa text thành "Đang quét, kết quả sẽ hiển thị khi hoàn tất".

Giai đoạn 2 nên thêm job async:

- `POST /scan` tạo job.
- `GET /scan/:id` lấy snapshot progress.
- `POST /scan/:id/cancel` hủy job.
- UI poll progress thật: pages crawled, queue size, links checked.

## 6. API đề xuất

### Request

```json
{
  "url": "https://example.com/",
  "scope": "same-host",
  "maxDepth": 2,
  "maxPages": 50,
  "maxLinks": 1000,
  "maxWorkers": 25,
  "ignoreTlsErrors": false,
  "bypassCache": false,
  "detectSoft404": true
}
```

### Response data

```json
{
  "requested_url": "https://example.com/",
  "final_page_url": "https://example.com/",
  "summary": {
    "pages_crawled": 12,
    "pages_skipped": 4,
    "links_found": 420,
    "unique_targets": 210,
    "ok": 180,
    "redirect": 12,
    "broken": 10,
    "blocked": 3,
    "timeout": 5,
    "skipped_out_of_scope": 40,
    "skipped_over_limit": 0
  },
  "results": []
}
```

## 7. Các pha triển khai

### Pha 1: Sửa đúng bản chất và wording

- Đổi/cập nhật warning "Giới hạn số lượng liên kết" để tách riêng over-limit và out-of-scope.
- Thêm `source_page` vào result hiện tại.
- Backend normalize URL trần trước validate.
- Sửa mô tả tool nếu chưa crawl toàn site.
- Thêm test cho các lỗi hiện có.

### Pha 2: Crawler nhiều trang

- Thêm queue crawl nội bộ theo depth/page limit.
- Tách `PageRecord`, `LinkRecord`, `TargetVerdict`.
- Gộp nhiều source page trỏ tới cùng broken target nhưng vẫn hiển thị được từng source.
- Không crawl external, chỉ check external status.

### Pha 3: Extractor nâng cao

- Parse thêm CSS `url(...)`, `@import`.
- Parse `meta refresh`, `poster`, `srcset` tốt hơn.
- Lưu anchor text/source snippet an toàn.

### Pha 4: Report chuẩn SEO

- UI thêm filter internal/external/resource/source page.
- Row detail cho redirect chain và source tag.
- Export CSV/XLSX/JSON theo format mới.

### Pha 5: Async progress

- Chuyển scan nặng sang job manager.
- Poll progress thật.
- Cancel scan từ frontend gọi backend.
- Dọn state job hết hạn.

### Pha 6: Soft 404 và polish

- Heuristic soft 404.
- Retry nhẹ cho lỗi mạng tạm thời.
- Cải thiện thông báo tiếng Việt.
- Visual QA desktop/mobile.

## 8. Test bắt buộc

- Unit test normalize URL:
  - domain trần.
  - trailing slash không bị xóa sai.
  - query/fragment.
  - IDN/punycode nếu hỗ trợ.
- Unit test extractor:
  - HTML tags.
  - srcset.
  - CSS url.
  - invalid schemes.
- Unit test crawler:
  - depth limit.
  - max pages.
  - same-host scope.
  - dedupe.
- Unit test checker:
  - 2xx, 3xx, 4xx, 5xx.
  - redirect loop.
  - missing Location.
  - timeout.
  - HEAD fallback GET.
- Security test:
  - private IP.
  - redirect tới private IP.
  - DNS resolve private IP.
  - credentials in URL.
- Frontend test thủ công:
  - URL trần.
  - out-of-scope warning.
  - over-limit warning.
  - filter/pagination/export.

## 9. Rủi ro

- Crawl nhiều trang dễ làm request lâu: cần giới hạn mặc định chặt và UI báo rõ.
- Một số site chặn bot/HEAD: cần fallback GET và phân loại `blocked` thay vì kết luận broken vội.
- Soft 404 có false positive: nên đánh dấu là cảnh báo, không gộp cứng vào broken ở giai đoạn đầu.
- SSRF phải kiểm tra lại ở mọi redirect và mọi URL extract được.
- Nếu thêm async job sẽ tăng độ phức tạp backend, nên để sau khi crawler sync ổn.

## 10. Tiêu chí hoàn thành

- Tool crawl được nhiều trang nội bộ trong giới hạn cấu hình.
- Mỗi broken link chỉ rõ trang nguồn chứa link đó.
- Báo cáo phân biệt internal, external và resource.
- Warning không còn gây hiểu nhầm giữa "vượt giới hạn" và "ngoài phạm vi".
- Backend có test cho crawler/checker/security.
- UI không dùng inline style tùy tiện, không dùng Tailwind tự phát, dùng đúng component/token hiện có.
- Chạy được `go test ./internal/modules/broken-link-scanner/...`.

