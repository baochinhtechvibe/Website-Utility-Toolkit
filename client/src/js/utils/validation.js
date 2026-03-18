/*
===============================================
    FORM VALIDATION UTILITIES
    Các hàm hỗ trợ validate input realtime cho form.
=================================================
*/


/**
 * Tạo validator realtime cho ô nhập URL (http:// hoặc https://).
 *
 * - Khoá nút submit khi ô trống hoặc URL không hợp lệ.
 * - Bỏ qua các prefix đang gõ dở (h, ht, http, https://, ...).
 * - Hiện/ẩn error element kèm class `is-invalid` theo trạng thái.
 *
 * @param {HTMLInputElement}  inputEl   - Ô input cần validate
 * @param {HTMLElement}       errorEl   - Element hiển thị lỗi (ẩn/hiện)
 * @param {HTMLButtonElement} submitBtn - Nút submit cần khoá/mở
 *
 * @example
 * const cleanup = createRealtimeURLValidator(
 *     document.getElementById('url'),
 *     document.getElementById('urlError'),
 *     document.getElementById('btnSubmit'),
 * );
 * // Gọi cleanup() nếu muốn remove event listeners.
 */
export function createRealtimeURLValidator(inputEl, errorEl, submitBtn) {

    const TYPING_PREFIXES = [
        'h', 'ht', 'htt', 'http', 'http:', 'http:/', 'http://',
        'https', 'https:', 'https:/', 'https://'
    ];

    function isValidURL(str) {
        if (!/^https?:\/\//i.test(str)) return false;
        try {
            const u = new URL(str);
            return (u.protocol === 'http:' || u.protocol === 'https:') && u.host.length > 0;
        } catch { return false; }
    }

    function setBtn(enabled) {
        if (submitBtn) submitBtn.disabled = !enabled;
    }

    function validate() {
        const val = inputEl.value.trim();

        // Ô trống
        if (!val) {
            inputEl.classList.remove('is-invalid');
            errorEl?.classList.add('d-none');
            setBtn(false);
            return;
        }

        // Đang gõ dở prefix → chờ thêm, không báo lỗi
        if (TYPING_PREFIXES.includes(val)) {
            inputEl.classList.remove('is-invalid');
            errorEl?.classList.add('d-none');
            setBtn(false);
            return;
        }

        if (isValidURL(val)) {
            inputEl.classList.remove('is-invalid');
            errorEl?.classList.add('d-none');
            setBtn(true);
        } else {
            inputEl.classList.add('is-invalid');
            errorEl?.classList.remove('d-none');
            setBtn(false);
        }
    }

    function onPaste() {
        setTimeout(validate, 0); // đợi browser paste xong rồi mới đọc giá trị
    }

    inputEl.addEventListener('input', validate);
    inputEl.addEventListener('paste', onPaste);

    // Khoá nút ngay lập tức (phòng trường hợp ô đang rỗng khi gắn validator)
    setBtn(isValidURL(inputEl.value.trim()));

    // Trả về hàm cleanup để remove listeners khi cần
    return function cleanup() {
        inputEl.removeEventListener('input', validate);
        inputEl.removeEventListener('paste', onPaste);
    };
}


/**
 * Tạo validator realtime cho ô nhập domain / IP address.
 *
 * Hành vi:
 * - Chấp nhận: domain hợp lệ (google.com, sub.example.org), IPv4, IPv6.
 * - Cho phép http:// / https:// ở đầu (được strip trước khi validate, tương thích
 *   với normalizeHostnameInput trong network.js).
 * - Khoá nút submit khi ô trống hoặc giá trị sau khi strip là rỗng / sai định dạng.
 * - Hiện/ẩn error element kèm class `is-invalid` theo trạng thái.
 *
 * @param {HTMLInputElement}  inputEl   - Ô input cần validate
 * @param {HTMLElement}       errorEl   - Element hiển thị lỗi (ẩn/hiện)
 * @param {HTMLButtonElement} submitBtn - Nút submit cần khoá/mở
 *
 * @example
 * const cleanup = createRealtimeDomainValidator(
 *     document.getElementById('domain'),
 *     document.getElementById('domainError'),
 *     document.getElementById('btnLookup'),
 * );
 */
export function createRealtimeDomainValidator(inputEl, errorEl, submitBtn) {

    // Regex domain đơn giản nhưng đủ dùng cho realtime UX check
    // Chấp nhận: google.com, sub.example.org, my-site.co.uk, localhost
    const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^localhost$/;

    // IPv4
    const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

    // IPv6 (có dấu ":" là đủ; validation sâu hơn có thể bổ sung sau)
    const IPV6_RE = /:/;

    function stripProtocol(val) {
        return val.replace(/^https?:\/\//i, '').replace(/\/.*$/, '').trim();
    }

    function isValid(raw) {
        if (!raw) return false;
        const val = stripProtocol(raw);
        if (!val) return false;
        return DOMAIN_RE.test(val) || IPV4_RE.test(val) || IPV6_RE.test(val);
    }

    function setBtn(enabled) {
        if (submitBtn) submitBtn.disabled = !enabled;
    }

    function validate() {
        const raw = inputEl.value.trim();

        if (!raw) {
            inputEl.classList.remove('is-invalid');
            errorEl?.classList.add('d-none');
            setBtn(false);
            return;
        }

        if (isValid(raw)) {
            inputEl.classList.remove('is-invalid');
            errorEl?.classList.add('d-none');
            setBtn(true);
        } else {
            inputEl.classList.add('is-invalid');
            errorEl?.classList.remove('d-none');
            setBtn(false);
        }
    }

    function onPaste() {
        setTimeout(validate, 0);
    }

    inputEl.addEventListener('input', validate);
    inputEl.addEventListener('paste', onPaste);

    // Áp dụng ngay trạng thái ban đầu
    validate();

    return function cleanup() {
        inputEl.removeEventListener('input', validate);
        inputEl.removeEventListener('paste', onPaste);
    };
}
