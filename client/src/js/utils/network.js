/*
===============================================
    NETWORK UTILITIES FUNCTIONS
    Các hàm xử lý IP, Domain, DNS input
=================================================
*/


/**
 * Kiểm tra chuỗi có phải IPv4 hay không
 * Ví dụ: 8.8.8.8 → true
 *        google.com → false
 *
 * @param {string} value
 * @returns {boolean}
 */
export function isIP(value) {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(value);
}


/**
 * Kiểm tra chuỗi có phải IPv6 hay không
 * Dựa trên việc có chứa dấu ":" hay không
 *
 * Ví dụ: 2001:db8::1 → true
 *        8.8.8.8 → false
 *
 * @param {string} value
 * @returns {boolean}
 */
export function isIPv6(value) {
    return value.includes(":");
}


/**
 * Xác định kiểu dữ liệu người dùng nhập vào
 * - IPv4 → IP
 * - IPv6 → IP
 * - Còn lại → DOMAIN
 *
 * @param {string} value
 * @returns {"IP" | "DOMAIN"}
 */
export function detectInputType(value) {
    if (isIP(value)) return "IP";
    if (isIPv6(value)) return "IP";
    return "DOMAIN";
}


/**
 * Mở rộng IPv6 dạng rút gọn (::) thành dạng đầy đủ 8 block
 *
 * Ví dụ:
 * 2001:db8::1
 * → 2001:0db8:0000:0000:0000:0000:0000:0001
 *
 * @param {string} ip - IPv6 rút gọn
 * @returns {string} IPv6 đầy đủ (không có dấu :)
 */
export function expandIPv6(ip) {

    // Tách phần trước và sau dấu ::
    const parts = ip.split("::");

    let head = parts[0].split(":").filter(Boolean);
    let tail = parts[1] ? parts[1].split(":").filter(Boolean) : [];

    // Tính số block còn thiếu để đủ 8 block
    const missing = 8 - (head.length + tail.length);

    const zeros = Array(missing).fill("0000");

    // Ghép lại và pad mỗi block thành 4 ký tự
    const full = [...head, ...zeros, ...tail]
        .map(p => p.padStart(4, "0"));

    return full.join("");
}


/**
 * Tạo tên truy vấn PTR (Reverse DNS) từ IP
 *
 * IPv4:
 * 8.8.8.8 → 8.8.8.8.in-addr.arpa
 *
 * IPv6:
 * 2001:db8::1 →
 * 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
 *
 * @param {string} ip
 * @returns {string}
 */
export function getPTRQueryName(ip) {

    // IPv4
    if (isIP(ip)) {
        return ip.split(".").reverse().join(".") + ".in-addr.arpa";
    }

    // IPv6
    if (isIPv6(ip)) {

        const expanded = expandIPv6(ip);

        return expanded
            .split("")
            .reverse()
            .join(".") + ".ip6.arpa";
    }

    return ip;
}


/**
 * Chuẩn hóa loại record khi người dùng chọn "ALL"
 *
 * Nếu input là IP → chuyển sang PTR
 * Nếu là domain → giữ ALL
 *
 * @param {string} hostname
 * @param {string} type
 * @returns {string}
 */
export function normalizeRecordType(hostname, type) {

    if (type !== "ALL") return type;

    return detectInputType(hostname) === "IP"
        ? "PTR"
        : "ALL";
}

/**
 * Chuẩn hóa dữ liệu hostname người dùng nhập
 *
 * Mục đích:
 * - Chuẩn hóa input về dạng domain thuần (hostname)
 * - Hạn chế lỗi khi user nhập URL, path, protocol...
 *
 * Xử lý:
 * - Trim khoảng trắng
 * - Chuyển về chữ thường
 * - Tự thêm https:// để parse nếu thiếu protocol
 * - Dùng URL API để lấy hostname
 * - Fallback khi URL không hợp lệ
 *
 * Ví dụ:
 * https://google.com/test   → google.com
 * google.com/path          → google.com
 * WWW.Site.COM///          → www.site.com
 *
 * @param {string} input - Dữ liệu user nhập
 * @returns {string} hostname đã được chuẩn hóa
 */
export function normalizeHostnameInput(input) {

    if (!input) return "";

    input = input.trim().toLowerCase();

    try {
        // Nếu chưa có protocol → thêm tạm để parse
        if (!input.startsWith("http://") && !input.startsWith("https://")) {
            input = "https://" + input;
        }

        const url = new URL(input);
        return url.hostname;

    } catch (e) {
        // Fallback: remove path & slash
        return input
            .replace(/^https?:\/\//, "")
            .replace(/\/+$/, "")
            .split("/")[0];
    }
}

