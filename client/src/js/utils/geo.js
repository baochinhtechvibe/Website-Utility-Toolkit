/*
===============================================
    GEOGRAPHIC UTILITIES FUNCTIONS
    Các hàm xử lý dữ liệu quốc gia / vị trí địa lý
=================================================
*/


/**
 * Chuyển tên quốc gia (English name) → mã quốc gia ISO 3166-1 alpha-2
 * Dùng để hiển thị cờ, map, API geo, CDN, v.v.
 *
 * Ví dụ:
 * "Vietnam"        → "vn"
 * "United States"  → "us"
 * "Japan"          → "jp"
 *
 * @param {string} countryName - Tên quốc gia (theo dữ liệu API trả về)
 * @returns {string} country code (viết thường) hoặc "" nếu không tìm thấy
 */
export function getCountryCode(countryName) {

    const countryMap = {

        "United States": "us",
        Vietnam: "vn",
        Singapore: "sg",
        Japan: "jp",
        China: "cn",
        "United Kingdom": "gb",
        Germany: "de",
        France: "fr",
        Australia: "au",
        Canada: "ca",
        India: "in",
        Brazil: "br",
        Russia: "ru",
        "South Korea": "kr",
        Netherlands: "nl",
        Switzerland: "ch",
        Sweden: "se",
        Spain: "es",
        Italy: "it",
        Poland: "pl",

    };

    // Trả về mã ISO hoặc chuỗi rỗng nếu không có
    return countryMap[countryName] || "";
}


/**
 * Tạo HTML hiển thị cờ quốc gia từ country code
 * Sử dụng CDN của flagcdn.com
 *
 * Nếu ảnh load lỗi → tự động ẩn
 *
 * Ví dụ:
 * "vn" → <img src=".../vn.png">
 *
 * @param {string} countryCode - ISO code (vd: vn, us, jp)
 * @returns {string} HTML img tag
 */
export function getCountryFlag(countryCode) {

    if (!countryCode) return "";

    // CDN hiển thị ảnh cờ (24x18)
    const flagUrl = `https://flagcdn.com/24x18/${countryCode.toLowerCase()}.png`;

    return `
        <img
            src="${flagUrl}"
            alt="${countryCode}"
            class="country-flag"
            onerror="this.style.display='none'"
        >
    `;
}
