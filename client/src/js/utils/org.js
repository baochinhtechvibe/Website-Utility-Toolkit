/*
===============================================
    ISP / ORGANIZATION DISPLAY NORMALIZATION
    Chuẩn hóa tên nhà mạng / tổ chức để hiển thị UI
=================================================
*/
import {stripLegalSuffix} from "./format.js";

/**
 * Danh sách hậu tố pháp lý của công ty
 * Dùng để loại bỏ khi hiển thị tên ISP/ORG
 *
 * Ví dụ:
 * "FPT Telecom Joint Stock Company"
 * → "fpt telecom"
 */
export const LEGAL_SUFFIXES = [

    "joint stock company",
    "company limited",
    "limited",
    "co., ltd",
    "co ltd",
    "ltd",
    "jsc",
    "corp",
    "corporation",
    "group",
    "inc",
    "inc.",
    "plc",        // Public limited company
    "llc",        // Limited liability company
    "llp",        // Limited liability partnership
    "gmbh",       // Germany
    "sa",         // Société Anonyme (EU)
    "ag",         // Germany / Switzerland
    "pte",        // Singapore
    "srl",        // Italy / Romania / LatAm
    "spa",        // Italy
    "oy",         // Finland
    "ab",         // Sweden
    "as",         // Norway / Estonia
    "bv",         // Netherlands
    "kk",         // Japan
    "oyj",        // Finland
    "nv",         // Belgium / Netherlands
    "sae",        // Spain
    "sas",        // France
    "gk",         // Japan

];


/**
 * Các keyword đặc biệt cần giữ nguyên tên đầy đủ
 * (Registry, NIC, tổ chức quản lý Internet)
 *
 * Ví dụ:
 * APNIC, VNNIC, RIPE, ARIN...
 */
export const KEEP_FULL_NAME_KEYWORDS = [

    "internet network information center",
    "vnnic",
    "apnic",
    "ripe",
    "arin",
    "lacnic",
    "nic"

];


/**
 * Chuẩn hóa và rút gọn tên ISP/ORG để hiển thị
 *
 * Luồng xử lý:
 * 1. Ưu tiên lấy org → fallback sang isp
 * 2. Nếu là NIC/Registry → giữ nguyên
 * 3. Nếu có nội dung trong ngoặc → lấy phần đó
 * 4. Strip hậu tố pháp lý
 * 5. Cắt tối đa 3 từ
 * 6. Viết hoa chữ cái đầu
 *
 * @param {Object} record - Dữ liệu từ API (ipinfo, whois, geo, ...)
 * @returns {string} Tên hiển thị rút gọn
 */
export function getISPDisplay(record) {

    // Ưu tiên org, fallback sang isp
    const source = record.org || record.isp;

    if (!source) return "-";


    // 1️⃣ Nếu là NIC / Registry → giữ nguyên
    if (shouldKeepFullName(source)) {
        return truncateByWords(source, 3);
    }


    // 2️⃣ Nếu có nội dung trong ngoặc
    // Ví dụ: "ABC Telecom (Vietnam) Co., Ltd"
    const match = source.match(/\(([^)]+)\)/);

    if (match && match[1]) {

        const inner = stripLegalSuffix(match[1]);

        return truncateByWords(inner, 3);
    }


    // 3️⃣ Chuẩn hóa thông thường
    const normalized = stripLegalSuffix(source);

    const truncated = truncateByWords(normalized, 3);


    // Viết hoa chữ cái đầu từng từ
    return truncated
        .split(" ")
        .map(w => w.charAt(0).toUpperCase() + w.slice(1))
        .join(" ");
}


/**
 * Kiểm tra xem tên tổ chức có thuộc nhóm cần giữ nguyên không
 * (NIC / Registry / Authority)
 *
 * @param {string} name
 * @returns {boolean}
 */
export function shouldKeepFullName(name = "") {

    const lower = name.toLowerCase();

    return KEEP_FULL_NAME_KEYWORDS.some(
        k => lower.includes(k)
    );
}
