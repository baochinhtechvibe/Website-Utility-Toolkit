/*
===============================================
    FORMAT UTILITIES FUNCTIONS
    Các hàm xử lý hiển thị chuỗi, thời gian, dữ liệu
=================================================
*/

import { LEGAL_SUFFIXES } from "./org.js";
/**
 * Cắt chuỗi theo số ký tự tối đa
 * Nếu vượt quá maxLength → thêm "..."
 *
 * Ví dụ:
 * "abcdefghijklmnopqrstuvwxyz", 10
 * → "abcdefghij..."
 *
 * @param {string} str
 * @param {number} maxLength
 * @returns {string}
 */
export function truncateString(str, maxLength = 64) {

    if (!str || str.length <= maxLength) return str;

    return str.substring(0, maxLength) + "...";
}


/**
 * Cắt chuỗi theo số lượng từ
 * Giữ nguyên từ, không cắt giữa chừng
 *
 * Ví dụ:
 * "Google Public DNS Service" (maxWords=3)
 * → "Google Public DNS ..."
 *
 * @param {string} text
 * @param {number} maxWords
 * @returns {string}
 */
export function truncateByWords(text = "", maxWords = 3) {

    const words = text.trim().split(/\s+/);

    // Nếu số từ <= maxWords → giữ nguyên
    if (words.length <= maxWords) {
        return text.trim();
    }

    // Nếu > maxWords → cắt + ...
    return words.slice(0, maxWords).join(" ") + " ...";
}


/**
 * Loại bỏ hậu tố pháp lý khỏi tên tổ chức / ISP
 * Dùng để chuẩn hóa tên hiển thị
 *
 * Ví dụ:
 * "Google LLC." → "google"
 * "Amazon, Inc" → "amazon"
 *
 * @param {string} name
 * @returns {string}
 */
export function stripLegalSuffix(name = "") {

    let clean = name.toLowerCase();

    // Loại bỏ dấu chấm và dấu phẩy
    clean = clean.replace(/[.,]/g, "");

    // Xóa các hậu tố pháp lý (LLC, Inc, Ltd, ...)
    LEGAL_SUFFIXES.forEach(suffix => {
        clean = clean.replace(
            new RegExp(`\\b${suffix}\\b`, "gi"),
            ""
        );
    });

    // Chuẩn hóa khoảng trắng
    return clean.replace(/\s+/g, " ").trim();
}


/**
 * Định dạng TTL (Time To Live)
 * Hiện tại trả về giá trị giây gốc
 *
 * Nếu không có dữ liệu → "N/A"
 *
 * @param {number|null} ttl
 * @returns {string|number}
 */
export function formatTTL(ttl) {

    if (!ttl && ttl !== 0) return "N/A";

    return ttl; // Trả về số giây
}


/**
 * Định dạng ngày hết hạn (SSL / Cert / Whois...)
 * Đồng thời tạo trạng thái cảnh báo theo số ngày còn lại
 *
 * Trạng thái:
 * - Hết hạn → expired
 * - ≤ 7 ngày → warning
 * - ≤ 30 ngày → soon
 * - > 30 ngày → ok
 *
 * @param {string} dateString - ISO date string
 * @returns {string} HTML hiển thị trạng thái
 */
export function formatExpirationDate(dateString) {

    // Giá trị rỗng hoặc mặc định → không có dữ liệu
    if (
        !dateString ||
        dateString === "0001-01-01T00:00:00Z"
    ) {
        return "N/A";
    }

    const date = new Date(dateString);
    const now = new Date();

    // Khoảng cách thời gian (ms)
    const diffTime = date - now;

    // Chuyển sang ngày
    const diffDays = Math.ceil(
        diffTime / (1000 * 60 * 60 * 24)
    );

    // Format theo locale Việt Nam
    const formatted = date.toLocaleString("vi-VN", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });

    let statusClass = "expires-ok";
    let statusText = "";

    // Xác định trạng thái
    if (diffDays < 0) {

        statusClass = "expires-expired";
        statusText = "⚠️ Expired";

    } else if (diffDays <= 7) {

        statusClass = "expires-warning";
        statusText = `⚠️ Expires in ${diffDays} days`;

    } else if (diffDays <= 30) {

        statusClass = "expires-soon";
        statusText = `Expires in ${diffDays} days`;

    } else {

        statusText = `Valid for ${diffDays} days`;
    }

    // Trả về block HTML để render trực tiếp
    return `
        <div class="expiration-info">
            <div class="expiration-date">${formatted}</div>
            <div class="expiration-status ${statusClass}">
                ${statusText}
            </div>
        </div>
    `;
}

/**
 * Định dạng ngày (ISO string) theo chuẩn Việt Nam
 * Hiển thị dạng: DD/MM/YYYY
 *
 * Nếu không có dữ liệu hoặc date không hợp lệ → "N/A"
 *
 * Ví dụ:
 * "2026-02-08T03:15:00Z"
 * → "08/02/2026"
 *
 * @param {string|null} iso - ISO date string
 * @returns {string}
 */
export function formatDate(iso) {

    if (!iso) return "N/A";

    const date = new Date(iso);

    if (Number.isNaN(date.getTime())) {
        return "N/A";
    }

    return date.toLocaleDateString("vi-VN", {
        day: "2-digit",
        month: "2-digit",
        year: "numeric",
    });
}


