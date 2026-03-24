/**
 * FILE: ip-lookup.js
 * Logic cho công cụ tra cứu IP (My IP Lookup)
 */

import { API_BASE_URL } from "../../config.js";

import { 
    $, 
    $$,
    show, 
    hide, 
    toggleLoading,
    escapeHTML,
} from "../../utils/index.js";


// Khởi tạo bản đồ (biến toàn cục để cập nhật)
let ipMap = null;
let mapMarker = null;

document.addEventListener("DOMContentLoaded", () => {
    initMyIP();
    setupEventListeners();
    setupRefreshLogic();
});

function setupRefreshLogic() {
    $("#btnRefreshIP")?.addEventListener("click", () => {
        const btn = $("#btnRefreshIP");
        const icon = btn.querySelector("i");
        
        // 1. Hiệu ứng xoay icon
        icon?.classList.add("fa-spin");
        btn.disabled = true;
        
        // 2. Reset các trường về trạng thái "Checking..."
        resetIPDisplayToLoading();
        
        // 3. Truyền true để báo hiệu force refresh (bypass cache)
        initMyIP(true).finally(() => {
            setTimeout(() => {
                icon?.classList.remove("fa-spin");
                btn.disabled = false;
            }, 500);
        });
    });
}

/**
 * Đưa giao diện về trạng thái đang kiểm tra
 */
function resetIPDisplayToLoading() {
    const loadingHtml = `<span class="loading-text">Checking...</span>`;
    
    // Summary
    const v4El = $("#my-ip-v4");
    if (v4El) v4El.innerHTML = loadingHtml;
    
    const v6El = $("#my-ip-v6");
    if (v6El) v6El.innerHTML = loadingHtml;

    // Details Header
    const targetEl = $("#detailIPTarget");
    if (targetEl) targetEl.innerHTML = loadingHtml;

    // Grid details
    const detailIds = [
        "decimal", "hostname", "asn", "timezone", "isp", 
        "services", "country", "region", "city", 
        "latitude", "longitude", "os", "browser", "ua"
    ];
    
    detailIds.forEach(id => {
        const el = $(`#ip-detail-${id}`);
        if (el) el.innerHTML = loadingHtml;
    });
}

/**
 * Khởi tạo dữ liệu IP khi load trang
 */
async function initMyIP(forceRefresh = false) {
    try {
        // Fetch dữ liệu từ backend, thêm query refresh nếu cần
        const url = forceRefresh 
            ? `${API_BASE_URL}/ip-lookup/my-ip?refresh=true` 
            : `${API_BASE_URL}/ip-lookup/my-ip`;

        const response = await fetch(url);
        const result = await response.json();

        if (result.success && result.data) {
            renderIPData(result.data, result.meta);
            initMap(result.data.latitude, result.data.longitude, result.data.ip);
        } else {
            console.error("Failed to fetch IP data:", result.message || result.error);
            showFetchError("Không thể lấy thông tin IP. Vui lòng thử lại.");
        }
    } catch (error) {
        console.error("Error initializing IP tool:", error);
        showFetchError("Không kết nối được với máy chủ.");
    }
}

/**
 * Hiển thị lỗi khi gọi API thất bại
 */
function showFetchError(msg) {
    const errorHtml = `<span class="text-danger font-medium">${escapeHTML(msg)}</span>`;
    const v4El = $("#my-ip-v4");
    if (v4El) v4El.innerHTML = errorHtml;
    const v6El = $("#my-ip-v6");
    if (v6El) v6El.innerHTML = errorHtml;
    
    const targetEl = $("#detailIPTarget");
    if (targetEl) targetEl.innerHTML = errorHtml;

    const detailIds = [
        "decimal", "hostname", "asn", "timezone", "isp", 
        "services", "country", "region", "city", 
        "latitude", "longitude", "os", "browser", "ua"
    ];
    detailIds.forEach(id => {
        const el = $(`#ip-detail-${id}`);
        if (el) el.innerHTML = `<span class="text-na">N/A</span>`;
    });
}

/**
 * Render dữ liệu vào giao diện
 */
function renderIPData(data, meta = null) {
    // 1. Phần Summary (IPv4/IPv6)
    const v4El = $("#my-ip-v4");
    const v6El = $("#my-ip-v6");
    v4El?.classList.remove("loading-text");
    v6El?.classList.remove("loading-text");

    if (data.version === "IPv4") {
        if (v4El) v4El.textContent = data.ip;
        if (v6El) v6El.textContent = "N/A";
    } else {
        if (v4El) v4El.textContent = "N/A";
        if (v6El) v6El.textContent = data.ip;
    }

    // 2. Phần chi tiết trong Card Title
    const targetEl = $("#detailIPTarget");
    if (targetEl) {
        targetEl.classList.remove("loading-text");
        targetEl.textContent = data.ip;
    }

    // 3. Các dòng chi tiết
    updateDetailField("ip-detail-decimal", data.decimal);
    updateDetailField("ip-detail-hostname", data.hostname);
    updateDetailField("ip-detail-asn", data.asn);
    updateDetailField("ip-detail-isp", data.isp);
    // Xử lý hiển thị Services (VPN Detection)
    const servicesEl = document.getElementById("ip-detail-services");
    if (servicesEl) {
        servicesEl.classList.remove("loading-text");
        if (data.services === "VPN Server") {
            servicesEl.innerHTML = `<span style="color: var(--green-400); font-weight: bold;">VPN Server</span>`;
        } else if (!data.services || data.services === "N/A") {
            servicesEl.innerHTML = `<span class="text-na">N/A</span>`;
        } else {
            servicesEl.textContent = data.services;
        }
    }
    
    // Xử lý hiển thị Quốc gia kèm lá cờ
    const countryEl = document.getElementById("ip-detail-country");
    if (countryEl) {
        countryEl.classList.remove("loading-text");
        if (data.country && data.country_code) {
            countryEl.innerHTML = `
                <img src="https://flagcdn.com/24x18/${escapeHTML(data.country_code.toLowerCase())}.png" 
                     srcset="https://flagcdn.com/48x36/${escapeHTML(data.country_code.toLowerCase())}.png 2x"
                     width="24" height="18" 
                     alt="${escapeHTML(data.country)}"
                     class="ip-flag">
                <span>${escapeHTML(data.country)}</span>
            `;
        } else {
            countryEl.innerHTML = `<span class="text-na">N/A</span>`;
        }
    }

    updateDetailField("ip-detail-region", data.region);
    updateDetailField("ip-detail-city", data.city);
    updateDetailField("ip-detail-timezone", data.timezone);

    // Xử lý định dạng tọa độ Decimal (DMS)
    const latEl = $("#ip-detail-latitude");
    if (latEl) {
        latEl.classList.remove("loading-text");
        latEl.textContent = `${data.latitude} (${toDMS(data.latitude, true)})`;
    }
    const lonEl = $("#ip-detail-longitude");
    if (lonEl) {
        lonEl.classList.remove("loading-text");
        lonEl.textContent = `${data.longitude} (${toDMS(data.longitude, false)})`;
    }
    
    // OS, Browser & UA mới
    updateDetailField("ip-detail-os", data.os);
    updateDetailField("ip-detail-browser", data.browser);
    updateDetailField("ip-detail-ua", data.user_agent);

    // Cập nhật timestamp tra cứu và thông báo cache
    const cacheNotice = $("#cacheNotice");
    if (cacheNotice && meta) {
        cacheNotice.classList.remove("d-none");
        const spanEl = cacheNotice.querySelector("span");
        const timeStr = meta.fetched_at 
            ? new Date(meta.fetched_at).toLocaleString('vi-VN') 
            : new Date().toLocaleString('vi-VN');

        if (meta.cached) {
            spanEl.innerHTML = `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b id="cacheTime">${timeStr}</b>.`;
        } else {
            spanEl.innerHTML = `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b id="cacheTime">${timeStr}</b>.`;
        }
    }
}

/**
 * Chuyển số thập phân vĩ độ/kinh độ sang định dạng DMS (Độ Phút Giây)
 * Ví dụ: 10.75 --> 10° 45′ 0.00″ N
 */
function toDMS(decimal, isLat) {
    if (!decimal && decimal !== 0) return "N/A";

    const absolute = Math.abs(decimal);
    const degrees = Math.floor(absolute);
    const minutesNotTruncated = (absolute - degrees) * 60;
    const minutes = Math.floor(minutesNotTruncated);
    const seconds = ((minutesNotTruncated - minutes) * 60).toFixed(2);

    let direction = "";
    if (isLat) {
        direction = decimal >= 0 ? "N" : "S";
    } else {
        direction = decimal >= 0 ? "E" : "W";
    }

    return `${degrees}° ${minutes}′ ${seconds}″ ${direction}`;
}

/**
 * Cập nhật từng field chi tiết, nếu rỗng thì hiện N/A
 */
function updateDetailField(id, value) {
    const el = document.getElementById(id);
    if (!el) return;

    // Xóa class loading nếu có
    el.classList.remove("loading-text");

    if (value === undefined || value === null || value === "") {
        el.innerHTML = `<span class="text-na">N/A</span>`;
    } else {
        el.textContent = value;
    }
}

/**
 * Khởi tạo hoặc cập nhật bản đồ Leaflet
 */
function initMap(lat, lon, ip) {
    if (!lat || !lon) return;
    if (typeof L === 'undefined') return;

    const mapEl = document.getElementById("ipMap");
    if (!mapEl) return;

    if (!ipMap) {
        // Lần đầu khởi tạo
        ipMap = L.map('ipMap').setView([lat, lon], 13);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '© OpenStreetMap contributors'
        }).addTo(ipMap);
    } else {
        // Cập nhật vị trí
        ipMap.setView([lat, lon], 13);
    }

    // Cập nhật marker
    if (mapMarker) {
        mapMarker.setLatLng([lat, lon]).setPopupContent(`IP: ${ip}`).openPopup();
    } else {
        mapMarker = L.marker([lat, lon]).addTo(ipMap)
            .bindPopup(`IP: ${ip}`)
            .openPopup();
    }
}

/**
 * Thiết lập các event listener (Copy, v.v.)
 */
function setupEventListeners() {
    // Nút copy
    $$(".btn-copy").forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-target");
            const text = $(targetId)?.textContent;
            if (text && text !== "N/A") {
                copyToClipboard(text, btn);
            }
        });
    });

    // Nút Check Blacklist (Hiện tại chỉ là placeholder hoặc redirect)
    $("#btnCheckBlacklist")?.addEventListener("click", () => {
        const ip = $("#detailIPTarget")?.textContent;
        if (ip && ip !== "N/A") {
            window.location.href = `/tools/dns?ip=${ip}&type=blacklist`;
        }
    });
}

/**
 * Helper copy vào clipboard
 */
async function copyToClipboard(text, btn) {
    try {
        await navigator.clipboard.writeText(text);
        
        // Hiệu ứng feedback nhẹ
        const originalHtml = btn.innerHTML;
        btn.innerHTML = `<i class="fa-solid fa-check"></i> Copied`;
        btn.classList.add("btn-success");
        
        setTimeout(() => {
            btn.innerHTML = originalHtml;
            btn.classList.remove("btn-success");
        }, 2000);
    } catch (err) {
        console.error("Could not copy text: ", err);
    }
}
