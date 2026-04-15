/**
 * FILE: ip-lookup.js
 * Logic cho công cụ tra cứu IP (My IP Lookup)
 */

import { API_BASE_URL } from "../../config.js";

import { 
    $, 
    $$, 
    escapeHTML, 
    copyToClipboard,
    setDisplay,
    showElements,
    renderSuccessHeader
} from "../../utils/index.js";


// Khởi tạo bản đồ (biến toàn cục để cập nhật)
let ipMap = null;
let mapMarker = null;
let isRefreshing = false;

function init() {
    initMyIP();
    setupEventListeners();
    setupRefreshLogic();
}

document.addEventListener("DOMContentLoaded", init);

function setupRefreshLogic() {
    const btnRefreshIP = $("#btnRefreshIP");
    if (!btnRefreshIP) return;

    btnRefreshIP.addEventListener("click", async () => {
        if (isRefreshing) return;
        isRefreshing = true;

        const icon = btnRefreshIP.querySelector("i");
        
        // 1. Hiệu ứng xoay icon
        icon?.classList.add("fa-spin");
        btnRefreshIP.disabled = true;
        
        // 2. Reset các trường về trạng thái "Checking..."
        resetIPDisplayToLoading();
        
        // 3. Truyền true để báo hiệu force refresh (bypass cache)
        try {
            await initMyIP(true);
        } finally {
            setTimeout(() => {
                icon?.classList.remove("fa-spin");
                btnRefreshIP.disabled = false;
                isRefreshing = false;
            }, 500);
        }
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
    if (targetEl) {
        targetEl.innerHTML = loadingHtml;
        targetEl.classList.add("loading-text");
    }

    // Disable nút Check Blacklist khi đang load
    const btnBlacklist = $("#btnCheckBlacklist");
    if (btnBlacklist) btnBlacklist.disabled = true;

    // Grid details
    const detailIds = [
        "decimal", "hostname", "asn", "timezone", "isp", 
        "services", "country", "region", "city", 
        "latitude", "longitude", "os", "browser", "ua"
    ];
    
    detailIds.forEach(id => {
        const el = $(`#ip-detail-${id}`);
        if (el) {
            el.innerHTML = loadingHtml;
            el.classList.add("loading-text");
        }
    });
}

/**
 * Khởi tạo dữ liệu IP khi load trang
 */
async function initMyIP(forceRefresh = false, retryCount = 0) {
    const MAX_RETRIES = 2;

    try {
        // Fetch dữ liệu từ backend, thêm query refresh nếu cần
        const url = forceRefresh 
            ? `${API_BASE_URL}/ip-lookup/my-ip?refresh=true` 
            : `${API_BASE_URL}/ip-lookup/my-ip`;

        const response = await fetch(url);
        
        if (!response.ok) {
            throw new Error(`HTTP Error: ${response.status}`);
        }

        const result = await response.json();

        if (result.success && result.data) {
            renderIPData(result.data, result.meta);
            initMap(result.data.latitude, result.data.longitude, result.data.ip);
        } else {
            throw new Error(result.message || result.error || "Unknown error");
        }
    } catch (error) {
        console.error("Error initializing IP tool:", error);
        
        // Retry logic
        if (retryCount < MAX_RETRIES) {
            const delay = 1000 * (retryCount + 1);
            console.log(`Retrying in ${delay}ms... (${retryCount + 1}/${MAX_RETRIES})`);
            await new Promise(resolve => setTimeout(resolve, delay));
            return initMyIP(forceRefresh, retryCount + 1);
        }

        showFetchError(`Không thể lấy thông tin IP: ${error.message}`);
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
    if (targetEl) {
        targetEl.innerHTML = errorHtml;
        targetEl.classList.remove("loading-text");
    }

    const detailIds = [
        "decimal", "hostname", "asn", "timezone", "isp", 
        "services", "country", "region", "city", 
        "latitude", "longitude", "os", "browser", "ua"
    ];
    detailIds.forEach(id => {
        const el = $(`#ip-detail-${id}`);
        if (el) {
            el.innerHTML = `<span class="text-na">N/A</span>`;
            el.classList.remove("loading-text");
        }
    });

    // Re-enable nút Check Blacklist khi có lỗi để user có thể tương tác lại
    const btnBlacklist = $("#btnCheckBlacklist");
    if (btnBlacklist) btnBlacklist.disabled = false;
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

    // 2. Phần chi tiết trong Title
    const summaryTitle = $(".ip-summary-section .card__title");
    if (summaryTitle) {
        renderSuccessHeader(summaryTitle, "Địa chỉ IP Công cộng của bạn");
    }

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
        let tags = [];
        if (data.is_proxy) tags.push(`<span class="badge badge-warning">Proxy/VPN</span>`);
        if (data.is_hosting) tags.push(`<span class="badge badge-info">Hosting/DC</span>`);
        if (data.is_mobile) tags.push(`<span class="badge badge-success">Mobile</span>`);

        if (tags.length > 0) {
            servicesEl.innerHTML = tags.join(" ");
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

    // Kích hoạt lại nút Check Blacklist sau khi có IP
    const btnBlacklist = $("#btnCheckBlacklist");
    if (btnBlacklist) btnBlacklist.disabled = false;

    // Cập nhật timestamp tra cứu và thông báo cache
    const cacheNotice = $("#cacheNotice");
    if (cacheNotice && meta) {
        setDisplay(cacheNotice, "flex");
        const spanEl = cacheNotice.querySelector(".cache-card__text");
        const timeStr = meta.fetched_at 
            ? new Date(meta.fetched_at).toLocaleString('vi-VN') 
            : new Date().toLocaleString('vi-VN');

        if (meta.cached) {
            spanEl.innerHTML = `Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b id="cacheTime">${timeStr}</b>.`;
        } else {
            spanEl.innerHTML = `Kết quả tra cứu mới nhất lúc <b id="cacheTime">${timeStr}</b>.`;
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
function initMap(lat, lon, ip, retryCount = 0) {
    if (!lat || !lon) return;
    
    // Đợi Leaflet (L) sẵn sàng nếu dùng defer
    if (typeof L === 'undefined') {
        if (retryCount < 10) { // Thử lại trong 2 giây (mỗi lần 200ms)
            setTimeout(() => initMap(lat, lon, ip, retryCount + 1), 200);
        }
        return;
    }

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
        mapMarker.remove();
        mapMarker = null;
    }
    
    mapMarker = L.marker([lat, lon]).addTo(ipMap)
        .bindPopup(`IP: ${ip}`)
        .openPopup();
}

/**
 * Thiết lập các event listener (Copy, v.v.)
 */
function setupEventListeners() {
    // Nút copy
    $$(".btn-copy").forEach(btn => {
        btn.addEventListener("click", async () => {
            const targetId = btn.getAttribute("data-target");
            const text = $(targetId)?.textContent;
            if (text && text !== "N/A" && text !== "Checking...") {
                const success = await copyToClipboard(text);
                if (success) {
                    const originalHtml = btn.innerHTML;
                    const originalClass = btn.className;
                    
                    btn.innerHTML = `<i class="fa-solid fa-check"></i> Copied`;
                    btn.classList.add("btn-success");
                    
                    setTimeout(() => {
                        btn.innerHTML = originalHtml;
                        btn.className = originalClass;
                    }, 2000);
                }
            }
        });
    });

    // Nút Check Blacklist (Hiện tại chỉ là placeholder hoặc redirect)
    $("#btnCheckBlacklist")?.addEventListener("click", () => {
        const ip = $("#detailIPTarget")?.textContent;
        if (ip && ip !== "N/A" && ip !== "Checking...") {
            window.location.href = `../tools/dns.html?host=${encodeURIComponent(ip.trim())}&type=BLACKLIST`;
        }
    });
}
