/**
 * FILE: ip-lookup.js
 * Logic cho công cụ tra cứu IP (My IP Lookup)
 * Bao gồm Smart Watcher tự động phát hiện thay đổi IP (VPN/Mạng)
 */

import { API_BASE_URL } from "../../config.js";

import {
    $,
    $$,
    escapeHTML,
    copyToClipboard,
    setDisplay
} from "../../utils/index.js";


// Khởi tạo bản đồ (biến toàn cục để cập nhật)
let ipMap = null;
let mapMarker = null;
let isRefreshing = false;

// Smart Watcher state
let currentIPs = { v4: null, v6: null };
let watcherIntervalId = null;
const WATCHER_INTERVAL_MS = 30000; // 30 giây

// Data state cho 2 Tabs
let globalV4Data = null;
let globalV6Data = null;
let currentActiveTab = "v4";
let currentFetchSession = 0;

function init() {
    initMyIP();
    setupEventListeners();
    setupTabs();
    setupRefreshLogic();
    startSmartWatcher();
}

document.addEventListener("DOMContentLoaded", init);

// ============================================
//  SMART WATCHER: Tự động phát hiện đổi IP
// ============================================

/**
 * Khởi động Smart Watcher:
 * - setInterval mỗi 30s gọi endpoint /my-ip/check (nhẹ, chỉ trả IP thô)
 * - visibilitychange: khi user quay lại tab → check ngay lập tức
 * - Nếu IP khác → tự động load lại toàn bộ details
 */
function startSmartWatcher() {
    // Interval check mỗi 30 giây
    watcherIntervalId = setInterval(checkIPChange, WATCHER_INTERVAL_MS);

    // Check ngay khi user quay lại tab
    document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") {
            checkIPChange();
        }
    });
}

/**
 * Gọi API nhẹ để lấy IP thô, so sánh với IP đang hiển thị.
 * Nếu khác → reload full details + hiện thông báo
 */
async function checkIPChange() {
    // Không check khi đang refresh hoặc chưa có IP ban đầu
    if (isRefreshing || (!currentIPs.v4 && !currentIPs.v6)) return;

    try {
        const isLocal = API_BASE_URL.includes("localhost") || API_BASE_URL.includes("127.0.0.1");

        let newV4 = "N/A";
        let newV6 = "N/A";

        if (isLocal) {
            const res = await fetch(`${API_BASE_URL}/ip-lookup/my-ip/check`);
            if (!res.ok) return;
            let json;
            try {
                json = await res.json();
            } catch (e) {
                return;
            }

            if (json.ip && json.ip.includes(":")) {
                newV6 = json.ip;
                newV4 = currentIPs.v4; // Assume v4 didn't change
            } else if (json.ip) {
                newV4 = json.ip;
                newV6 = currentIPs.v6; // Assume v6 didn't change
            }
        } else {
            const fetchCheck = async (url) => {
                try {
                    const r = await fetch(url);
                    if (r.ok) {
                        const j = await r.json();
                        return j.ip;
                    }
                } catch (e) { }
                return "N/A";
            };

            const [v4, v6] = await Promise.all([
                fetchCheck("https://ipv4.bctechvibe.com/api/ip-lookup/my-ip/check"),
                fetchCheck("https://ipv6.bctechvibe.com/api/ip-lookup/my-ip/check")
            ]);
            newV4 = v4;
            newV6 = v6;
        }

        const changedV4 = newV4 !== "N/A" && newV4 !== currentIPs.v4;
        const changedV6 = newV6 !== "N/A" && newV6 !== currentIPs.v6;

        if (changedV4 || changedV6) {
            const changedIP = changedV4 ? newV4 : newV6;
            currentIPs = { v4: newV4, v6: newV6 };

            // Hiện thông báo cho user
            showIPChangeNotice(changedIP);

            // Reset UI về trạng thái loading và load lại toàn bộ
            resetIPDisplayToLoading();
            await initMyIP(true);
        }
    } catch (err) {
        // Lỗi mạng khi check → bỏ qua âm thầm
    }
}

/**
 * Hiện thông báo trên giao diện khi phát hiện IP thay đổi
 */
function showIPChangeNotice(newIP) {
    const cacheNotice = $("#cacheNotice");
    if (!cacheNotice) return;

    const spanEl = cacheNotice.querySelector("span");
    if (spanEl) {
        const timeStr = new Date().toLocaleString("vi-VN");
        spanEl.innerHTML = `<i class="fa-solid fa-rotate"></i> Phát hiện IP thay đổi thành <b>${escapeHTML(newIP)}</b> lúc <b>${timeStr}</b> — Đang cập nhật...`;
    }
    cacheNotice.classList.remove("d-none");
    setDisplay(cacheNotice, "flex");
}

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

    // Disable nút Copy
    const btnCopyIpv4 = $("#btnCopyIpv4");
    if (btnCopyIpv4) btnCopyIpv4.disabled = true;
    const btnCopyIpv6 = $("#btnCopyIpv6");
    if (btnCopyIpv6) btnCopyIpv6.disabled = true;

    // Disable nút Check Blacklist khi đang load
    const btnBlacklist = $("#btnCheckBlacklist");
    if (btnBlacklist) btnBlacklist.disabled = true;

    // Grid details
    const detailIds = [
        "address", "decimal", "hostname", "asn", "timezone", "isp",
        "services", "country", "region", "city", "postal",
        "latitude", "longitude", "os", "browser", "ua"
    ];

    detailIds.forEach(id => {
        const el = $(`#ip-detail-${id}`);
        if (el) {
            el.innerHTML = loadingHtml;
            el.classList.add("loading-text");
        }
    });

    const rowServices = $("#row-detail-services");
    if (rowServices) rowServices.classList.remove("d-none");
}

/**
 * Khởi tạo dữ liệu IP khi load trang (Hỗ trợ Dual-stack IPv4/IPv6)
 */
async function initMyIP(forceRefresh = false, retryCount = 0) {
    const MAX_RETRIES = 2;
    const sessionId = ++currentFetchSession;

    const fetchIPData = async (mode) => {
        const isLocal = API_BASE_URL.includes("localhost") || API_BASE_URL.includes("127.0.0.1");
        let qs = forceRefresh ? "?refresh=true" : "?";
        qs += (qs === "?" ? "" : "&") + `mode=${mode}`;

        const fetchJson = async (url) => {
            const res = await fetch(url);
            if (!res.ok) throw new Error(`HTTP Error: ${res.status}`);
            let json;
            try {
                json = await res.json();
            } catch (e) {
                throw new Error("Lỗi kết nối máy chủ (Invalid JSON)");
            }
            if (!json.success || !json.data) throw new Error(json.message || json.error || "Unknown error");
            return json;
        };

        let nextV4Data = null;
        let nextV6Data = null;
        let nextMainResult = null;

        if (isLocal) {
            const url = `${API_BASE_URL}/ip-lookup/my-ip${qs}`;
            nextMainResult = await fetchJson(url);

            const isV4 = nextMainResult.data.version === "IPv4";
            nextV4Data = isV4 ? nextMainResult.data : null;
            nextV6Data = !isV4 ? nextMainResult.data : null;
            
            nextMainResult.data.ip_v4 = isV4 ? nextMainResult.data.ip : "N/A";
            nextMainResult.data.ip_v6 = !isV4 ? nextMainResult.data.ip : "N/A";

        } else {
            const url4 = `https://ipv4.bctechvibe.com/api/ip-lookup/my-ip${qs}`;
            const url6 = `https://ipv6.bctechvibe.com/api/ip-lookup/my-ip${qs}`;

            const results = await Promise.allSettled([
                fetchJson(url4),
                fetchJson(url6)
            ]);

            const res4 = results[0].status === "fulfilled" ? results[0].value : null;
            const res6 = results[1].status === "fulfilled" ? results[1].value : null;

            if (!res4 && !res6) {
                throw new Error(results[0].reason?.message || results[1].reason?.message || "Failed to fetch from both IPv4 and IPv6");
            }

            nextMainResult = res4 || res6;

            nextV4Data = res4?.data?.version === "IPv4" ? res4.data : null;
            nextV6Data = res6?.data?.version === "IPv6" ? res6.data : null;

            nextMainResult.data.ip_v4 = nextV4Data ? nextV4Data.ip : "N/A";
            nextMainResult.data.ip_v6 = nextV6Data ? nextV6Data.ip : "N/A";
        }

        // GUARD: Ngăn chặn stale request ghi đè state
        if (currentFetchSession !== sessionId) return;

        // Bắt đầu mutate global state an toàn
        globalV4Data = nextV4Data;
        globalV6Data = nextV6Data;
        let mainResult = nextMainResult;

        if (globalV4Data) globalV4Data.isFastMode = (mode === "fast");
        if (globalV6Data) globalV6Data.isFastMode = (mode === "fast");

        currentIPs = {
            v4: mainResult.data.ip_v4,
            v6: mainResult.data.ip_v6
        };

        renderSummary(mainResult.data, mainResult.meta);
        switchTab(currentActiveTab);
    };

    try {
        // BƯỚC 1: Gọi fast mode (Trả về MaxMind siêu nhanh trong 10ms)
        await fetchIPData("fast");

        // BƯỚC 2: Chạy ngầm deep mode để lấy các API chậm (chờ 10-15s), sẽ tự update UI khi xong
        fetchIPData("deep").catch(e => console.warn("Lỗi khi fetch deep info:", e));

    } catch (error) {
        if (retryCount < MAX_RETRIES) {
            const delay = 1000 * (retryCount + 1);
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

    const detailIds = [
        "address", "decimal", "hostname", "asn", "timezone", "isp",
        "services", "country", "region", "city", "postal",
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
 * Render dữ liệu vào giao diện (phần trên cùng)
 */
function renderSummary(data, meta = null) {
    // 1. Phần Summary (IPv4/IPv6)
    const v4El = $("#my-ip-v4");
    const v6El = $("#my-ip-v6");
    v4El?.classList.remove("loading-text");
    v6El?.classList.remove("loading-text");

    const btnCopyIpv4 = $("#btnCopyIpv4");
    const btnCopyIpv6 = $("#btnCopyIpv6");

    const ip4 = data.ip_v4 || "N/A";
    const ip6 = data.ip_v6 || "N/A";

    if (v4El) {
        if (ip4 === "N/A") {
            v4El.innerHTML = `<span class="badge badge-warning">Not Detected</span>`;
        } else {
            v4El.innerHTML = `<span class="badge badge-success text-md">${ip4}</span>`;
        }
    }

    if (v6El) {
        if (ip6 === "N/A") {
            v6El.innerHTML = `<span class="badge badge-warning">Not Detected</span>`;
        } else {
            v6El.innerHTML = `<span class="badge badge-success text-md">${ip6}</span>`;
        }
    }

    if (btnCopyIpv4) btnCopyIpv4.disabled = (ip4 === "N/A");
    if (btnCopyIpv6) btnCopyIpv6.disabled = (ip6 === "N/A");

    // Cập nhật timestamp tra cứu và thông báo cache
    const cacheNotice = $("#cacheNotice");
    if (cacheNotice && meta) {
        setDisplay(cacheNotice, "flex");
        cacheNotice.classList.remove("d-none");
        const spanEl = cacheNotice.querySelector("span");
        if (spanEl) {
            const timeStr = meta.fetched_at
                ? new Date(meta.fetched_at).toLocaleString('vi-VN')
                : new Date().toLocaleString('vi-VN');

            if (meta.cached) {
                spanEl.innerHTML = `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b id="cacheTime">${timeStr}</b>`;
            } else {
                spanEl.innerHTML = `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b id="cacheTime">${timeStr}</b>`;
            }
        }
    }
}

/**
 * Render chi tiết cho Tab được chọn
 */
function renderDetailsTab(data) {
    if (!data) return;

    // Các dòng chi tiết
    updateDetailField("ip-detail-address", data.ip);
    updateDetailField("ip-detail-decimal", data.decimal);
    updateDetailField("ip-detail-hostname", data.hostname);
    updateDetailField("ip-detail-asn", data.asn);
    updateDetailField("ip-detail-isp", data.isp);
    // Xử lý hiển thị Services (VPN Detection)
    const servicesEl = document.getElementById("ip-detail-services");
    const rowServicesEl = document.getElementById("row-detail-services");
    if (servicesEl) {
        let tags = [];
        if (data.is_proxy) tags.push(`<span class="badge badge-warning">Proxy/VPN</span>`);
        if (data.is_hosting) tags.push(`<span class="badge badge-info">Hosting/DC</span>`);
        if (data.is_mobile) tags.push(`<span class="badge badge-success">Mobile</span>`);

        if (tags.length > 0) {
            servicesEl.classList.remove("loading-text");
            servicesEl.innerHTML = tags.join(" ");
            if (rowServicesEl) rowServicesEl.classList.remove("d-none");
        } else if (!data.services || data.services === "N/A") {
            if (!data.isFastMode) {
                servicesEl.classList.remove("loading-text");
                if (rowServicesEl) rowServicesEl.classList.remove("d-none");
                servicesEl.innerHTML = `<span class="text-na">N/A</span>`;
            }
        } else {
            servicesEl.classList.remove("loading-text");
            servicesEl.textContent = data.services;
            if (rowServicesEl) rowServicesEl.classList.remove("d-none");
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

    updateDetailField("ip-detail-region", data.region, data.isFastMode);
    updateDetailField("ip-detail-city", data.city, data.isFastMode);
    updateDetailField("ip-detail-postal", data.postal_code, data.isFastMode);
    updateDetailField("ip-detail-timezone", data.timezone, data.isFastMode);

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
}

/**
 * Xử lý chuyển đổi Tab
 */
function switchTab(tabType) {
    currentActiveTab = tabType;
    
    // Đổi CSS active cho các nút Tab
    $$(".ip-tab-btn").forEach(btn => btn.classList.remove("active"));
    const activeBtn = document.querySelector(`.ip-tab-btn[data-type="${tabType}"]`);
    if (activeBtn) activeBtn.classList.add("active");

    const data = tabType === "v4" ? globalV4Data : globalV6Data;
    const contentList = $("#ip-details-content");
    const mapContainer = $(".ip-details-map-container");
    const notDetectedMsg = $("#ip-not-detected");

    const btnBlacklist = $("#btnCheckBlacklist");

    if (!data) {
        // Tab này không có IP (vd: IPv6 Not Detected)
        if (contentList) contentList.classList.add("d-none"); // Ẩn bảng chi tiết theo ý user
        if (mapContainer) mapContainer.classList.remove("d-none"); // Vẫn giữ layout bản đồ
        if (notDetectedMsg) notDetectedMsg.classList.remove("d-none"); // Hiện cảnh báo
        
        if (btnBlacklist) btnBlacklist.disabled = true; // Disable nút blacklist
        
        clearMap(); // Xóa mốc bản đồ
    } else {
        // Có dữ liệu
        if (contentList) contentList.classList.remove("d-none");
        if (mapContainer) mapContainer.classList.remove("d-none");
        if (notDetectedMsg) notDetectedMsg.classList.add("d-none");
        
        if (btnBlacklist) btnBlacklist.disabled = false; // Bật lại nút
        
        renderDetailsTab(data);
        initMap(data.latitude, data.longitude, data.ip);
    }
}

/**
 * Cài đặt sự kiện cho Tabs
 */
function setupTabs() {
    $$(".ip-tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const type = btn.getAttribute("data-type");
            if (type && type !== currentActiveTab) {
                switchTab(type);
            }
        });
    });
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
 * Cập nhật từng field chi tiết, nếu rỗng thì hiện N/A hoặc giữ Checking nếu đang fast mode
 */
function updateDetailField(id, value, isFastMode = false) {
    const el = document.getElementById(id);
    if (!el) return;

    if (value === undefined || value === null || value === "") {
        if (!isFastMode) {
            el.classList.remove("loading-text");
            el.innerHTML = `<span class="text-na">N/A</span>`;
        }
    } else {
        el.classList.remove("loading-text");
        el.textContent = value;
    }
}

/**
 * Khởi tạo hoặc cập nhật bản đồ Leaflet
 */
function initMap(lat, lon, ip, retryCount = 0) {
    if (lat == null || lon == null) return;

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
 * Xóa marker khỏi bản đồ và đưa về vị trí trống
 */
function clearMap() {
    if (!ipMap) return;
    if (mapMarker) {
        mapMarker.remove();
        mapMarker = null;
    }
    // Set view ra giữa đại dương hoặc zoom xa ra để trông như bản đồ trống
    ipMap.setView([20, 0], 2);
}

/**
 * Thiết lập các event listener (Copy, v.v.)
 */
function setupEventListeners() {
    // Nút copy — sử dụng classList thay vì ghi đè className (Rule 17 GEMINI.md)
    $$(".btn-copy").forEach(btn => {
        btn.addEventListener("click", async () => {
            const targetId = btn.getAttribute("data-target");
            const text = $(targetId)?.textContent;
            if (text && text !== "N/A" && text !== "Checking...") {
                const success = await copyToClipboard(text);
                if (success) {
                    const icon = btn.querySelector("i");
                    const textSpan = btn.querySelector("span");

                    // Lưu nội dung gốc
                    const originalText = textSpan ? textSpan.textContent : "Copy IP";

                    // Đổi sang trạng thái "Copied" — chỉ toggle class modifier
                    if (icon) {
                        icon.classList.remove("fa-copy");
                        icon.classList.add("fa-check");
                    }
                    btn.classList.add("btn-success");
                    // Cập nhật text trong span
                    if (textSpan) textSpan.textContent = "Copied";

                    setTimeout(() => {
                        if (icon) {
                            icon.classList.remove("fa-check");
                            icon.classList.add("fa-copy");
                        }
                        btn.classList.remove("btn-success");
                        if (textSpan) textSpan.textContent = originalText;
                    }, 2000);
                }
            }
        });
    });

    // Nút Check Blacklist (Hiện tại chỉ là placeholder hoặc redirect)
    $("#btnCheckBlacklist")?.addEventListener("click", () => {
        const ip = $("#ip-detail-address")?.textContent;
        if (ip && ip !== "N/A" && ip !== "Checking...") {
            window.location.href = `../tools/dns.html?host=${encodeURIComponent(ip.trim())}&type=BLACKLIST`;
        }
    });
}
