import { API_BASE_URL } from '../../config.js';
import { $, createRealtimeURLValidator, escapeHTML } from '../../utils/index.js';

// Dynamic API Resolver
// Fallbacks to standard relative domain path for Prod envs.
const resolveApiBase = () => {
    if (window.location.protocol === 'file:') {
        return API_BASE_URL; // e.g. "http://localhost:3101/api"
    }
    // If we're on a real host (like Vercel, VPS domain)
    if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
        return window.location.origin + "/api";
    }
    return API_BASE_URL;
};

const BASE_API = resolveApiBase();
const SCAN_ENDPOINT = `${BASE_API}/broken-link-scanner/scan`;

const form = $("#bls-form");
const urlInput = $("#bls-url-input");
const btnScan = $("#bls-btn-scan");
const validationError = $("#bls-validation-error");

const progressBlock = $("#bls-progress");
const btnCancel = $("#bls-btn-cancel");
const resultsSection = $("#bls-results-section");
const errorCard = $("#bls-error-card");
const errorMessage = $("#bls-error-message");
const emptyState = $("#bls-empty-state");
const shareCard = $("#shareCard");
const shareLink = $("#shareLink");
const btnCopyLink = $("#btnCopyLink");

// DOM Stats
const statTotal = $("#bls-stat-total");
const statOk = $("#bls-stat-ok");
const statRedirect = $("#bls-stat-redirect");
const statBroken = $("#bls-stat-broken");
const statBlocked = $("#bls-stat-blocked");
const statTimeout = $("#bls-stat-timeout");

const tableWrapper = document.querySelector(".bls-table-wrapper");
const tbody = document.querySelector("#bls-results-body");

// Options
const optSameHost = $("#bls-scope-same-host");
const optIgnoreTls = $("#bls-ignore-tls");
const optBypassCache = $("#bls-bypass-cache");
const workersInput = $("#bls-workers-input");
const workersVal = $("#bls-worker-val");

// Button icons
const scanIcon = $("#bls-scan-icon");
const scanLoadingState = $("#bls-scan-loading");

let currentResults = []; // Store for filtering & CSV export
let abortController = null;
let currentFilter = "all";
let currentPage = 1;
let pageSize = 10;

// ==============================
// Khởi tạo
// ==============================
document.addEventListener('DOMContentLoaded', () => {
    // Slider Value Synchronizer
    if (workersInput) {
        workersInput.addEventListener("input", (e) => {
            if (workersVal) workersVal.textContent = e.target.value;
        });
    }

    // Thiết lập validate realtime (Giống redirect/bot scanner)
    if (urlInput && validationError && btnScan) {
        // Hàm này tự disable nút Scan nếu URL lỗi hoặc rỗng
        createRealtimeURLValidator(urlInput, validationError, btnScan);
        
        // Ẩn thông báo lỗi API & bảng cũ khi user bắt đầu gõ mới
        urlInput.addEventListener('input', () => {
            if (errorCard) errorCard.classList.add("d-none");
            if (resultsSection) resultsSection.classList.add("d-none");
        });
    }

    // Sự kiện Cancel
    btnCancel?.addEventListener('click', () => {
        if (abortController) {
            abortController.abort();
        }
    });

    // Sự kiện Bypass Cache (Làm mới)
    const btnBypassCache = document.getElementById("btnBypassCache");
    btnBypassCache?.addEventListener('click', () => {
        performScan(true);
    });

    // Handle submit chính
    form?.addEventListener("submit", async (e) => {
        e.preventDefault();
        performScan(false);
    });

    async function performScan(isBypassCacheArg = false) {
        const rawUrl = urlInput.value.trim();
        if (!rawUrl) return;

        updateURL(rawUrl);

        // Reset UI state
        if (resultsSection) resultsSection.classList.add("d-none");
        if (shareCard) shareCard.classList.add("d-none");
        
        if (progressBlock) {
            progressBlock.classList.remove("d-none");
            // UI Progress Hardening: Ẩn thanh bar tĩnh và meta 0/? 
            const barTrack = progressBlock.querySelector(".bls-progress-bar-track");
            const barMeta = progressBlock.querySelector(".bls-progress-meta");
            if (barTrack) barTrack.classList.add("d-none");
            if (barMeta) barMeta.classList.add("d-none");
            
            const progressLabel = progressBlock.querySelector("span.font-bold");
            if (progressLabel) progressLabel.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i> Đang thu thập và phân tích liên kết...';
        }

        btnScan.disabled = true;
        if (scanIcon) scanIcon.classList.add("d-none");
        if (scanLoadingState) scanLoadingState.classList.remove("d-none");
        if (tbody) tbody.innerHTML = "";
        currentResults = [];

        // Khởi tạo Abort Controller
        abortController = new AbortController();

        const scope = (optSameHost && optSameHost.checked) ? "same-host" : "all";
        const ignoreTls = optIgnoreTls ? optIgnoreTls.checked : false;
        const bypassCache = isBypassCacheArg;
        const maxWorkers = workersInput ? parseInt(workersInput.value, 10) : 50;

        try {
            const response = await fetch(SCAN_ENDPOINT, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    url: rawUrl,
                    scope: scope,
                    maxWorkers: maxWorkers,
                    ignoreTlsErrors: ignoreTls,
                    bypassCache: bypassCache
                }),
                signal: abortController.signal
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || `HTTP ${response.status}`);
            }

            const scanData = data.data; 
            
            // Render Summary Stats
            if (statTotal) statTotal.textContent = scanData.summary?.total || 0;
            if (statOk) statOk.textContent = scanData.summary?.ok || 0;
            if (statRedirect) statRedirect.textContent = scanData.summary?.redirect || 0;
            if (statBroken) statBroken.textContent = scanData.summary?.broken || 0;
            if (statBlocked) statBlocked.textContent = scanData.summary?.blocked || 0;
            if (statTimeout) statTimeout.textContent = scanData.summary?.timeout || 0;

            currentResults = scanData.results || [];
            currentPage = 1;
            renderTable("all");
            
            // Handle Cache Banner
            const cacheNoticeBox = document.getElementById('cacheNotice');
            if (data.meta) {
                const timeStr = new Date(data.meta.fetched_at).toLocaleString('vi-VN');
                const spanEl = cacheNoticeBox?.querySelector("span");
                if (spanEl) {
                    if (data.meta.cached) {
                        spanEl.innerHTML = `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b id="cacheTime">${timeStr}</b>.`;
                    } else {
                        spanEl.innerHTML = `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b id="cacheTime">${timeStr}</b>.`;
                    }
                }
                cacheNoticeBox?.classList.remove('d-none');
                cacheNoticeBox?.classList.add('d-flex');
            } else {
                cacheNoticeBox?.classList.add('d-none');
                cacheNoticeBox?.classList.remove('d-flex');
            }

            if (resultsSection) resultsSection.classList.remove("d-none");
            if (shareCard) {
                shareCard.classList.remove("d-none");
                if (shareLink) {
                    shareLink.value = window.location.href;
                }
            }

        } catch (err) {
            if (err.name === 'AbortError') {
                console.log('Quét bị người dùng huỷ bỏ.');
                if (errorMessage) errorMessage.textContent = 'Đã hủy thao tác quét.';
            } else {
                if (errorMessage) errorMessage.textContent = err.message;
            }
            if (errorCard) errorCard.classList.remove("d-none");
        } finally {
            if (progressBlock) progressBlock.classList.add("d-none");
            btnScan.disabled = false;
            if (scanIcon) scanIcon.classList.remove("d-none");
            if (scanLoadingState) scanLoadingState.classList.add("d-none");
            abortController = null;
        }
    }

    // Filter Buttons logic
    document.querySelectorAll(".btn-filter").forEach(btn => {
        btn.addEventListener("click", (e) => {
            document.querySelectorAll(".btn-filter").forEach(b => b.classList.remove("is-active"));
            e.currentTarget.classList.add("is-active");
            currentPage = 1;
            renderTable(e.currentTarget.dataset.filter);
        });
    });

    // CSV Export Logic
    const btnExportCSV = document.getElementById("bls-btn-export-csv");
    if (btnExportCSV) {
        btnExportCSV.addEventListener("click", () => {
            if (currentResults.length === 0) return;
            
            const headers = ["Khởi nguồn thẻ", "Phân loại Thẻ", "Đường dẫn gốc", "Đường dẫn Final", "Mã HTTP", "Status Class", "Độ trễ (ms)", "Ghi chú Lỗi"];
            
            let csvContent = headers.join(",") + "\n";
            currentResults.forEach(r => {
                const tr = [
                    `"${(r.source_tag || "").replace(/"/g, '""')}"`,
                    r.kind,
                    `"${r.original_url}"`,
                    `"${r.final_url}"`,
                    r.status_code,
                    r.status_class,
                    r.response_ms || 0,
                    `"${(r.error || "").replace(/"/g, '""')}"`
                ];
                csvContent += tr.join(",") + "\n";
            });

            const blob = new Blob(["\uFEFF"+csvContent], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");
            link.href = url;
            link.setAttribute("download", `broken_links_${new Date().toISOString().substring(0,10)}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
        });
    }

    // Configure Pagination size buttons
    document.querySelectorAll(".btn-size").forEach(btn => {
        btn.addEventListener("click", (e) => {
            document.querySelectorAll(".btn-size").forEach(b => b.classList.remove("is-active"));
            e.currentTarget.classList.add("is-active");
            
            const size = e.currentTarget.dataset.size;
            if (size === "all") {
                pageSize = "all";
            } else {
                pageSize = parseInt(size, 10);
            }
            currentPage = 1;
            renderTable(currentFilter);
        });
    });

    // Setup URL Share/Sync
    const handleParams = () => {
        const params = new URLSearchParams(window.location.search);
        const pUrl = params.get('url');

        if (pUrl && urlInput && form) {
            urlInput.value = decodeURIComponent(pUrl);
            urlInput.dispatchEvent(new Event('input')); // Notify validation logic

            // Auto Submit if scan isn't already running
            if (!scanLoadingState || scanLoadingState.classList.contains('d-none')) {
                // Ensure the button isn't disabled by validator
                setTimeout(() => {
                    if (!btnScan.disabled) {
                        form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
                    }
                }, 100);
            }
        }
    };

    handleParams();

    window.addEventListener("popstate", () => {
        if (abortController) {
            abortController.abort();
        }
        handleParams();
    });

    // Share link copy
    btnCopyLink?.addEventListener('click', async () => {
        try {
            if (shareLink) {
                shareLink.select();
                shareLink.setSelectionRange(0, 99999);
                await navigator.clipboard.writeText(shareLink.value);
            }
            const original = btnCopyLink.innerHTML;
            btnCopyLink.innerHTML = '<i class="fas fa-check"></i> <span>Đã copy!</span>';
            setTimeout(() => { btnCopyLink.innerHTML = original; }, 2000);
        } catch (err) {
            console.error("Copy failed:", err);
        }
    });

});

// Render table function
const paginationContainer = document.getElementById("bls-pagination-container");
const paginationList = document.getElementById("bls-pagination-list");
const pageStartElem = document.getElementById("bls-page-start");
const pageEndElem = document.getElementById("bls-page-end");
const pageTotalElem = document.getElementById("bls-page-total-items");

function renderTable(filter) {
    if (!tbody) return;
    tbody.innerHTML = "";
    currentFilter = filter;

    // Filter results first
    const filteredResults = currentResults.filter(row => {
        if (filter !== "all" && row.status_class !== filter) {
            return false;
        }
        return true;
    });

    const totalItems = filteredResults.length;

    if (totalItems === 0) {
        if (emptyState) emptyState.classList.remove("d-none");
        if (tableWrapper) tableWrapper.classList.add("d-none");
        if (paginationContainer) paginationContainer.classList.add("d-none");
        return;
    } else {
        if (emptyState) emptyState.classList.add("d-none");
        if (tableWrapper) tableWrapper.classList.remove("d-none");
        if (paginationContainer) paginationContainer.classList.remove("d-none");
    }

    let startIndex = 0;
    let endIndex = totalItems;
    
    if (pageSize !== "all") {
        const totalPages = Math.ceil(totalItems / pageSize);
        if (currentPage > totalPages && totalPages > 0) currentPage = totalPages;
        if (currentPage < 1) currentPage = 1;
        
        startIndex = (currentPage - 1) * pageSize;
        endIndex = Math.min(startIndex + pageSize, totalItems);
    }
    
    // Update Pagination Info
    if (pageStartElem) pageStartElem.textContent = totalItems === 0 ? 0 : startIndex + 1;
    if (pageEndElem) pageEndElem.textContent = endIndex;
    if (pageTotalElem) pageTotalElem.textContent = totalItems;

    const pageResults = filteredResults.slice(startIndex, endIndex);

    pageResults.forEach(row => {
        const tr = document.createElement("tr");
        
        // Status Badge
        const tdStatus = document.createElement("td");
        tdStatus.innerHTML = `<span class="badge bls-badge--${row.status_class} uppercase" style="gap: 4px;"><strong>${row.status_code || "ERR"}</strong><span>${row.status_class}</span></span>`;

        // Kind (tag)
        const tdKind = document.createElement("td");
        tdKind.innerHTML = `<span class="bls-tag-badge text-muted">&lt;&lt;${escapeHTML(row.kind)}&gt;&gt;</span>`;

        // Final URL
        const tdURL = document.createElement("td");
        tdURL.className = "bls-url-cell";
        
        let urlMain = escapeHTML(row.final_url);
        let titleBlock = `Original: ${row.original_url}\n`;
        
        if (row.error) {
            titleBlock += `Error: ${row.error}`;
            urlMain = `<span class="text-error">${urlMain} <br/><small><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHTML(row.error)}</small></span>`;
        }
        
        tdURL.innerHTML = `
            <div class="bls-url-main" title="${titleBlock}"><a href="${escapeHTML(row.final_url)}" target="_blank">${urlMain}</a></div>
            <div class="bls-url-parent text-muted"><i class="fa-solid fa-level-up-alt fa-rotate-90"></i> ${escapeHTML(row.original_url)}</div>
        `;

        // Chain & Delay
        const tdChain = document.createElement("td");
        const delayRaw = row.response_ms != null ? row.response_ms : 0;
        tdChain.innerHTML = `
            <div class="bls-latency">${row.redirect_count > 0 ? `<i class="fa-solid fa-arrow-right-arrow-left text-warning"></i> ${row.redirect_count} redirects<br>` : ""}
            <i class="fa-regular fa-clock"></i> ${delayRaw} ms</div>
        `;

        tr.appendChild(tdStatus);
        tr.appendChild(tdKind);
        tr.appendChild(tdURL);
        tr.appendChild(tdChain);
        
        tbody.appendChild(tr);
    });

    renderPaginationControls(totalItems);
}

function renderPaginationControls(totalItems) {
    if (!paginationList) return;
    paginationList.innerHTML = "";
    
    // Nếu chọn Tất cả (all) hoặc tổng số lượng nhỏ hơn số dòng trên 1 trang 
    // -> Không hiển thị các nút chọn trang (danh sách trang rỗng)
    if (pageSize === "all" || totalItems <= pageSize) {
        return;
    }

    const totalPages = Math.ceil(totalItems / pageSize);
    
    const createLi = (htmlContent, pageNum, isDisabled, isActive, extraClass="") => {
        const li = document.createElement("li");
        li.className = `bls-page-item ${isDisabled ? 'is-disabled' : ''} ${isActive ? 'is-active' : ''}`;
        
        const btn = document.createElement("button");
        btn.className = `bls-page-link ${extraClass}`;
        btn.innerHTML = htmlContent;
        btn.type = "button";
        
        if (!isDisabled && !isActive) {
            btn.addEventListener("click", () => {
                currentPage = pageNum;
                renderTable(currentFilter);
                if (resultsSection) {
                    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                }
            });
        }
        li.appendChild(btn);
        return li;
    };

    // Prev
    paginationList.appendChild(createLi('<i class="fas fa-chevron-left mr-1"></i> Previous', currentPage - 1, currentPage === 1, false, 'bls-page-link--prev'));
    
    // Generate page numbers
    let pages = [];
    if (totalPages <= 7) {
        for (let i = 1; i <= totalPages; i++) pages.push(i);
    } else {
        if (currentPage <= 4) {
            pages = [1, 2, 3, 4, 5, "...", totalPages];
        } else if (currentPage >= totalPages - 3) {
            pages = [1, "...", totalPages - 4, totalPages - 3, totalPages - 2, totalPages - 1, totalPages];
        } else {
            pages = [1, "...", currentPage - 1, currentPage, currentPage + 1, "...", totalPages];
        }
    }

    pages.forEach(p => {
        if (p === "...") {
            const li = document.createElement("li");
            li.className = "bls-page-item is-ellipsis";
            const span = document.createElement("span");
            span.className = "bls-page-link bls-page-link--num bls-page-link--ellipsis";
            span.innerHTML = "&hellip;";
            li.appendChild(span);
            paginationList.appendChild(li);
        } else {
            paginationList.appendChild(createLi(p.toString(), p, false, currentPage === p, 'bls-page-link--num'));
        }
    });
    
    // Next
    paginationList.appendChild(createLi('Next <i class="fas fa-chevron-right ml-1"></i>', currentPage + 1, currentPage === totalPages, false, 'bls-page-link--next'));
}

/**
 * Cập nhật thanh địa chỉ trình duyệt để tạo Share link
 */
function updateURL(url) {
    try {
        const params = new URLSearchParams(window.location.search);
        params.set('url', url);
        const newSearch = `?${params.toString()}`;
        const newURL = `${window.location.pathname}${newSearch}`;
        if (window.location.search !== newSearch) {
            window.history.pushState({ url }, '', newURL);
        }
    } catch (err) {
        console.warn("Lỗi cập nhật URL:", err);
    }
}
