import { API_BASE_URL } from '../../config.js';
import { $, createRealtimeURLValidator, escapeHTML, copyToClipboard } from '../../utils/index.js';

// Dynamic API Resolver
const resolveApiBase = () => {
    if (window.location.protocol === 'file:') return API_BASE_URL;
    if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
        return window.location.origin + "/api";
    }
    return API_BASE_URL;
};

const BASE_API = resolveApiBase();
const SCAN_ENDPOINT = `${BASE_API}/broken-link-scanner/scan`;

const state = {
    currentResults: [],
    abortController: null,
    currentFilter: "all",
    currentPage: 1,
    pageSize: 10,
    isScanning: false
};

function init() {
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

    const statTotal = $("#bls-stat-total");
    const statOk = $("#bls-stat-ok");
    const statRedirect = $("#bls-stat-redirect");
    const statBroken = $("#bls-stat-broken");
    const statBlocked = $("#bls-stat-blocked");
    const statTimeout = $("#bls-stat-timeout");

    const tbody = $("#bls-results-body");

    const optSameHost = $("#bls-scope-same-host");
    const optIgnoreTls = $("#bls-ignore-tls");
    const workersInput = $("#bls-workers-input");
    const workersVal = $("#bls-worker-val");

    const scanIcon = $("#bls-scan-icon");
    const scanLoadingState = $("#bls-scan-loading");

    // Slider Value Sync
    workersInput?.addEventListener("input", (e) => {
        if (workersVal) workersVal.textContent = e.target.value;
    });

    const hideResults = () => {
        resultsSection?.classList.add("d-none");
        errorCard?.classList.add("d-none");
        shareCard?.classList.add("d-none");
        emptyState?.classList.add("d-none");
    };

    // Realtime Validation
    if (urlInput && validationError && btnScan) {
        createRealtimeURLValidator(urlInput, validationError, btnScan);
        urlInput.addEventListener('input', hideResults);
    }

    // Cancel Scan
    btnCancel?.addEventListener('click', () => {
        state.abortController?.abort();
    });

    // Bypass Cache
    $("#btnBypassCache")?.addEventListener('click', () => performScan(true));

    // Main Submit
    form?.addEventListener("submit", (e) => {
        e.preventDefault();
        performScan(false);
    });

    async function performScan(isBypassCache = false) {
        if (state.isScanning) return;
        const rawUrl = urlInput.value.trim();
        if (!rawUrl) return;

        state.isScanning = true;
        updateURL(rawUrl);

        hideResults();

        if (progressBlock) {
            progressBlock.classList.remove("d-none");
            progressBlock.querySelector(".bls-progress-bar-track")?.classList.add("d-none");
            progressBlock.querySelector(".bls-progress-meta")?.classList.add("d-none");
            const progressLabel = progressBlock.querySelector("span.font-bold");
            if (progressLabel) progressLabel.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i> Đang thu thập và phân tích liên kết...';
        }

        btnScan.disabled = true;
        scanIcon?.classList.add("d-none");
        scanLoadingState?.classList.remove("d-none");
        if (tbody) tbody.innerHTML = "";
        state.currentResults = [];
        state.abortController = new AbortController();

        try {
            const response = await fetch(SCAN_ENDPOINT, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    url: rawUrl,
                    scope: optSameHost?.checked ? "same-host" : "all",
                    maxWorkers: parseInt(workersInput?.value || "50", 10),
                    ignoreTlsErrors: optIgnoreTls?.checked || false,
                    bypassCache: isBypassCache
                }),
                signal: state.abortController.signal
            });

            const data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.message || `HTTP ${response.status}`);

            const scanData = data.data;
            if (statTotal) statTotal.textContent = scanData.summary?.total || 0;
            if (statOk) statOk.textContent = scanData.summary?.ok || 0;
            if (statRedirect) statRedirect.textContent = scanData.summary?.redirect || 0;
            if (statBroken) statBroken.textContent = scanData.summary?.broken || 0;
            if (statBlocked) statBlocked.textContent = scanData.summary?.blocked || 0;
            if (statTimeout) statTimeout.textContent = scanData.summary?.timeout || 0;

            state.currentResults = scanData.results || [];
            state.currentPage = 1;
            renderTable("all");

            // Cache Banner
            const cacheNotice = $("#cacheNotice");
            if (cacheNotice && data.meta?.fetched_at) {
                const timeStr = new Date(data.meta.fetched_at).toLocaleString('vi-VN');
                const spanEl = cacheNotice.querySelector("span");
                if (spanEl) {
                    if (data.meta.cached) {
                        spanEl.innerHTML = `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b id="cacheTime">${timeStr}</b>.`;
                    } else {
                        spanEl.innerHTML = `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b id="cacheTime">${timeStr}</b>.`;
                    }
                }
                cacheNotice.classList.remove('d-none');
                cacheNotice.classList.add('d-flex');
            } else {
                cacheNotice?.classList.add('d-none');
                cacheNotice?.classList.remove('d-flex');
            }

            resultsSection?.classList.remove("d-none");
            if (shareCard) {
                shareCard.classList.remove("d-none");
                if (shareLink) shareLink.value = window.location.href;
            }
        } catch (err) {
            if (err.name !== 'AbortError') {
                if (errorMessage) errorMessage.textContent = err.message;
                errorCard?.classList.remove("d-none");
            }
        } finally {
            progressBlock?.classList.add("d-none");
            state.isScanning = false;
            btnScan.disabled = false;
            scanIcon?.classList.remove("d-none");
            scanLoadingState?.classList.add("d-none");
            state.abortController = null;
        }
    }

    function renderTable(filter) {
        if (!tbody) return;
        tbody.innerHTML = "";
        state.currentFilter = filter;

        const filtered = state.currentResults.filter(r => filter === "all" || r.status_class === filter);
        const total = filtered.length;

        if (total === 0) {
            emptyState?.classList.remove("d-none");
            document.querySelector(".bls-table-wrapper")?.classList.add("d-none");
            $("#bls-pagination-container")?.classList.add("d-none");
            return;
        }

        emptyState?.classList.add("d-none");
        document.querySelector(".bls-table-wrapper")?.classList.remove("d-none");
        const paginationContainer = $("#bls-pagination-container");
        paginationContainer?.classList.remove("d-none");

        let start = 0, end = total;
        if (state.pageSize !== "all") {
            const pages = Math.ceil(total / state.pageSize);
            if (state.currentPage > pages) state.currentPage = pages;
            start = (state.currentPage - 1) * state.pageSize;
            end = Math.min(start + state.pageSize, total);
        }

        $("#bls-page-start").textContent = total === 0 ? 0 : start + 1;
        $("#bls-page-end").textContent = end;
        $("#bls-page-total-items").textContent = total;

        filtered.slice(start, end).forEach(row => {
            const tr = document.createElement("tr");
            
            // Map status_class to project badges
            let badgeClass = "badge-default";
            if (row.status_class === "ok") badgeClass = "badge-success";
            else if (row.status_class === "broken" || row.status_class === "blocked") badgeClass = "badge-error";
            else if (row.status_class === "redirect") badgeClass = "badge-warning";
            else if (row.status_class === "timeout") badgeClass = "badge-info";

            // Map Kind to Icons
            const kindLower = row.kind.toLowerCase();
            let kindIcon = "fa-link";
            if (kindLower.includes("img")) kindIcon = "fa-image";
            else if (kindLower.includes("script")) kindIcon = "fa-code";
            else if (kindLower.includes("style")) kindIcon = "fa-css3";
            else if (kindLower.includes("iframe")) kindIcon = "fa-window-maximize";

            const redirectInfo = row.redirect_count > 0 
                ? `<div class="bls-redirect-info text-warning mt-1" style="font-size: 0.75rem;"><i class="fa-solid fa-arrow-right-arrow-left"></i> ${row.redirect_count} chuyển hướng</div>` 
                : "";
            
            tr.innerHTML = `
                <td>
                    <span class="badge ${badgeClass} uppercase">
                        <strong>${row.status_code || "???"}</strong> <span class="ml-1 font-normal">${row.status_class}</span>
                    </span>
                </td>
                <td>
                    <div class="bls-tag-item">
                        <i class="fa-solid ${kindIcon}"></i>
                        <span class="uppercase">${escapeHTML(row.kind)}</span>
                    </div>
                </td>
                <td class="bls-url-cell">
                    <div class="bls-url-main">
                        <a href="${escapeHTML(row.final_url)}" target="_blank">
                            ${row.error ? `<span class="text-error">${escapeHTML(row.final_url)} <br/><small class="text-muted"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHTML(row.error)}</small></span>` : escapeHTML(row.final_url)}
                        </a>
                    </div>
                    <div class="bls-url-parent text-muted"><i class="fa-solid fa-share fa-rotate-90 mr-1 opacity-50"></i> ${escapeHTML(row.original_url)}</div>
                </td>
                <td>
                    <div class="bls-latency text-right">
                        ${redirectInfo}
                        <div class="bls-time font-mono text-muted text-sm"><i class="fa-regular fa-clock opacity-70 mr-1"></i> ${row.response_ms || 0} ms</div>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });
        renderPagination(total);
    }

    function renderPagination(total) {
        const list = $("#bls-pagination-list");
        if (!list) return;
        list.innerHTML = "";
        if (state.pageSize === "all" || total <= state.pageSize) return;

        const totalPages = Math.ceil(total / state.pageSize);
        const createLi = (html, page, disabled, active, extra = "") => {
            const li = document.createElement("li");
            li.className = `bls-page-item ${disabled ? 'is-disabled' : ''} ${active ? 'is-active' : ''}`;
            const btn = document.createElement("button");
            btn.className = `bls-page-link ${extra}`;
            btn.innerHTML = html;
            btn.type = "button";
            btn.title = `Chuyển tới trang ${page}`;
            if (!disabled && !active) {
                btn.onclick = () => {
                    state.currentPage = page;
                    renderTable(state.currentFilter);
                    resultsSection?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                };
            }
            li.appendChild(btn);
            return li;
        };

        // Previous Button
        list.appendChild(createLi('<i class="fa-solid fa-chevron-left"></i>', state.currentPage - 1, state.currentPage === 1, false, 'bls-page-link--prev'));
        
        let pages = [];
        if (totalPages <= 5) {
            for (let i = 1; i <= totalPages; i++) pages.push(i);
        } else {
            if (state.currentPage <= 2) {
                pages = [1, 2, "...", totalPages];
            } else if (state.currentPage >= totalPages - 1) {
                pages = [1, "...", totalPages - 1, totalPages];
            } else {
                pages = [1, "...", state.currentPage, "...", totalPages];
            }
        }

        pages.forEach(p => {
            if (p === "...") {
                const li = document.createElement("li");
                li.className = "bls-page-item is-ellipsis";
                li.innerHTML = '<span class="bls-page-link bls-page-link--ellipsis">&hellip;</span>';
                list.appendChild(li);
            } else {
                list.appendChild(createLi(p.toString(), p, false, state.currentPage === p, 'bls-page-link--num'));
            }
        });

        // Next Button
        list.appendChild(createLi('<i class="fa-solid fa-chevron-right"></i>', state.currentPage + 1, state.currentPage === totalPages, false, 'bls-page-link--next'));
    }

    // Filter Buttons
    document.querySelectorAll(".btn-filter").forEach(btn => {
        btn.onclick = (e) => {
            document.querySelectorAll(".btn-filter").forEach(b => b.classList.remove("is-active"));
            e.currentTarget.classList.add("is-active");
            state.currentPage = 1;
            renderTable(e.currentTarget.dataset.filter);
        };
    });

    // Page Size Buttons
    document.querySelectorAll(".btn-size").forEach(btn => {
        btn.onclick = (e) => {
            document.querySelectorAll(".btn-size").forEach(b => b.classList.remove("is-active"));
            e.currentTarget.classList.add("is-active");
            const size = e.currentTarget.dataset.size;
            state.pageSize = size === "all" ? "all" : parseInt(size, 10);
            state.currentPage = 1;
            renderTable(state.currentFilter);
        };
    });

    // CSV Export
    $("#bls-btn-export-csv")?.addEventListener("click", () => {
        if (state.currentResults.length === 0) return;
        const headers = ["Khởi nguồn thẻ", "Phân loại Thẻ", "Đường dẫn gốc", "Đường dẫn Final", "Mã HTTP", "Status Class", "Độ trễ (ms)", "Ghi chú Lỗi"];
        const csv = [headers.join(","), ...state.currentResults.map(r => [
            `"${(r.source_tag || "").replace(/"/g, '""')}"`, r.kind, `"${r.original_url}"`, `"${r.final_url}"`,
            r.status_code, r.status_class, r.response_ms || 0, `"${(r.error || "").replace(/"/g, '""')}"`
        ].join(","))].join("\n");
        const blob = new Blob(["\uFEFF" + csv], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = `broken_links_${new Date().toISOString().substring(0, 10)}.csv`;
        link.click();
    });

    // Share link copy
    btnCopyLink?.addEventListener('click', () => {
        if (shareLink) copyToClipboard(shareLink.value, btnCopyLink);
    });

    // Handle initial URL params
    const params = new URLSearchParams(window.location.search);
    const pUrl = params.get('url');
    if (pUrl && urlInput) {
        urlInput.value = decodeURIComponent(pUrl);
        urlInput.dispatchEvent(new Event('input'));
        setTimeout(() => { if (!btnScan.disabled) performScan(false); }, 100);
    }
}

function updateURL(url) {
    const params = new URLSearchParams(window.location.search);
    params.set('url', url);
    const newURL = `${window.location.pathname}?${params.toString()}`;
    if (window.location.search !== `?${params.toString()}`) {
        window.history.pushState({ url }, '', newURL);
    }
}

document.addEventListener('DOMContentLoaded', init);
