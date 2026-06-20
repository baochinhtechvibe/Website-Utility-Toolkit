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
const SCAN_ENDPOINT   = `${BASE_API}/broken-link-scanner/scan`;        // legacy sync (kept)
const SUBMIT_ENDPOINT = `${BASE_API}/broken-link-scanner/scan/submit`;
const STATUS_ENDPOINT = `${BASE_API}/broken-link-scanner/scan/status`;

const state = {
    currentResults: [],
    filteredResults: [],
    abortController: null,
    currentFilter: "all",
    currentScope: "all",
    currentKind: "all",
    searchQuery: "",
    currentPage: 1,
    pageSize: 10,
    isScanning: false,
    scannedUrl: "",
    originHost: ""
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
    const validationCard = $("#bls-validation-error");

    function hideErrors() {
        errorCard?.classList.add("d-none");
        validationCard?.classList.add("d-none");
        urlInput.classList.remove("is-invalid");
    }
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
    const resultsTitle = $("#bls-results-title");

    const optSameHost = $("#bls-scope-same-host");
    const optIgnoreTls = $("#bls-ignore-tls");
    const workersInput = $("#bls-workers-input");
    const workersVal = $("#bls-worker-val");
    
    const maxDepthInput = $("#bls-max-depth");
    const maxPagesInput = $("#bls-max-pages");
    const maxLinksInput = $("#bls-max-links");

    const scanIcon = $("#bls-scan-icon");
    const scanLoadingState = $("#bls-scan-loading");
    const btnExportXlsx = $("#bls-btn-export-xlsx");

    // Slider Value Sync
    workersInput?.addEventListener("input", (e) => {
        if (workersVal) workersVal.textContent = e.target.value;
    });

    const hideResults = () => {
        resultsSection?.classList.add("d-none");
        errorCard?.classList.add("d-none");
        shareCard?.classList.add("d-none");
        emptyState?.classList.add("d-none");
        $("#bls-skipped-warning")?.classList.add("d-none");
    };

    // Realtime Validation
    if (urlInput && validationError && btnScan) {
        createRealtimeURLValidator(urlInput, validationError, btnScan);
        urlInput.addEventListener('input', () => {
            // Chỉ ẩn kết quả cũ, không đè lên thông báo của validator
            if (!validationError.classList.contains('d-none')) return;
            hideResults();
        });
    }

    // Cancel Scan
    btnCancel?.addEventListener('click', () => {
        state.abortController?.abort();
    });

    // Bypass Cache
    $("#btnBypassCache")?.addEventListener('click', () => performScan(true));

    // Copy Link & Export Excel: event listeners gắn bên dưới (tránh duplicate — GEMINI Rule #16)

    // Main Submit
    form?.addEventListener("submit", (e) => {
        e.preventDefault();
        performScan(false);
    });

    async function performScan(isBypassCache = false) {
        if (state.isScanning) return;
        hideErrors();

        let rawUrl = urlInput.value.trim();
        if (!rawUrl) return;

        // Auto-fix URL: Thêm https:// nếu thiếu (GEMINI Rule #67)
        if (!/^https?:\/\//i.test(rawUrl)) {
            rawUrl = 'https://' + rawUrl;
        }

        // Auto-fix: Thêm dấu "/" ở cuối nếu chỉ có domain (Ví dụ: https://naty.vn -> https://naty.vn/)
        try {
            const urlObj = new URL(rawUrl);
            if (urlObj.pathname === '/' && !rawUrl.endsWith('/')) {
                rawUrl += '/';
            }
            urlInput.value = rawUrl;
            // Kích hoạt lại validator để xóa lỗi đỏ
            urlInput.dispatchEvent(new Event('input'));
        } catch (e) {
            // kệ nó, nếu URL không hợp lệ thì để validator báo sau
        }

        state.isScanning = true;
        state.scannedUrl = rawUrl;
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
            btnExportXlsx?.setAttribute("disabled", "true");

            // ── Step 1: Submit job, returns {job_id} immediately ──────────────
            const submitRes = await fetch(SUBMIT_ENDPOINT, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    url: rawUrl,
                    scope: optSameHost?.checked ? "same-host" : "all",
                    maxWorkers: parseInt(workersInput?.value || "50", 10),
                    maxDepth: parseInt(maxDepthInput?.value || "2", 10),
                    maxPages: parseInt(maxPagesInput?.value || "50", 10),
                    maxLinks: parseInt(maxLinksInput?.value || "1000", 10),
                    ignoreTlsErrors: optIgnoreTls?.checked || false,
                    respectRobots: $("#bls-respect-robots")?.checked ?? true,
                    bypassCache: isBypassCache
                }),
                signal: state.abortController.signal
            });

            if (!submitRes.ok) {
                const errData = await submitRes.json();
                throw new Error(errData.message || `HTTP ${submitRes.status}`);
            }

            const submitData = await submitRes.json();

            // ── Cache hit: server returned full data immediately ──────────────
            if (submitData.cached && submitData.data) {
                await handleScanData(submitData, rawUrl, { cached: true, fetched_at: submitData.fetched_at });
                return;
            }

            // ── Step 2: Open SSE stream for live progress ─────────────────────
            const jobId = submitData.job_id;
            await listenJobSSE(jobId, rawUrl);

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
            if (state.currentResults.length > 0) {
                btnExportXlsx?.removeAttribute("disabled");
            } else {
                btnExportXlsx?.setAttribute("disabled", "true");
            }
        }
    }

    // ── SSE listener: streams progress events then final result ───────────
    function listenJobSSE(jobId, rawUrl) {
        return new Promise((resolve, reject) => {
            const url = `${STATUS_ENDPOINT}?job_id=${encodeURIComponent(jobId)}`;
            const es = new EventSource(url);

            // Allow cancel button to kill the stream AND notify server
            const prevAbort = state.abortController;
            if (prevAbort) {
                prevAbort.signal.addEventListener('abort', () => {
                    es.close();
                    fetch(`${BASE_API}/broken-link-scanner/scan/cancel`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ job_id: jobId }),
                        keepalive: true
                    }).catch(() => {}); // ignore errors on cancel
                    reject(new DOMException('Aborted', 'AbortError'));
                });
            }

            // Show progress bar
            if (progressBlock) {
                progressBlock.querySelector(".bls-progress-bar-track")?.classList.remove("d-none");
                progressBlock.querySelector(".bls-progress-meta")?.classList.remove("d-none");
            }

            es.addEventListener('progress', (e) => {
                try {
                    const ev = JSON.parse(e.data);
                    const done = ev.links_found || 0;
                    const label = progressBlock?.querySelector("span.font-bold");
                    if (label) label.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-2"></i> Đang quét... <strong>${ev.pages_crawled || 0}</strong> trang / <strong>${done}</strong> links tìm thấy`;

                    const pctEl = $("#bls-progress-pct");
                    const doneEl = $("#bls-progress-done");
                    if (pctEl) pctEl.textContent = `${done} links`;
                    if (doneEl) doneEl.textContent = done;
                } catch { /* ignore parse errors */ }
            });

            es.addEventListener('done', async (e) => {
                es.close();
                try {
                    const result = JSON.parse(e.data);
                    await handleScanData(result, rawUrl, { cached: false, fetched_at: new Date().toISOString() });
                    resolve();
                } catch (err) {
                    reject(err);
                }
            });

            es.addEventListener('scan_error', (e) => {
                es.close();
                try {
                    const errData = JSON.parse(e.data || '{}');
                    reject(new Error(errData.message || 'Quét thất bại. Vui lòng thử lại.'));
                } catch {
                    reject(new Error('Quét thất bại. Vui lòng thử lại.'));
                }
            });

            es.onerror = (e) => {
                if (es.readyState === EventSource.CLOSED) return; // already handled
                es.close();
                reject(new Error('Mất kết nối với máy chủ. Vui lòng thử lại.'));
            };
        });
    }

    // ── Render scan data after receiving final result ─────────────────────
    async function handleScanData(response, rawUrl, meta) {
        const scanData = response.data;

        // Update Result Title
        if (resultsTitle) {
            resultsTitle.innerHTML = `<i class="fa-solid fa-magnifying-glass-chart mr-2"></i> Báo cáo quét trên <span class="text-success">"${escapeHTML(rawUrl)}"</span>`;
        }

        const statCrawled = $("#bls-stat-crawled");
        const statTotal   = $("#bls-stat-total");
        const statUnique  = $("#bls-stat-unique");
        const statOk      = $("#bls-stat-ok");
        const statRedirect = $("#bls-stat-redirect");
        const statBroken  = $("#bls-stat-broken");
        const statBlocked = $("#bls-stat-blocked");
        const statTimeout = $("#bls-stat-timeout");

        if (statCrawled)  statCrawled.textContent  = scanData.summary?.pages_crawled  || 0;
        if (statTotal)    statTotal.textContent     = scanData.summary?.total          || 0;
        if (statUnique)   statUnique.textContent    = scanData.summary?.unique_targets || 0;
        if (statOk)       statOk.textContent        = scanData.summary?.ok             || 0;
        if (statRedirect) statRedirect.textContent  = scanData.summary?.redirect       || 0;
        if (statBroken)   statBroken.textContent    = scanData.summary?.broken         || 0;
        if (statBlocked)  statBlocked.textContent   = scanData.summary?.blocked        || 0;
        if (statTimeout)  statTimeout.textContent   = scanData.summary?.timeout        || 0;

        state.currentResults = scanData.results || [];
        state.currentPage = 1;

        // Extract origin host for Internal/External classification
        try {
            state.originHost = new URL(scanData.final_page_url || rawUrl).hostname;
        } catch { state.originHost = ""; }

        // Handle Skipped Links Warning
        const skippedWarning = $("#bls-skipped-warning");
        const hasOverLimit  = scanData.summary?.skipped_over_limit  > 0;
        const hasOutOfScope = scanData.summary?.skipped_out_of_scope > 0;
        const limitReached  = scanData.summary?.limit_reached || false;

        if (skippedWarning && (hasOverLimit || hasOutOfScope || limitReached)) {
            skippedWarning.classList.remove("d-none");
            const overLimitRow   = $("#bls-skipped-over-limit-row");
            const overLimitCount = $("#bls-skipped-count");
            if ((hasOverLimit || limitReached) && overLimitRow && overLimitCount) {
                overLimitRow.classList.remove("d-none");
                const overLimitText = $("#bls-skipped-over-limit-text");
                if (hasOverLimit) {
                    overLimitCount.textContent = scanData.summary?.skipped_over_limit || 0;
                    overLimitText?.classList.remove("d-none");
                } else {
                    overLimitText?.classList.add("d-none");
                }
            } else {
                overLimitRow?.classList.add("d-none");
            }
            const outScopeRow   = $("#bls-skipped-out-scope-row");
            const outScopeCount = $("#bls-skipped-scope-count");
            if (hasOutOfScope && outScopeRow && outScopeCount) {
                outScopeCount.textContent = scanData.summary.skipped_out_of_scope;
                outScopeRow.classList.remove("d-none");
            } else {
                outScopeRow?.classList.add("d-none");
            }
        } else {
            skippedWarning?.classList.add("d-none");
        }

        renderTable("all");

        // Cache Banner — use meta passed in from SSE/cache-hit path
        const cacheNotice = $("#cacheNotice");
        if (cacheNotice && meta?.fetched_at) {
            const timeStr = new Date(meta.fetched_at).toLocaleString('vi-VN');
            const spanEl = cacheNotice.querySelector("span");
            if (spanEl) {
                if (meta.cached) {
                    spanEl.innerHTML = `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b id="cacheTime">${timeStr}</b>`;
                } else {
                    spanEl.innerHTML = `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b id="cacheTime">${timeStr}</b>`;
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
    }

    function isInternal(row) {
        if (!state.originHost || !row.final_url) return false;
        try {
            const targetHost = new URL(row.final_url).hostname;
            return targetHost.toLowerCase() === state.originHost.toLowerCase();
        } catch { return false; }
    }

    function isResource(row) {
        const resourceKinds = ["<img>", "<script>", "<link>", '<link rel="stylesheet">', "CSS", "CSS_IMPORT", "<video>", "<audio>", "<source>", "<track>", "<embed>", "<object>"];
        return resourceKinds.some(k => row.kind === k || row.kind.includes("style") || row.kind.includes("CSS"));
    }

    // Sort priority: broken > blocked > timeout > redirect > ok
    const statusPriority = { broken: 0, blocked: 1, timeout: 2, redirect: 3, ok: 4 };

    function renderTable(filter) {
        if (!tbody) return;
        tbody.innerHTML = "";
        state.currentFilter = filter;

        const searchLower = state.searchQuery.toLowerCase();

        const filtered = state.currentResults.filter(r => {
            // Status filter
            if (filter !== "all" && r.status_class !== filter) return false;
            // Scope filter
            if (state.currentScope !== "all") {
                const internal = isInternal(r);
                if (state.currentScope === "internal" && !internal) return false;
                if (state.currentScope === "external" && internal) return false;
            }
            // Kind filter
            if (state.currentKind !== "all") {
                const resource = isResource(r);
                if (state.currentKind === "resource" && !resource) return false;
                if (state.currentKind === "page" && resource) return false;
            }
            // Search filter
            if (searchLower) {
                const inTarget = (r.final_url || "").toLowerCase().includes(searchLower);
                const inOriginal = (r.original_url || "").toLowerCase().includes(searchLower);
                const inSource = (r.source_page || "").toLowerCase().includes(searchLower);
                if (!inTarget && !inOriginal && !inSource) return false;
            }
            return true;
        }).sort((a, b) => {
            const pa = statusPriority[a.status_class] ?? 99;
            const pb = statusPriority[b.status_class] ?? 99;
            return pa - pb;
        });
        
        state.filteredResults = filtered;
        const total = filtered.length;

        if (total === 0) {
            emptyState?.classList.remove("d-none");
            document.querySelector(".bls-table-wrapper")?.classList.add("d-none");
            $("#bls-pagination-container")?.classList.add("d-none");
            btnExportXlsx?.setAttribute("disabled", "true");
            return;
        }

        emptyState?.classList.add("d-none");
        document.querySelector(".bls-table-wrapper")?.classList.remove("d-none");
        btnExportXlsx?.removeAttribute("disabled");
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
            let kindIcon = "fa-arrow-pointer"; // Mặc định cho thẻ <a> (Anchor)
            if (kindLower.includes("img")) kindIcon = "fa-image";
            else if (kindLower.includes("script")) kindIcon = "fa-code";
            else if (kindLower.includes("style") || kindLower.includes("link")) kindIcon = "fa-link";
            else if (kindLower.includes("iframe")) kindIcon = "fa-window-maximize";

            const redirectInfo = row.redirect_count > 0
                ? `<div class="bls-redirect-info text-warning mt-1"><i class="fa-solid fa-arrow-right-arrow-left"></i> ${row.redirect_count} chuyển hướng</div>`
                : "";

            // Point #52: XSS Prevention for dynamic links
            const safeFinalUrl = isSafeURL(row.final_url) ? row.final_url : "#";
            // Dùng final_url (absolute) cho href, original_url chỉ để hiển thị text
            const linkHref = safeFinalUrl !== "#" ? safeFinalUrl : (isSafeURL(row.original_url) ? row.original_url : "#");

            const safeSourcePage = isSafeURL(row.source_page) ? row.source_page : "#";
            const sourcePageHtml = row.source_page 
                ? `<div class="mt-1 text-muted text-sm"><i class="fa-solid fa-file-lines mr-1"></i>Từ trang: <a href="${escapeHTML(safeSourcePage)}" target="_blank" rel="noopener noreferrer" class="text-muted">${escapeHTML(row.source_page)}</a></div>` 
                : "";

            tr.innerHTML = `
                <td>
                    <span class="badge ${badgeClass}">
                        <strong>${row.status_code || "???"}</strong> <span class="ml-1 font-normal">${row.status_text || row.status_class}</span>
                    </span>
                </td>
                <td>
                    <div class="badge badge-default bls-tag-item">
                        <i class="fa-solid ${kindIcon}"></i>
                        <span>${escapeHTML(row.kind)}</span>
                    </div>
                </td>
                <td class="bls-url-cell">
                    <div class="bls-url-main">
                        <a href="${escapeHTML(linkHref)}" target="_blank" rel="noopener noreferrer">
                            ${row.error ? `<span class="text-error">${escapeHTML(row.original_url)} <br/><small class="text-muted"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeHTML(row.error)}</small></span>` : escapeHTML(row.original_url)}
                        </a>
                    </div>
                    ${row.redirect_count > 0 ? `
                    <div class="bls-url-parent text-muted">
                        <i class="fa-solid fa-arrow-right-long mr-1"></i> 
                        <a href="${escapeHTML(safeFinalUrl)}" target="_blank" rel="noopener noreferrer" class="text-muted">${escapeHTML(row.final_url)}</a>
                    </div>
                    ` : ''}
                    ${sourcePageHtml}
                </td>
                <td>
                    <div class="bls-latency text-right">
                        ${redirectInfo}
                        <div class="bls-time font-mono text-muted text-sm"><i class="fa-regular fa-clock opacity-50 mr-1"></i> ${row.response_ms || 0} ms</div>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });
        renderPagination(total);
    }

    function isSafeURL(s) {
        if (!s) return false;
        // Cho phép URL tương đối hợp lệ (bắt đầu bằng /)
        if (s.startsWith('/') && !s.startsWith('//')) return true;
        try {
            const u = new URL(s);
            // Point #7: Chặn URLs có embedded credentials: http://user:pass@evil.com
            if (u.username || u.password) return false;
            // Strict check: Chỉ cho phép http và https cho website bên ngoài (GEMINI Rule #52)
            return u.protocol === 'http:' || u.protocol === 'https:';
        } catch {
            return false; // Reject all relative paths or invalid protocols
        }
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

    const statMappings = {
        "bls-stat--ok": "ok",
        "bls-stat--redirect": "redirect",
        "bls-stat--broken": "broken",
        "bls-stat--blocked": "blocked",
        "bls-stat--timeout": "timeout"
    };

    Object.keys(statMappings).forEach(className => {
        const el = document.querySelector(`.${className}`);
        if (el) {
            el.onclick = () => {
                const filter = statMappings[className];
                const targetBtn = document.querySelector(`.btn-filter[data-filter="${filter}"]`);
                if (targetBtn) targetBtn.click();
            };
        }
    });

    // Scope Filter Dropdown
    const scopeFilter = $("#bls-scope-filter");
    scopeFilter?.addEventListener("change", (e) => {
        state.currentScope = e.target.value;
        state.currentPage = 1;
        renderTable(state.currentFilter);
    });

    // Kind Filter Dropdown
    const kindFilter = $("#bls-kind-filter");
    kindFilter?.addEventListener("change", (e) => {
        state.currentKind = e.target.value;
        state.currentPage = 1;
        renderTable(state.currentFilter);
    });

    // Search Input
    const searchInput = $("#bls-search-input");
    let searchDebounce = null;
    searchInput?.addEventListener("input", (e) => {
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => {
            state.searchQuery = e.target.value.trim();
            state.currentPage = 1;
            renderTable(state.currentFilter);
        }, 250);
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

    // XLSX Export
    btnExportXlsx?.addEventListener("click", () => {
        if (state.filteredResults && state.filteredResults.length > 0) {
            exportXLSX(state.filteredResults, state.scannedUrl);
        }
    });

    // Share link copy
    btnCopyLink?.addEventListener('click', () => {
        if (shareLink) copyToClipboard(shareLink.value, btnCopyLink);
    });

    // Handle initial URL params
    const params = new URLSearchParams(window.location.search);
    const pUrl = params.get('url');
    if (pUrl && urlInput) {
        const val = decodeURIComponent(pUrl);
        urlInput.value = val;
        // Trực tiếp kiểm tra tính hợp lệ và trigger scan thay vì dùng setTimeout 100ms
        if (/^https?:\/\//i.test(val)) {
            performScan(false);
        }
    }
}

/**
 * Xuất dữ liệu ra file Excel (.xlsx) với định dạng và màu sắc chuyên nghiệp.
 * Sử dụng thư viện xlsx-js-style.
 */
function exportXLSX(results, url) {
    if (!window.XLSX) {
        console.error("xlsx-js-style library not found.");
        return;
    }

    const filename = `broken_links_${new Date().toISOString().substring(0, 10)}.xlsx`;
    const wb = XLSX.utils.book_new();

    // --- SHEET 1: TỔNG QUAN ---
    const summaryData = [
        ["BÁO CÁO QUÉT LIÊN KẾT HỎNG (BROKEN LINK SCANNER)"],
        ["URL quét:", url],
        ["Ngày thực hiện:", new Date().toLocaleString("vi-VN")],
        [""],
        ["THỐNG KÊ TỔNG QUÁT"],
        ["Trạng thái", "Số lượng", "Mô tả"],
        ["Hoạt động (OK)", results.filter(r => r.status_class === "ok").length, "Các liên kết trả về mã 2xx"],
        ["Điều hướng (Redirect)", results.filter(r => r.status_class === "redirect").length, "Các liên kết trả về mã 3xx"],
        ["Lỗi (Broken)", results.filter(r => r.status_class === "broken").length, "Các liên kết trả về mã 4xx/5xx hoặc lỗi kết nối"],
        ["Bị chặn (Blocked)", results.filter(r => r.status_class === "blocked").length, "Máy chủ mục tiêu từ chối truy cập (403/401)"],
        ["Hết thời gian (Timeout)", results.filter(r => r.status_class === "timeout").length, "Máy chủ không phản hồi kịp thời"],
        ["TỔNG CỘNG", results.length, ""]
    ];

    const wsSummary = XLSX.utils.aoa_to_sheet(summaryData);

    // Tính toán độ rộng cột tự động cho Sheet Tổng quan
    const summaryColWidths = [{ wch: 25 }, { wch: 15 }, { wch: 50 }]; // Mặc định cơ bản
    summaryData.forEach((row, rowIndex) => {
        // Bỏ qua dòng tiêu đề dài để không làm giãn cột A quá lố
        if (rowIndex === 0) return;
        row.forEach((cell, colIdx) => {
            if (cell !== undefined && cell !== null) {
                const len = cell.toString().length + 4; // Thêm padding
                if (summaryColWidths[colIdx] && len > summaryColWidths[colIdx].wch) {
                    summaryColWidths[colIdx].wch = Math.min(len, 80); // Giới hạn max 80 ký tự
                }
            }
        });
    });
    wsSummary["!cols"] = summaryColWidths;

    // Styling cho Sheet Tổng quan
    wsSummary["A1"].s = { font: { bold: true, sz: 16, color: { rgb: "2E7D32" } } };
    
    const headerStyle = {
        font: { bold: true, color: { rgb: "FFFFFF" } },
        fill: { fgColor: { rgb: "444444" } },
        alignment: { horizontal: "center" },
        border: { top: { style: "thin" }, bottom: { style: "thin" }, left: { style: "thin" }, right: { style: "thin" } }
    };
    
    ["A6", "B6", "C6"].forEach(ref => { if (wsSummary[ref]) wsSummary[ref].s = headerStyle; });

    // --- SHEET 2: CHI TIẾT ---
    const headers = ["Trạng thái", "Mã HTTP", "Loại thẻ", "Nguồn (Source Page)", "Redirects", "URL Đích (Final)", "URL Gốc (Original)", "Độ trễ (ms)", "Lỗi chi tiết"];
    const rows = results.map(r => [
        r.status_class.toUpperCase(),
        r.status_code || "-",
        r.kind,
        r.source_page || "",
        r.redirect_count || 0,
        r.final_url,
        r.original_url,
        r.response_ms || 0,
        r.error || ""
    ]);

    const wsDetails = XLSX.utils.aoa_to_sheet([headers, ...rows]);

    // Tính toán độ rộng cột tự động cho Sheet Chi tiết
    const detailColWidths = headers.map(h => ({ wch: h.length + 5 }));
    rows.forEach(row => {
        row.forEach((cell, colIdx) => {
            if (cell !== undefined && cell !== null) {
                const len = cell.toString().length + 4; // Thêm padding
                if (len > detailColWidths[colIdx].wch) {
                    detailColWidths[colIdx].wch = Math.min(len, 100); // Giới hạn max 100 ký tự để không bị tràn màn hình quá dài
                }
            }
        });
    });
    wsDetails["!cols"] = detailColWidths;

    // Filter và Freeze
    wsDetails["!autofilter"] = { ref: `A1:I${rows.length + 1}` };
    wsDetails["!views"] = [{ state: "frozen", ySplit: 1 }];

    // Styling Headers chi tiết
    const detailHeaderStyle = {
        font: { bold: true, color: { rgb: "FFFFFF" } },
        fill: { fgColor: { rgb: "1976D2" } }, // Blue Primary
        alignment: { horizontal: "center", vertical: "center" }
    };

    const alphabet = "ABCDEFGHI";
    for (let i = 0; i < alphabet.length; i++) {
        const cellRef = alphabet[i] + "1";
        if (wsDetails[cellRef]) wsDetails[cellRef].s = detailHeaderStyle;
    }

    // Styling Rows theo mức độ lỗi
    rows.forEach((row, index) => {
        const rowIndex = index + 2;
        const statusClass = row[0].toLowerCase();
        
        let rowColor = null;
        if (statusClass === "broken" || statusClass === "blocked") rowColor = "FFEBEE"; // Red-50
        else if (statusClass === "redirect") rowColor = "FFFDE7"; // Yellow-50
        else if (statusClass === "timeout") rowColor = "E3F2FD"; // Blue-50

        if (rowColor) {
            for (let i = 0; i < alphabet.length; i++) {
                const cellRef = alphabet[i] + rowIndex;
                if (wsDetails[cellRef]) {
                    wsDetails[cellRef].s = {
                        fill: { fgColor: { rgb: rowColor } },
                        border: { bottom: { style: "thin", color: { rgb: "EEEEEE" } } }
                    };
                }
            }
        }
    });

    // Hàm áp dụng font mặc định (Cambria, size 13) cho TẤT CẢ các ô
    const applyDefaultFont = (ws) => {
        for (const key in ws) {
            if (!key.startsWith('!')) { // Bỏ qua các key hệ thống của XLSX
                if (!ws[key].s) ws[key].s = {};
                if (!ws[key].s.font) ws[key].s.font = {};
                
                ws[key].s.font.name = "Cambria"; // Đặt font Cambria
                if (!ws[key].s.font.sz) ws[key].s.font.sz = 13; // Đặt size 13 nếu chưa có size riêng (như tiêu đề 16)
            }
        }
    };

    applyDefaultFont(wsSummary);
    applyDefaultFont(wsDetails);

    XLSX.utils.book_append_sheet(wb, wsSummary, "Tổng quan");
    XLSX.utils.book_append_sheet(wb, wsDetails, "Chi tiết liên kết");

    XLSX.writeFile(wb, filename);
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
