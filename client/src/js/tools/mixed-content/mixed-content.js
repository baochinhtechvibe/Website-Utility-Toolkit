// =================================//
//  MIXED CONTENT SCANNER — MAIN JS
//==================================//
import {
    /* dom.js */
    $,
    setDisplay,
    toggleLoading,
    setElementsEnabled,
    createRealtimeDomainValidator,

    /* format.js */
    escapeHTML,
    normalizeURLInput,
} from "../../utils/index.js";
import { API_BASE_URL } from "../../config.js";

// ─── State ────────────────────────────────────────────────────────────────────
const state = {
    currentResults: [],
    currentPage: 1,
    pageSize: 10,
    currentFilter: "all",
    scannedUrl: ""
};

// ─── Utils ────────────────────────────────────────────────────────────────────

function getSeverityBadge(type) {
    if (type === "Active") {
        return `<span class="badge badge-error badge-sm uppercase"><i class="fa-solid fa-circle-xmark mr-1"></i> CRITICAL</span>`;
    }
    if (type === "Info") {
        return `<span class="badge badge-info badge-sm uppercase"><i class="fa-solid fa-info-circle mr-1"></i> INFO</span>`;
    }
    return `<span class="badge badge-warning badge-sm uppercase"><i class="fa-solid fa-triangle-exclamation mr-1"></i> WARNING</span>`;
}

function safeHref(url) {
    const lower = (url || "").toLowerCase().trim();
    if (lower.startsWith("http://") || lower.startsWith("https://")) {
        return escapeHTML(url);
    }
    return "#";
}

function getOriginBadge(origin) {
    if (origin === "same-domain") {
        return `<span class="badge badge-success badge-sm">Nội bộ</span>`;
    }
    return `<span class="badge badge-error badge-sm">Bên thứ 3</span>`;
}

function getSubtypeBadge(subtype) {
    return `<span class="badge badge-info badge-circle text-xs lowercase">${escapeHTML(subtype)}</span>`;
}

// ─── Export XLSX (styled) ────────────────────────────────────────────────────
function exportXLSX(items, scannedUrl) {
    // eslint-disable-next-line no-undef
    const XLSX = window.XLSX;
    if (!XLSX) {
        console.error("XLSX library not loaded");
        return;
    }

    let hostname = "scan";
    try {
        hostname = new URL(scannedUrl).hostname;
    } catch (e) {
        console.warn("Invalid URL for XLSX filename", e);
    }

    // ─── Styles ───────────────────────────────────────────────────────────
    const border = {
        top: { style: "thin", color: { rgb: "D0D5DD" } },
        bottom: { style: "thin", color: { rgb: "D0D5DD" } },
        left: { style: "thin", color: { rgb: "D0D5DD" } },
        right: { style: "thin", color: { rgb: "D0D5DD" } },
    };

    const headerStyle = {
        font: { bold: true, color: { rgb: "FFFFFF" }, sz: 11 },
        fill: { fgColor: { rgb: "1A56DB" } },
        alignment: { horizontal: "center", vertical: "center", wrapText: true },
        border,
    };

    const rowStyles = {
        Active: { fill: { fgColor: { rgb: "FEE2E2" } }, font: { color: { rgb: "991B1B" }, sz: 10 } },
        Passive: { fill: { fgColor: { rgb: "FEF3C7" } }, font: { color: { rgb: "92400E" }, sz: 10 } },
        Info: { fill: { fgColor: { rgb: "DBEAFE" } }, font: { color: { rgb: "1E40AF" }, sz: 10 } },
    };

    const defaultRowFont = { sz: 10, color: { rgb: "344054" } };

    // ─── Sheet 1: Chi tiết ────────────────────────────────────────────────
    const headers = ["#", "Mức độ", "Loại tài nguyên", "Vị trí (Tag)", "URL HTTP", "Gợi ý Fix (HTTPS)", "Nguồn gốc"];
    const wsData = [];

    // Header row
    wsData.push(headers.map(h => ({ v: h, s: headerStyle })));

    // Data rows
    items.forEach((item, idx) => {
        const style = rowStyles[item.type] || {};
        const font = style.font || defaultRowFont;
        const fill = style.fill || { fgColor: { rgb: "FFFFFF" } };

        const cellStyle = { font, fill, border, alignment: { vertical: "center", wrapText: true } };
        const centerStyle = { ...cellStyle, alignment: { ...cellStyle.alignment, horizontal: "center" } };

        wsData.push([
            { v: idx + 1, s: centerStyle },
            { v: item.type.toUpperCase(), s: centerStyle },
            { v: item.subtype, s: centerStyle },
            { v: item.foundIn, s: centerStyle },
            { v: item.url, s: cellStyle },
            { v: item.fixSuggestion, s: cellStyle },
            { v: item.origin === "same-domain" ? "Nội bộ" : "Bên thứ 3", s: centerStyle },
        ]);
    });

    const ws = XLSX.utils.aoa_to_sheet(wsData);

    // Auto-width
    ws["!cols"] = [
        { wch: 5 },   // #
        { wch: 12 },  // Mức độ
        { wch: 16 },  // Loại
        { wch: 14 },  // Tag
        { wch: 55 },  // URL
        { wch: 55 },  // Fix
        { wch: 14 },  // Nguồn gốc
    ];

    // Freeze header
    ws["!freeze"] = { xSplit: 0, ySplit: 1 };

    // Auto-filter
    ws["!autofilter"] = { ref: `A1:G${items.length + 1}` };

    // ─── Sheet 2: Tổng quan ───────────────────────────────────────────────
    const activeCount = items.filter(i => i.type === "Active").length;
    const passiveCount = items.filter(i => i.type === "Passive").length;
    const infoCount = items.filter(i => i.type === "Info").length;

    const titleStyle = { font: { bold: true, sz: 13, color: { rgb: "1A56DB" } } };
    const labelStyle = { font: { bold: true, sz: 11 }, border };
    const valueStyle = { font: { sz: 11 }, border, alignment: { horizontal: "left" } };
    const dangerVal = { font: { sz: 11, bold: true, color: { rgb: "DC2626" } }, border };
    const warnVal = { font: { sz: 11, bold: true, color: { rgb: "D97706" } }, border };
    const infoVal = { font: { sz: 11, bold: true, color: { rgb: "2563EB" } }, border };

    const summaryData = [
        [{ v: "📊 Tổng quan Mixed Content Scan", s: titleStyle }],
        [],
        [{ v: "URL đã quét:", s: labelStyle }, { v: scannedUrl, s: valueStyle }],
        [{ v: "Thời gian xuất:", s: labelStyle }, { v: new Date().toLocaleString("vi-VN"), s: valueStyle }],
        [],
        [{ v: "Thống kê:", s: labelStyle }],
        [{ v: "  Tổng lỗi phát hiện:", s: labelStyle }, { v: items.length, s: valueStyle }],
        [{ v: "  Active (Critical):", s: labelStyle }, { v: activeCount, s: dangerVal }],
        [{ v: "  Passive (Warning):", s: labelStyle }, { v: passiveCount, s: warnVal }],
        [{ v: "  Info:", s: labelStyle }, { v: infoCount, s: infoVal }],
        [],
        [{ v: "Ghi chú:", s: labelStyle }],
        [{ v: "• Active: Tài nguyên có thể bị chặn bởi trình duyệt (script, iframe, css).", s: { font: { sz: 10 } } }],
        [{ v: "• Passive: Tài nguyên hiển thị cảnh báo nhưng vẫn load được (img, video, audio).", s: { font: { sz: 10 } } }],
        [{ v: "• Info: Link hoặc form action sử dụng HTTP — không bị chặn nhưng không an toàn.", s: { font: { sz: 10 } } }],
    ];

    const wsSummary = XLSX.utils.aoa_to_sheet(summaryData);
    wsSummary["!cols"] = [{ wch: 28 }, { wch: 60 }];

    // ─── Workbook ─────────────────────────────────────────────────────────
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, wsSummary, "Tổng quan");
    XLSX.utils.book_append_sheet(wb, ws, "Chi tiết");

    XLSX.writeFile(wb, `mixed-content-${hostname}-${Date.now()}.xlsx`);
}

// ─── Init ─────────────────────────────────────────────────────────────────────
function init() {
    // ─── DOM Elements ─────────────────────────────────────────────────────
    const form = document.getElementById("mixedContentForm");
    const urlInput = document.getElementById("mixedContentUrl");
    const ignoreTLSInput = document.getElementById("ignoreTLSErrors");
    const btnScan = document.getElementById("btnScan");
    const scanIcon = document.getElementById("scanIcon");
    const scanLoading = document.getElementById("scanLoading");
    const urlError = document.getElementById("urlValidationError");
    const errorCard = document.getElementById("errorCard");
    const errorMessage = document.getElementById("errorMessage");
    const resultSection = document.getElementById("resultSection");
    const statTotal = document.getElementById("statTotal");
    const statActive = document.getElementById("statActive");
    const statPassive = document.getElementById("statPassive");
    const truncatedBanner = document.getElementById("truncatedBanner");
    const noIssuesCard = document.getElementById("noIssuesCard");
    const issuesCard = document.getElementById("issuesCard");
    const issuesTableBody = document.getElementById("issuesTableBody");
    const resultsTitle = document.querySelector(".result-card__title");
    const shareLink = document.getElementById("shareLink");
    const btnCopyLink = document.getElementById("btnCopyLink");
    const btnExportXlsx = document.getElementById("btnExportXlsx");
    const btnCopyFixes = document.getElementById("btnCopyFixes");
    const cacheNotice = document.getElementById("cacheNotice");

    const btnBypassCache = document.getElementById("btnBypassCache");

    let isScanning = false;

    // ─── Reset UI (chỉ ẩn errorCard + resultSection, KHÔNG ẩn urlError) ──
    function resetUI() {
        setDisplay(errorCard, "none");
        setDisplay(resultSection, "none");
    }

    // ─── Render ───────────────────────────────────────────────────────────
    function renderResults(data, meta) {
        state.scannedUrl = data.scannedUrl;
        state.currentResults = data.items || [];
        state.currentPage = 1;

        // Summary
        resultsTitle.innerHTML = `<i class="fa-solid fa-magnifying-glass-chart mr-2"></i> Báo cáo quét trên <span class="text-success">"${escapeHTML(data.scannedUrl)}"</span>`;

        statTotal.textContent = data.totalFound;
        statActive.textContent = data.activeCount;
        statPassive.textContent = data.passiveCount;
        setDisplay(truncatedBanner, data.truncated ? "flex" : "none");

        // Cache Notice
        if (meta && meta.fetched_at) {
            const date = new Date(meta.fetched_at);
            const timeStr = date.toLocaleString("vi-VN");
            const spanEl = cacheNotice.querySelector("span");
            if (spanEl) {
                if (meta.cached) {
                    spanEl.innerHTML = `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b id="cacheTime">${timeStr}</b>`;
                } else {
                    spanEl.innerHTML = `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b id="cacheTime">${timeStr}</b>`;
                }
            }
            setDisplay(cacheNotice, "flex");
        } else {
            setDisplay(cacheNotice, "none");
        }

        if (state.currentResults.length === 0) {
            setDisplay(noIssuesCard, "block");
            setDisplay(issuesCard, "none");
        } else {
            setDisplay(noIssuesCard, "none");
            setDisplay(issuesCard, "block");
            renderTable(state.currentFilter);
        }

        // Share link
        const base = window.location.origin + window.location.pathname;
        const shareUrl = `${base}?url=${encodeURIComponent(data.scannedUrl)}`;
        shareLink.value = shareUrl;

        // Cập nhật thanh địa chỉ mà không reload trang
        window.history.replaceState({}, "", shareUrl);

        setDisplay(resultSection, "block");
    }

    function renderTable(filter = "all") {
        state.currentFilter = filter;

        // 1. Filter
        let filtered = state.currentResults;
        if (filter === "active") filtered = filtered.filter(i => i.type === "Active");
        else if (filter === "passive") filtered = filtered.filter(i => i.type === "Passive");
        else if (filter === "internal") filtered = filtered.filter(i => i.origin === "same-domain");
        else if (filter === "third-party") filtered = filtered.filter(i => i.origin === "third-party");

        // 2. Pagination Logic
        const totalItems = filtered.length;
        const pageSize = state.pageSize === "all" ? totalItems : state.pageSize;
        const totalPages = Math.ceil(totalItems / pageSize) || 1;

        if (state.currentPage > totalPages) state.currentPage = totalPages;
        const startIdx = (state.currentPage - 1) * pageSize;
        const endIdx = state.pageSize === "all" ? totalItems : Math.min(startIdx + pageSize, totalItems);
        const pageItems = filtered.slice(startIdx, endIdx);

        // 3. UI Toggle
        const emptyState = document.getElementById("mc-empty-state");
        const tableEl = document.querySelector(".mc-table");
        const paginationContainer = document.getElementById("mc-pagination-container");

        if (totalItems === 0) {
            setDisplay(emptyState, "block");
            setDisplay(tableEl, "none");
            setDisplay(paginationContainer, "none");
        } else {
            setDisplay(emptyState, "none");
            setDisplay(tableEl, "table");
            setDisplay(paginationContainer, "flex");

            issuesTableBody.innerHTML = pageItems.map(item => `
            <tr>
                <td class="mc-table__cell--level">
                    <div class="mc-table__level-wrapper">
                        ${getSeverityBadge(item.type)}
                        ${getOriginBadge(item.origin)}
                    </div>
                </td>
                <td class="mc-table__cell--type">${getSubtypeBadge(item.subtype)}</td>
                <td class="mc-table__cell--found"><span class="badge badge-default badge-subtle">${escapeHTML(item.foundIn)}</span></td>
                <td class="mc-combined-cell">
                    <div class="mc-url-block">
                        <a href="${safeHref(item.url)}" target="_blank" rel="noopener noreferrer" class="mc-url-link">
                            <i class="fa-solid fa-link-slash mr-1"></i>
                            ${escapeHTML(item.url)}
                        </a>
                    </div>
                    <div class="mc-fix-block">
                        <span class="mc-fix-arrow text-success"> <i class="fa-solid fa-arrow-right"></i> Gợi ý:</span>
                        <span class="mc-fix-url"> <i class="fa-solid fa-link mr-1"></i> ${escapeHTML(item.fixSuggestion)}</span>
                    </div>
                </td>
            </tr>
        `).join("");

            // Update Pagination Info
            document.getElementById("mc-page-start").textContent = totalItems === 0 ? 0 : startIdx + 1;
            document.getElementById("mc-page-end").textContent = endIdx;
            document.getElementById("mc-page-total-items").textContent = totalItems;

            renderPagination(totalPages);
        }
    }

    function renderPagination(totalPages) {
        const list = document.getElementById("mc-pagination-list");
        if (!list) return;
        list.innerHTML = "";

        if (totalPages <= 1) {
            return;
        }

        const createLi = (content, page, isDisabled = false, isActive = false, extraClass = "") => {
            const li = document.createElement("li");
            li.className = `mc-page-item ${isActive ? "is-active" : ""} ${isDisabled ? "is-disabled" : ""}`;

            const a = document.createElement("a");
            a.className = `mc-page-link ${extraClass}`;
            a.innerHTML = content;
            if (!isDisabled && !isActive) {
                a.onclick = (e) => {
                    e.preventDefault();
                    state.currentPage = page;
                    renderTable(state.currentFilter);
                    resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
                };
            }
            li.appendChild(a);
            return li;
        };

        // Prev Button
        list.appendChild(createLi('<i class="fa-solid fa-chevron-left"></i>', state.currentPage - 1, state.currentPage === 1, false, "mc-page-link--prev"));

        // Page Numbers with Ellipsis
        let pages = [];
        if (totalPages <= 7) {
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
                li.className = "mc-page-item is-ellipsis";
                li.innerHTML = '<span class="mc-page-link mc-page-link--ellipsis">&hellip;</span>';
                list.appendChild(li);
            } else {
                list.appendChild(createLi(p.toString(), p, false, state.currentPage === p, "mc-page-link--num"));
            }
        });

        // Next Button
        list.appendChild(createLi('<i class="fa-solid fa-chevron-right"></i>', state.currentPage + 1, state.currentPage === totalPages, false, "mc-page-link--next"));
    }

    // ─── Event Listeners for Filters & Pagination ──────────────────────────
    function setupInteractions() {
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
    }

    // ─── Copy All Fixes ───────────────────────────────────────────────────
    async function copyAllFixes(items) {
        const fixes = items.map(i => i.fixSuggestion).join("\n");
        try {
            await navigator.clipboard.writeText(fixes);
            btnCopyFixes.innerHTML = `<i class="fa-solid fa-check"></i> Đã copy ${items.length} links!`;
            setTimeout(() => {
                btnCopyFixes.innerHTML = `<i class="fa-solid fa-copy"></i> Copy Fixes`;
            }, 3000);
        } catch (err) {
            console.error("Copy failed:", err);
        }
    }

    // ─── Form Handling ────────────────────────────────────────────────────
    async function performScan(bypassCache = false) {
        if (isScanning) return;
        resetUI();
        
        const rawUrl = urlInput.value.trim();
        const url = normalizeURLInput(rawUrl);

        // Cập nhật lại UI để user thấy URL đã được chuẩn hóa
        urlInput.value = url;
        // Phát sự kiện input để validator realtime (nếu có) check lại giá trị mới
        urlInput.dispatchEvent(new Event('input'));

        if (!url) {
            setDisplay(urlError, "block");
            return;
        }

        try {
            isScanning = true;
            setElementsEnabled([urlInput, btnScan, btnBypassCache], false);
            toggleLoading(btnScan, scanIcon, scanLoading, true);

            const response = await fetch(`${API_BASE_URL}/mixed-content/scan`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    url: url,
                    ignoreTLSErrors: ignoreTLSInput?.checked || false,
                    bypassCache: bypassCache
                }),
            });

            const result = await response.json();
            if (!result.success) {
                errorMessage.textContent = result.message || "Scan thất bại. Vui lòng thử lại.";
                setDisplay(errorCard, "block");
                return;
            }

            renderResults(result.data, result.meta);
        } catch (err) {
            console.error("Scan error:", err);
            errorMessage.textContent = "Không thể kết nối tới server. Vui lòng thử lại sau.";
            setDisplay(errorCard, "block");
        } finally {
            isScanning = false;
            toggleLoading(btnScan, scanIcon, scanLoading, false);
            setElementsEnabled([urlInput, btnScan, btnBypassCache], true);
        }
    }

    // ─── Bind Events ──────────────────────────────────────────────────────
    form?.addEventListener("submit", (e) => {
        e.preventDefault();
        performScan(false);
    });

    btnBypassCache?.addEventListener("click", () => {
        performScan(true);
    });

    btnCopyLink?.addEventListener("click", async () => {
        try {
            shareLink.select();
            shareLink.setSelectionRange(0, 99999);
            await navigator.clipboard.writeText(shareLink.value);
            btnCopyLink.innerHTML = `<i class="fa-solid fa-check"></i><span>Đã copy!</span>`;
            setTimeout(() => {
                btnCopyLink.innerHTML = `<i class="fas fa-copy"></i><span>Copy</span>`;
            }, 3000);
        } catch (err) {
            console.error("Copy failed:", err);
        }
    });

    btnExportXlsx?.addEventListener("click", () => {
        if (state.currentResults.length > 0) {
            exportXLSX(state.currentResults, state.scannedUrl);
        }
    });

    btnCopyFixes?.addEventListener("click", () => {
        if (state.currentResults.length > 0) {
            copyAllFixes(state.currentResults);
        }
    });

    // Fix lỗi #12: Chỉ ẩn errorCard + resultSection, KHÔNG ẩn urlError
    // để tránh xung đột với createRealtimeDomainValidator (Quy tắc #26)
    urlInput?.addEventListener("input", () => {
        resetUI();
    });

    // ─── Setup ────────────────────────────────────────────────────────────
    createRealtimeDomainValidator(urlInput, urlError, btnScan);
    setupInteractions();

    // Auto-scan từ URL params
    const params = new URLSearchParams(window.location.search);
    const url = params.get("url");

    if (url) {
        urlInput.value = url;
        performScan(false);
    }

    window.addEventListener("popstate", () => {
        const p = new URLSearchParams(window.location.search);
        const u = p.get("url");
        if (u) {
            urlInput.value = u;
            performScan(false);
        } else {
            urlInput.value = "";
            resetUI();
        }
    });
}

document.addEventListener("DOMContentLoaded", init);
