// =================================//
//  MIXED CONTENT SCANNER — MAIN JS
//==================================//
import {
    /* dom.js */
    $,
    setDisplay,
    toggleLoading,
    setElementsEnabled,
    createRealtimeURLValidator,

    /* format.js */
    escapeHTML,
} from "../../utils/index.js";
import { API_BASE_URL } from "../../config.js";

// ─── DOM Elements ─────────────────────────────────────────────────────────────
const form           = document.getElementById("mixedContentForm");
const urlInput       = document.getElementById("mixedContentUrl");
const ignoreTLSInput = document.getElementById("ignoreTLSErrors");
const btnScan        = document.getElementById("btnScan");
const scanIcon       = document.getElementById("scanIcon");
const scanLoading    = document.getElementById("scanLoading");
const urlError       = document.getElementById("urlValidationError");
const errorCard      = document.getElementById("errorCard");
const errorMessage   = document.getElementById("errorMessage");
const resultSection  = document.getElementById("resultSection");
const summaryUrl     = document.getElementById("summaryUrl");
const statTotal      = document.getElementById("statTotal");
const statActive     = document.getElementById("statActive");
const statPassive    = document.getElementById("statPassive");
const truncatedBanner = document.getElementById("truncatedBanner");
const mcActionBar    = document.getElementById("mcActionBar");
const noIssuesCard   = document.getElementById("noIssuesCard");
const issuesCard     = document.getElementById("issuesCard");
const issuesTableBody = document.getElementById("issuesTableBody");
const shareLink      = document.getElementById("shareLink");
const btnCopyLink    = document.getElementById("btnCopyLink");
const btnExportCsv   = document.getElementById("btnExportCsv");
const btnCopyFixes   = document.getElementById("btnCopyFixes");

// ─── State ────────────────────────────────────────────────────────────────────
let lastItems = [];

// ─── Utils ────────────────────────────────────────────────────────────────────
function validateURL(url) {
    const lower = url.toLowerCase();
    return lower.startsWith("http://") || lower.startsWith("https://");
}

function resetUI() {
    setDisplay(urlError, "none");
    setDisplay(errorCard, "none");
    setDisplay(resultSection, "none");
}

function getSeverityBadge(type) {
    if (type === "Active") {
        return `<span class="mc-badge mc-badge--critical"><i class="fa-solid fa-bolt"></i> CRITICAL</span>`;
    }
    if (type === "Info") {
        return `<span class="mc-badge mc-badge--info"><i class="fa-solid fa-info-circle"></i> INFO</span>`;
    }
    return `<span class="mc-badge mc-badge--warning"><i class="fa-solid fa-triangle-exclamation"></i> WARNING</span>`;
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
        return `<span class="mc-badge mc-badge--same">Nội bộ</span>`;
    }
    return `<span class="mc-badge mc-badge--third">Bên thứ 3</span>`;
}

function getSubtypeBadge(subtype) {
    return `<span class="mc-badge mc-badge--info">${escapeHTML(subtype)}</span>`;
}

// ─── Render ───────────────────────────────────────────────────────────────────
function renderResults(data) {
    // Summary
    summaryUrl.textContent = data.scannedUrl;
    statTotal.textContent  = data.totalFound;
    statActive.textContent = data.activeCount;
    statPassive.textContent = data.passiveCount;
    setDisplay(truncatedBanner, data.truncated ? "flex" : "none");

    lastItems = data.items || [];

    if (lastItems.length === 0) {
        setDisplay(noIssuesCard, "block");
        setDisplay(issuesCard, "none");
        setDisplay(mcActionBar, "none");
    } else {
        setDisplay(noIssuesCard, "none");
        setDisplay(issuesCard, "block");
        setDisplay(mcActionBar, "flex");
        renderTable(lastItems);
    }

    // Share link
    const base = window.location.origin + window.location.pathname;
    const shareUrl = `${base}?url=${encodeURIComponent(data.scannedUrl)}`;
    shareLink.value = shareUrl;

    // Cập nhật thanh địa chỉ mà không reload trang
    window.history.replaceState({}, "", shareUrl);

    setDisplay(resultSection, "block");
}

function renderTable(items) {
    issuesTableBody.innerHTML = items.map(item => `
        <tr>
            <td>
                ${getSeverityBadge(item.type)}
                ${getOriginBadge(item.origin)}
            </td>
            <td>${getSubtypeBadge(item.subtype)}</td>
            <td><code class="mc-foundin">${escapeHTML(item.foundIn)}</code></td>
            <td class="mc-combined-cell">
                <div class="mc-url-block">
                    <a href="${safeHref(item.url)}" target="_blank" rel="noopener noreferrer" class="mc-url-link">
                        <i class="fa-solid fa-link-slash mr-1"></i>    
                        ${escapeHTML(item.url)}
                    </a>
                </div>
                <div class="mc-fix-block">
                    <span class="mc-fix-arrow">→ Gợi ý:</span>
                    <span class="mc-fix-url"> <i class="fa-solid fa-link mr-1"></i> ${escapeHTML(item.fixSuggestion)}</span>
                </div>
            </td>
        </tr>
    `).join("");
}

// ─── Export CSV (RFC 4180) ────────────────────────────────────────────────────
function csvEscape(val) {
    const s = String(val ?? "");
    // Nếu có dấu phẩy, quote, hoặc newline → bọc trong quotes và escape quote bằng double-quote
    if (s.includes(",") || s.includes('"') || s.includes("\n") || s.includes("\r")) {
        return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
}

function exportCSV(items, scannedUrl) {
    let hostname = "scan";
    try {
        hostname = new URL(scannedUrl).hostname;
    } catch (e) {
        console.warn("Invalid URL for CSV filename", e);
    }

    const headers = ["Mức độ", "Loại", "Vị trí (FoundIn)", "URL HTTP", "Gợi ý Fix", "Nguồn gốc"];
    const rows = items.map(item => [
        item.type.toUpperCase(),
        item.subtype,
        item.foundIn,
        item.url,
        item.fixSuggestion,
        item.origin,
    ].map(csvEscape).join(","));

    const csv = [headers.map(csvEscape).join(","), ...rows].join("\r\n");
    const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8;" }); // BOM for Excel
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `mixed-content-${hostname}-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
}

// ─── Copy All Fixes ───────────────────────────────────────────────────────────
async function copyAllFixes(items) {
    const fixes = items.map(i => i.fixSuggestion).join("\n");
    try {
        await navigator.clipboard.writeText(fixes);
        btnCopyFixes.innerHTML = `<i class="fa-solid fa-check"></i> Đã copy ${items.length} links!`;
        setTimeout(() => {
            btnCopyFixes.innerHTML = `<i class="fa-solid fa-copy"></i> Copy tất cả Fix Suggestions`;
        }, 3000);
    } catch (err) {
        console.error("Copy failed:", err);
    }
}

// ─── Share Link Copy ──────────────────────────────────────────────────────────
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

btnExportCsv?.addEventListener("click", () => {
    if (lastItems.length > 0) {
        exportCSV(lastItems, summaryUrl.textContent);
    }
});

btnCopyFixes?.addEventListener("click", () => {
    if (lastItems.length > 0) {
        copyAllFixes(lastItems);
    }
});

// ─── Reset on input ───────────────────────────────────────────────────────────
urlInput?.addEventListener("input", () => {
    setDisplay(urlError, "none");
    setDisplay(errorCard, "none");
    setDisplay(resultSection, "none");
});

// ─── Form Submit ──────────────────────────────────────────────────────────────
form?.addEventListener("submit", async (e) => {
    e.preventDefault();
    resetUI();

    const rawUrl = urlInput.value.trim();

    if (!rawUrl || !validateURL(rawUrl)) {
        setDisplay(urlError, "block");
        return;
    }

    setElementsEnabled([urlInput, btnScan], false);
    toggleLoading(btnScan, scanIcon, scanLoading, true);

    try {
        const response = await fetch(`${API_BASE_URL}/mixed-content/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                url: rawUrl,
                ignoreTLSErrors: ignoreTLSInput?.checked || false 
            }),
        });

        const result = await response.json();

        if (!result.success) {
            errorMessage.textContent = result.message || "Scan thất bại. Vui lòng thử lại.";
            setDisplay(errorCard, "block");
            return;
        }

        renderResults(result.data);
    } catch (err) {
        errorMessage.textContent = "Không thể kết nối tới server. Vui lòng thử lại sau.";
        setDisplay(errorCard, "block");
    } finally {
        toggleLoading(btnScan, scanIcon, scanLoading, false);
        setElementsEnabled([urlInput, btnScan], true);
    }
});

// ─── Auto-load from URL params ────────────────────────────────────────────────
function initFromURL() {
    createRealtimeURLValidator(urlInput, urlError, btnScan);

    const params = new URLSearchParams(window.location.search);
    const url = params.get("url");
    if (url) {
        urlInput.value = url;
        form.dispatchEvent(new Event("submit"));
    }
}

initFromURL();
