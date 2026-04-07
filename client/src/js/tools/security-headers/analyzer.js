/**
 * security-headers/analyzer.js
 * Core logic for Security Headers Analyzer Tool
 */

import { createRealtimeURLValidator } from "../../utils/index.js";
import { API_BASE_URL } from "../../config.js";

const resolveApiBase = () => {
    if (window.location.protocol === 'file:') {
        return API_BASE_URL;
    }
    if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
        return window.location.origin + "/api";
    }
    return API_BASE_URL;
};

document.addEventListener("DOMContentLoaded", () => {
    init();
});

function init() {
    const form = document.getElementById("analyzeForm");
    const urlInput = document.getElementById("url");
    const btnAnalyze = document.getElementById("btnAnalyze");
    const btnIcon = document.getElementById("btnIcon");
    const btnLoading = document.getElementById("btnLoading");
    const urlError = document.getElementById("urlError");
    const errorCard = document.getElementById("errorCard");
    const errorMessage = document.getElementById("errorMessage");
    
    const resultSection = document.getElementById("resultSection");
    const shareCard = document.getElementById("shareCard");
    const shareLink = document.getElementById("shareLink");
    const btnCopyLink = document.getElementById("btnCopyLink");
    
    // Validate Realtime
    createRealtimeURLValidator(urlInput, urlError, btnAnalyze);
    
    // Hide errors right when user starts typing newly
    urlInput.addEventListener('input', () => {
        errorCard.classList.add("d-none");
        resultSection.classList.add("d-none");
        shareCard.classList.add("d-none");
    });

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        
        const targetUrl = urlInput.value.trim();
        if (!targetUrl) return;

        btnAnalyze.disabled = true;
        btnIcon.classList.add("d-none");
        btnLoading.classList.remove("d-none");
        errorCard.classList.add("d-none");
        resultSection.classList.add("d-none");
        shareCard.classList.add("d-none");

        try {
            const baseApiUrl = resolveApiBase();
            const res = await fetch(`${baseApiUrl}/security-headers/analyze`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target_url: targetUrl }),
            });

            const responseText = await res.text();
            let data;
            try {
                data = JSON.parse(responseText);
            } catch (e) {
                throw new Error("Lỗi máy chủ trả về không phải JSON.");
            }

            if (!res.ok || !data.success) {
                throw new Error(data.error || data.message || "Phân tích thất bại.");
            }

            renderResults(data.data);
            resultSection.classList.remove("d-none");

            // Show share card
            const shareUrl = generateShareLink(targetUrl);
            shareLink.value = shareUrl;
            shareCard.classList.remove("d-none");

        } catch (error) {
            errorMessage.innerText = error.message;
            errorCard.classList.remove("d-none");
        } finally {
            btnAnalyze.disabled = false;
            btnIcon.classList.remove("d-none");
            btnLoading.classList.add("d-none");
        }
    });

    // Setup tabs & config toggles & copy
    setupTabs();
    setupConfigTabs();
    setupCopyButtons();
    setupShareCopy(btnCopyLink);
}

// ===========================
// RENDER RESULTS
// ===========================

function renderResults(data) {
    // Render Score
    const scoreCircle = document.getElementById("scoreCircle");
    const gradeEl = document.getElementById("scoreGrade");
    const scoreVal = document.getElementById("scoreValue");
    
    scoreCircle.className = "score-circle d-flex flex-col items-center justify-center";
    
    let gradeClass = "grade-f";
    let summaryText = "Bảo mật kém. Cần cải thiện ngay.";
    
    if (data.grade === "A+") { gradeClass = "grade-aplus"; summaryText = "Tuyệt vời, website cấu hình bảo mật chuẩn xác!"; }
    else if (data.grade === "A") { gradeClass = "grade-a"; summaryText = "Tốt, nhưng vẫn có thể hoàn thiện thêm."; }
    else if (data.grade === "B") { gradeClass = "grade-b"; summaryText = "Khá, một vài header quan trọng bị thiếu."; }
    else if (data.grade === "C") { gradeClass = "grade-c"; summaryText = "Mức trung bình. Cần vá các rủi ro bảo mật."; }
    else if (data.grade === "D") { gradeClass = "grade-d"; summaryText = "Kém. Website đang đối mặt nhiều nguy cơ rò rỉ."; }
    
    scoreCircle.classList.add(gradeClass);
    gradeEl.innerText = data.grade;
    scoreVal.innerText = data.score;
    document.getElementById("scoreSummaryText").innerText = summaryText;

    // Render Headers Table
    renderHeadersTable(data.headers);

    // Render Cookies Tab
    renderCookiesTable(data);

    // Render Leaks Tab
    renderLeaksTable(data.information_leakage);

    // Config texts with syntax highlighting
    const nginxHtml = data.config.nginx
        ? colorizeNginxConfig(data.config.nginx)
        : '<span class="code-comment"># Không có cấu hình nào cần thiết (Bạn đã đạt điểm tối đa).</span>';
    const apacheHtml = data.config.apache
        ? colorizeApacheConfig(data.config.apache)
        : '<span class="code-comment"># Không có cấu hình nào cần thiết (Bạn đã đạt điểm tối đa).</span>';

    document.getElementById("nginxConfigBox").innerHTML = nginxHtml;
    document.getElementById("apacheConfigBox").innerHTML = apacheHtml;
}

// ===========================
// RENDER: HEADERS TABLE
// ===========================

function renderHeadersTable(headers) {
    const tbody = document.getElementById("headersTableBody");
    tbody.innerHTML = "";
    headers.forEach(h => {
        const icon = h.status === "ok" ? '<i class="fa-solid fa-check text-success"></i>' : 
                     (h.status === "warning" ? '<i class="fa-solid fa-triangle-exclamation text-warning"></i>' : '<i class="fa-solid fa-xmark text-error"></i>');
        const badgeClass = h.status === "ok" ? "badge-success" : (h.status === "warning" ? "badge-warning" : "badge-error");
        const stateText = h.status === "ok" ? "An toàn" : (h.status === "warning" ? "Cảnh báo" : "Nguy hiểm");

        const detailCol = h.current_value 
            ? `<code class="bg-surface p-1 rounded-sm d-block">${escapeHTML(h.current_value)}</code>` 
            : `<span>Missing<br/>👉 Fix: ${escapeHTML(h.fix || '')}</span>`;

        tbody.insertAdjacentHTML("beforeend", `
            <tr style="border-bottom: var(--border-subtle);">
                <td ><span class="badge ${badgeClass}">${icon} ${stateText}</span></td>
                <td class="font-bold">${escapeHTML(h.name)}</td>
                <td>${escapeHTML(h.risk)}</td>
                <td>${detailCol}</td>
            </tr>
        `);
    });
}

// ===========================
// RENDER: COOKIES TABLE
// ===========================

function renderCookiesTable(data) {
    const tbody = document.getElementById("cookiesTableBody");
    tbody.innerHTML = "";
    const cCount = data.cookies ? data.cookies.length : 0;
    document.getElementById("cookieCount").innerText = cCount;

    if (!data.has_set_cookie || cCount === 0) {
        document.getElementById("noCookieMsg").classList.remove("d-none");
        document.getElementById("cookieWrapper").classList.add("d-none");
    } else {
        document.getElementById("noCookieMsg").classList.add("d-none");
        document.getElementById("cookieWrapper").classList.remove("d-none");

        data.cookies.forEach(c => {
            const httpOnlyNode = c.http_only ? '<i class="fa-solid fa-check text-success"></i>' : '<i class="fa-solid fa-xmark text-error"></i>';
            const secureNode = c.secure ? '<i class="fa-solid fa-check text-success"></i>' : '<i class="fa-solid fa-xmark text-error"></i>';
            let sameSiteNode = '<i class="fa-solid fa-xmark text-warning"></i> None';
            if (c.same_site === "Lax" || c.same_site === "Strict") {
                sameSiteNode = `<i class="fa-solid fa-check text-success"></i> ${c.same_site}`;
            }

            const svBadge = c.severity === "high" ? "badge-error" : (c.severity === "medium" ? "badge-warning" : "badge-success");
            const svText = c.severity.toUpperCase();

            tbody.insertAdjacentHTML("beforeend", `
                <tr style="border-bottom: var(--border-subtle);">
                    <td class="font-bold">${escapeHTML(c.name)}</td>
                    <td class="text-center">${httpOnlyNode}</td>
                    <td class="text-center">${secureNode}</td>
                    <td >${sameSiteNode}</td>
                    <td><span class="badge ${svBadge}">${svText}</span></td>
                </tr>
            `);
        });
    }
}

// ===========================
// RENDER: LEAKS TABLE
// ===========================

function renderLeaksTable(leaks) {
    const tbody = document.getElementById("leaksTableBody");
    tbody.innerHTML = "";
    if (!leaks || leaks.length === 0) {
        document.getElementById("noLeakMsg").classList.remove("d-none");
        document.getElementById("leakWrapper").classList.add("d-none");
    } else {
        document.getElementById("noLeakMsg").classList.add("d-none");
        document.getElementById("leakWrapper").classList.remove("d-none");

        leaks.forEach(l => {
            tbody.insertAdjacentHTML("beforeend", `
                <tr style="border-bottom: var(--border-subtle);">
                    <td class="font-bold">${escapeHTML(l.name)}</td>
                    <td><code class="text-error bg-surface p-1 rounded-sm">${escapeHTML(l.current_value)}</code></td>
                    <td>${escapeHTML(l.risk)}</td>
                    <td><span><i class="fa-solid fa-wrench"></i> ${escapeHTML(l.fix)}</span></td>
                </tr>
            `);
        });
    }
}

// ===========================
// SYNTAX HIGHLIGHTING: NGINX
// ===========================

function colorizeNginxConfig(raw) {
    return raw.split('\n').map(line => {
        const trimmed = line.trim();
        if (!trimmed) return '';

        // Comment lines
        if (trimmed.startsWith('#')) {
            return `<span class="code-comment">${escapeHTML(line)}</span>`;
        }

        // Nginx directive: add_header <name> <value> always;
        return line.replace(
            /^(add_header)\s+(\S+)\s+(".*?")\s*(always)?;?$/,
            (match, directive, headerName, value, always) => {
                let result = `<span class="code-keyword">${escapeHTML(directive)}</span>`;
                result += ` <span class="code-parameter">${escapeHTML(headerName)}</span>`;
                result += ` <span class="code-string">${escapeHTML(value)}</span>`;
                if (always) {
                    result += ` <span class="code-value">${escapeHTML(always)}</span>`;
                }
                result += '<span class="code-text">;</span>';
                return result;
            }
        );
    }).filter(l => l !== '').join('\n');
}

// ===========================
// SYNTAX HIGHLIGHTING: APACHE
// ===========================

function colorizeApacheConfig(raw) {
    return raw.split('\n').map(line => {
        const trimmed = line.trim();
        if (!trimmed) return '';

        // Comment lines
        if (trimmed.startsWith('#')) {
            return `<span class="code-comment">${escapeHTML(line)}</span>`;
        }

        // Apache directive: Header always set <name> <value>
        return line.replace(
            /^(Header)\s+(always\s+set)\s+(\S+)\s+(".*?")$/,
            (match, directive, action, headerName, value) => {
                let result = `<span class="code-keyword">${escapeHTML(directive)}</span>`;
                result += ` <span class="code-func">${escapeHTML(action)}</span>`;
                result += ` <span class="code-parameter">${escapeHTML(headerName)}</span>`;
                result += ` <span class="code-string">${escapeHTML(value)}</span>`;
                return result;
            }
        );
    }).filter(l => l !== '').join('\n');
}

// ===========================
// ESCAPE HTML HELPER
// ===========================

function escapeHTML(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ===========================
// TABS
// ===========================

function setupTabs() {
    document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-pane").forEach(p => p.classList.add("d-none"));
            
            btn.classList.add("active");
            document.getElementById(btn.dataset.tab).classList.remove("d-none");
        });
    });
}

function setupConfigTabs() {
    document.querySelectorAll(".config-tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".config-tab-btn").forEach(b => {
                b.classList.remove("active", "btn-action");
                b.classList.add("btn-outline");
            });
            btn.classList.remove("btn-outline");
            btn.classList.add("active", "btn-action");

            const targetId = btn.dataset.target;
            document.querySelectorAll(".config-box").forEach(box => {
                box.classList.add("d-none");
            });
            document.getElementById(targetId).classList.remove("d-none");
        });
    });
}

function setupCopyButtons() {
    document.querySelectorAll(".copy-config-btn").forEach(btnCopy => {
        btnCopy.addEventListener("click", () => {
            const targetId = btnCopy.dataset.copyTarget;
            const textToCopy = document.getElementById(targetId).innerText;
            navigator.clipboard.writeText(textToCopy).then(() => {
                const originalHTML = btnCopy.innerHTML;
                btnCopy.innerHTML = `<i class="fa-solid fa-check"></i>`;
                setTimeout(() => { btnCopy.innerHTML = originalHTML; }, 2000);
            });
        });
    });
}

// ===========================
// SHARE CARD
// ===========================

function generateShareLink(targetUrl) {
    const baseUrl = window.location.origin + window.location.pathname;
    return `${baseUrl}?url=${encodeURIComponent(targetUrl)}`;
}

function setupShareCopy(btnCopyLink) {
    if (!btnCopyLink) return;
    btnCopyLink.addEventListener("click", () => {
        const shareLink = document.getElementById("shareLink");
        if (!shareLink) return;
        navigator.clipboard.writeText(shareLink.value).then(() => {
            const spanEl = btnCopyLink.querySelector("span");
            if (spanEl) {
                const originalText = spanEl.textContent;
                spanEl.textContent = "Đã copy!";
                setTimeout(() => { spanEl.textContent = originalText; }, 2000);
            }
        });
    });
}
