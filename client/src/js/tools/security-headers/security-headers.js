/**
 * security-headers/analyzer.js
 * Core logic for Security Headers Analyzer Tool
 */

import { createRealtimeURLValidator, escapeHTML } from "../../utils/index.js";
import { API_BASE_URL } from "../../config.js";

let isBypassCache = false;
let currentController = null;
let currentRequestId = 0;

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

    const cacheNotice = document.getElementById("cacheNotice");
    const btnBypassCache = document.getElementById("btnBypassCache");

    // Validate Realtime
    createRealtimeURLValidator(urlInput, urlError, btnAnalyze);

    // Hide errors right when user starts typing newly
    urlInput.addEventListener('input', () => {
        if (currentController) {
            currentController.abort();
            currentRequestId++;
        }
        errorCard.classList.add("d-none");
        resultSection.classList.add("d-none");
        shareCard.classList.add("d-none");
        cacheNotice.classList.add("d-none");
    });

    const followRedirectsCheckbox = document.getElementById("followRedirects");
    if (followRedirectsCheckbox) {
        followRedirectsCheckbox.addEventListener('change', () => {
            if (currentController) {
                currentController.abort();
                currentRequestId++;
            }
            errorCard.classList.add("d-none");
            resultSection.classList.add("d-none");
            shareCard.classList.add("d-none");
            if (cacheNotice) cacheNotice.classList.add("d-none");
            
            const val = urlInput.value.trim();
            const isInvalid = urlInput.classList.contains("is-invalid");
            btnAnalyze.disabled = !val || isInvalid;
            btnIcon.classList.remove("d-none");
            btnLoading.classList.add("d-none");
        });
    }

    if (btnBypassCache) {
        btnBypassCache.addEventListener("click", () => {
            isBypassCache = true;
            form.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));
        });
    }

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const targetUrl = urlInput.value.trim();
        if (!targetUrl || urlInput.classList.contains("is-invalid")) return;

        const isBypassCacheForThisReq = isBypassCache;
        isBypassCache = false; // Reset immediately after reading

        if (currentController) {
            currentController.abort();
        }
        currentController = new AbortController();
        const { signal } = currentController;
        const requestId = ++currentRequestId;

        btnAnalyze.disabled = true;
        btnIcon.classList.add("d-none");
        btnLoading.classList.remove("d-none");
        errorCard.classList.add("d-none");
        resultSection.classList.add("d-none");
        shareCard.classList.add("d-none");

        if (!isBypassCacheForThisReq && cacheNotice) {
            cacheNotice.classList.add("d-none");
        }

        try {
            const res = await fetch(`${API_BASE_URL}/security-headers/analyze`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    target_url: targetUrl,
                    bypassCache: isBypassCacheForThisReq,
                    followRedirects: document.getElementById("followRedirects").checked
                }),
                signal
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

            if (requestId === currentRequestId) {
                renderResults(data.data, data.meta);
                resultSection.classList.remove("d-none");

                // Show share card
                const shareUrl = generateShareLink(targetUrl);
                shareLink.value = shareUrl;
                shareCard.classList.remove("d-none");

                // Update URL parameters
                updateURL(targetUrl);
            }

        } catch (error) {
            if (error.name === 'AbortError' || requestId !== currentRequestId) return;
            errorMessage.innerText = error.message;
            errorCard.classList.remove("d-none");
        } finally {
            if (requestId === currentRequestId) {
                const val = urlInput.value.trim();
                const isInvalid = urlInput.classList.contains("is-invalid");
                const isTypingPrefix = [
                    'h', 'ht', 'htt', 'http', 'http:', 'http:/', 'http://',
                    'https', 'https:', 'https:/', 'https://'
                ].includes(val.toLowerCase());
                btnAnalyze.disabled = !val || isInvalid || isTypingPrefix;
                btnIcon.classList.remove("d-none");
                btnLoading.classList.add("d-none");
            }
        }
    });

    // Setup tabs & config toggles & copy
    setupTabs();
    setupConfigTabs();
    setupCopyButtons();
    setupShareCopy(btnCopyLink);

    // Đồng bộ nút Back/Forward của trình duyệt
    window.addEventListener('popstate', (e) => {
        const params = new URLSearchParams(window.location.search);
        const urlParam = params.get('url') || '';
        const followParam = params.get('followRedirects');
        
        const followCheckbox = document.getElementById("followRedirects");
        if (followCheckbox) {
            followCheckbox.checked = (followParam === 'true');
        }

        if (urlParam) {
            urlInput.value = urlParam;
            urlInput.dispatchEvent(new Event('input', { bubbles: true }));
            form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
        } else {
            urlInput.value = '';
            urlInput.dispatchEvent(new Event('input', { bubbles: true }));
            errorCard.classList.add("d-none");
            resultSection.classList.add("d-none");
            shareCard.classList.add("d-none");
            cacheNotice.classList.add("d-none");
        }
    });

    // Auto-query on load if params exist
    checkURLParamsAndQuery();
}

// ===========================
// URL AUTO QUERY
// ===========================

function checkURLParamsAndQuery() {
    const params = new URLSearchParams(window.location.search);
    const urlParam = params.get('url');
    const followParam = params.get('followRedirects');

    if (urlParam) {
        const urlInput = document.getElementById("url");
        const followCheckbox = document.getElementById("followRedirects");
        
        if (followCheckbox && followParam === 'true') {
            followCheckbox.checked = true;
        }

        if (urlInput) {
            urlInput.value = urlParam;
            // Kích hoạt input event để ẩn lỗi & bật nút submit
            urlInput.dispatchEvent(new Event('input', { bubbles: true }));

            // Tự động submit
            setTimeout(() => {
                const form = document.getElementById("analyzeForm");
                if (form) {
                    form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
                }
            }, 300);
        }
    }
}

function updateURL(url) {
    const followCheckbox = document.getElementById("followRedirects");
    const isFollow = followCheckbox && followCheckbox.checked;
    
    const params = new URLSearchParams({ url });
    if (isFollow) params.set('followRedirects', 'true');
    
    const newSearch = `?${params.toString()}`;
    const newURL = `${window.location.pathname}${newSearch}`;
    if (window.location.search !== newSearch) {
        window.history.pushState({ url }, '', newURL);
    }
}

// ===========================
// RENDER RESULTS
// ===========================

function renderResults(data, meta) {
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
    else if (data.grade === "R") { gradeClass = "grade-r text-warning border-warning"; summaryText = "Website thực hiện Redirect. Bật Follow Redirects để tiếp tục."; }

    scoreCircle.classList.add(gradeClass);
    gradeEl.innerText = data.grade;
    scoreVal.innerText = data.score;
    document.getElementById("scoreSummaryText").innerText = summaryText;

    // Hiển thị Cache Notice nếu có meta
    const cacheNotice = document.getElementById("cacheNotice");
    if (cacheNotice && meta) {
        cacheNotice.classList.remove("d-none");
        const timeStr = new Date(meta.fetched_at).toLocaleString('vi-VN');
        const spanEl = cacheNotice.querySelector("span");
        if (meta.cached) {
            spanEl.innerHTML = `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b>${timeStr}</b>`;
        } else {
            spanEl.innerHTML = `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b>${timeStr}</b>`;
        }
    } else if (cacheNotice) {
        cacheNotice.classList.add("d-none");
    }

    // Render Redirect Chain
    const redirectChainWrapper = document.getElementById("redirectChainWrapper");
    const redirectChainNodes = document.getElementById("redirectChainNodes");
    if (data.redirect_chain && data.redirect_chain.length > 1) {
        redirectChainWrapper.classList.remove("d-none");
        redirectChainNodes.innerHTML = "";
        
        data.redirect_chain.forEach((hop, index) => {
            const isLast = index === data.redirect_chain.length - 1;
            const nodeHtml = `
                <div class="relative pl-4">
                    <span class="absolute -left-3.5 top-1.5 w-3 h-3 rounded-full ${isLast ? 'bg-success' : 'bg-primary'} shadow-[0_0_0_2px_var(--color-surface)]"></span>
                    <div class="d-flex flex-col mb-4">
                        <span class="font-bold text-sm ${isLast ? 'text-success' : ''}">Hop ${index + 1} (${hop.status_code}):</span>
                        <a href="${escapeHTML(hop.url)}" target="_blank" rel="noopener noreferrer" class="text-sm word-break text-primary hover-underline">${escapeHTML(hop.url)}</a>
                        ${hop.has_hsts ? '<span class="text-xs text-success mt-1"><i class="fa-solid fa-lock mr-1"></i>HSTS Enabled</span>' : ''}
                    </div>
                </div>
            `;
            redirectChainNodes.insertAdjacentHTML("beforeend", nodeHtml);
        });
    } else {
        redirectChainWrapper.classList.add("d-none");
    }

    // Render Headers Table
    renderHeadersTable(data.headers);

    // Render Cookies Tab
    renderCookiesTable(data);

    // Render Leaks Tab
    renderLeaksTable(data.information_leakage);

    // Render CORS Tab
    if (data.cors_analysis) {
        renderCORSAnalysis(data.cors_analysis);
    }

    // Render Smart Config Generator
    renderConfigGenerator(data.config, data.detected_tech);

    // Render CSP Visualizer
    renderCSPVisualizer(data.headers);


    // Render Raw Headers tab
    renderRawHeaders(data.raw_headers);

    // Render Additional Info section
    renderAdditionalInfo(data.additional_info);
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

        let detailCol = "";
        if (h.current_value) {
            detailCol = `<code class="bg-surface p-1 rounded-sm d-block break-all">${escapeHTML(h.current_value)}</code>`;
            if (h.status !== "ok" && h.fix) {
                detailCol += `<br/><span class="text-secondary mt-1 d-block">👉 Fix: ${escapeHTML(h.fix)}</span>`;
            }
        } else {
            detailCol = `<span class="badge badge-error badge-sm mb-2">Missing</span>`;
            if (h.fix) {
                detailCol += `<br/><span class="text-secondary">👉 Fix: ${escapeHTML(h.fix)}</span>`;
            }
        }

        tbody.insertAdjacentHTML("beforeend", `
            <tr class="security-headers__tr">
                <td data-label="Trạng thái"><span class="badge ${badgeClass}">${icon} ${stateText}</span></td>
                <td data-label="Header" class="font-bold">${escapeHTML(h.name)}</td>
                <td data-label="Rủi ro (Risk)">${escapeHTML(h.risk)}</td>
                <td data-label="Giải pháp (Fix / Detail)">${detailCol}</td>
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
            let sameSiteNode = '';
            if (c.same_site === "Lax" || c.same_site === "Strict") {
                sameSiteNode = `<i class="fa-solid fa-check text-success"></i> ${c.same_site}`;
            } else if (c.same_site === "Missing") {
                sameSiteNode = `<i class="fa-solid fa-minus text-secondary"></i> Missing`;
            } else if (c.same_site === "Invalid") {
                sameSiteNode = `<i class="fa-solid fa-triangle-exclamation text-error"></i> Invalid`;
            } else {
                sameSiteNode = `<i class="fa-solid fa-triangle-exclamation text-warning"></i> None`;
            }

            const svBadge = c.severity === "high" ? "badge-error" : (c.severity === "medium" ? "badge-warning" : "badge-success");
            const svText = c.severity.toUpperCase();

            tbody.insertAdjacentHTML("beforeend", `
                <tr class="security-headers__tr">
                    <td data-label="Cookie Name" class="font-bold">${escapeHTML(c.name)}</td>
                    <td data-label="HttpOnly" class="text-center">${httpOnlyNode}</td>
                    <td data-label="Secure" class="text-center">${secureNode}</td>
                    <td data-label="SameSite">${sameSiteNode}</td>
                    <td data-label="Mức độ an toàn"><span class="badge ${svBadge}">${svText}</span></td>
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
                <tr class="security-headers__tr">
                    <td data-label="Header" class="font-bold">${escapeHTML(l.name)}</td>
                    <td data-label="Giá trị bị rò rỉ"><code class="text-error bg-surface p-1 rounded-sm">${escapeHTML(l.current_value)}</code></td>
                    <td data-label="Nguy cơ">${escapeHTML(l.risk)}</td>
                    <td data-label="Cách ẩn đi"><span><i class="fa-solid fa-wrench"></i> ${escapeHTML(l.fix)}</span></td>
                </tr>
            `);
        });
    }
}

// ===========================
// RENDER: CORS TABLE
// ===========================

function renderCORSAnalysis(corsData) {
    const tbody = document.getElementById("corsTableBody");
    const statusMsg = document.getElementById("corsStatusMsg");
    const wrapper = document.getElementById("corsWrapper");

    if (!tbody || !corsData) return;
    tbody.innerHTML = "";

    if (corsData.error) {
        statusMsg.classList.remove("d-none");
        wrapper.classList.add("d-none");
        statusMsg.innerHTML = `<p class="text-error"><i class="fa-solid fa-triangle-exclamation mr-2"></i> Lỗi quét CORS: ${escapeHTML(corsData.error)}</p>`;
        return;
    }

    if (!corsData.enabled) {
        statusMsg.classList.remove("d-none");
        wrapper.classList.add("d-none");
        statusMsg.innerHTML = '<p class="text-secondary"><i class="fa-solid fa-shield-halved mr-2"></i> Website không kích hoạt CORS (Không có Access-Control-Allow-Origin).</p>';
        return;
    }

    statusMsg.classList.add("d-none");
    wrapper.classList.remove("d-none");

    corsData.issues.forEach(issue => {
        const icon = issue.status === "ok" ? '<i class="fa-solid fa-check text-success"></i>' :
            (issue.status === "warning" ? '<i class="fa-solid fa-triangle-exclamation text-warning"></i>' : '<i class="fa-solid fa-xmark text-error"></i>');
        const badgeClass = issue.status === "ok" ? "badge-success" : (issue.status === "warning" ? "badge-warning" : "badge-error");
        const stateText = issue.status === "ok" ? "An toàn" : (issue.status === "warning" ? "Cảnh báo" : "Nguy hiểm");

        tbody.insertAdjacentHTML("beforeend", `
            <tr class="security-headers__tr">
                <td data-label="Trạng thái"><span class="badge ${badgeClass}">${icon} ${stateText}</span></td>
                <td data-label="Mô tả" class="font-bold">${escapeHTML(issue.description)}</td>
                <td data-label="Nguy cơ">${escapeHTML(issue.risk || "An toàn")}</td>
                <td data-label="Cách xử lý">${issue.fix ? escapeHTML(issue.fix) : '<span class="text-secondary">—</span>'}</td>
            </tr>
        `);
    });
}

// ===========================
// SMART CONFIG GENERATOR
// ===========================

function renderConfigGenerator(config, detectedTech) {
    const tabsContainer = document.getElementById("configTabsContainer");
    const blocksContainer = document.getElementById("configBlocksContainer");
    
    if (!tabsContainer || !blocksContainer) return;

    tabsContainer.innerHTML = "";
    blocksContainer.innerHTML = "";

    let isFirst = true;

    const addConfigTab = (id, label, icon, code, isFallback = false) => {
        const btnClass = isFirst ? "btn btn-sm btn-action config-tab-btn active" : "btn btn-sm btn-outline config-tab-btn";
        const boxClass = isFirst ? "code-block mb-4 config-box d-block" : "code-block mb-4 config-box d-none";

        tabsContainer.insertAdjacentHTML("beforeend", `
            <button class="${btnClass}" data-target="${id}">
                ${isFallback ? label : `<i class="fa-solid fa-star text-warning mr-1"></i>${label}`}
            </button>
        `);

        blocksContainer.insertAdjacentHTML("beforeend", `
            <div id="${id}" class="${boxClass}">
                <div class="code-block__header">
                    <span class="code-block__lang"><i class="${icon} mr-1"></i> ${label}</span>
                    <button class="code-block__btn-copy copy-config-btn" data-copy-target="${id}-code">
                        <i class="fa-regular fa-clone"></i>
                    </button>
                </div>
                <div class="code-block__body">
                    <code id="${id}-code" class="code-block__text d-block">${code}</code>
                </div>
            </div>
        `);
        isFirst = false;
    };

    if (detectedTech && detectedTech.length > 0) {
        detectedTech.forEach(tech => {
            if (tech.name === "express") {
                addConfigTab("expressCodeBlock", "Express (Node.js)", "fa-brands fa-node-js", colorizeGenericConfig("const helmet = require('helmet');\napp.use(helmet({\n  strictTransportSecurity: {\n    maxAge: 31536000,\n    includeSubDomains: true,\n    preload: false, // Optional: set to true if you want to submit to HSTS Preload list\n  },\n  contentSecurityPolicy: {\n    directives: {\n      defaultSrc: [\"'self'\"],\n      objectSrc: [\"'none'\"],\n      baseUri: [\"'none'\"],\n      frameAncestors: [\"'self'\"],\n      formAction: [\"'self'\"]\n    }\n  }\n}));"));
            } else if (tech.name === "wordpress") {
                addConfigTab("wpCodeBlock", "WordPress", "fa-brands fa-wordpress", colorizeGenericConfig("// Thêm vào functions.php\nadd_action('send_headers', 'add_security_headers');\nfunction add_security_headers() {\n    header('Strict-Transport-Security: max-age=31536000; includeSubDomains'); // Optional: thêm ; preload nếu đăng ký HSTS Preload\n    header('X-Frame-Options: SAMEORIGIN');\n    // ... thêm CSP và các header khác\n}"));
            } else if (tech.name === "php") {
                addConfigTab("phpCodeBlock", "PHP", "fa-brands fa-php", colorizeGenericConfig("header('Strict-Transport-Security: max-age=31536000; includeSubDomains'); // Optional: thêm ; preload nếu đăng ký HSTS Preload\nheader('X-Frame-Options: SAMEORIGIN');\n// ..."));
            } else if (tech.name === "asp.net") {
                addConfigTab("aspCodeBlock", "ASP.NET", "fa-brands fa-microsoft", colorizeGenericConfig("<!-- Trong Web.config -->\n<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n      <!-- Optional: thêm ; preload vào value nếu đăng ký HSTS Preload -->\n      <add name=\"Strict-Transport-Security\" value=\"max-age=31536000; includeSubDomains\" />\n      <add name=\"X-Frame-Options\" value=\"SAMEORIGIN\" />\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>"));
            }
        });
    }

    const nginxHtml = config.nginx ? colorizeNginxConfig(config.nginx) : '<span class="code-comment"># Không có cấu hình nào cần thiết.</span>';
    const apacheHtml = config.apache ? colorizeApacheConfig(config.apache) : '<span class="code-comment"># Không có cấu hình nào cần thiết.</span>';
    
    addConfigTab("nginxCodeBlock", "Nginx", "fa-solid fa-file-code", nginxHtml, true);
    addConfigTab("apacheCodeBlock", "Apache", "fa-solid fa-file-code", apacheHtml, true);

    setupConfigTabs();
    setupCopyButtons();
}

function colorizeGenericConfig(raw) {
    return raw.split('\\n').map(line => {
        if (line.trim().startsWith('//') || line.trim().startsWith('#') || line.trim().startsWith('<!--')) {
            return `<span class="code-comment">${escapeHTML(line)}</span>`;
        }
        return `<span class="code-text">${escapeHTML(line)}</span>`;
    }).join('\\n');
}

// ===========================
// RENDER: CSP VISUALIZER
// ===========================

function renderCSPVisualizer(headers) {
    const noCspMsg = document.getElementById("noCspMsg");
    const cspWrapper = document.getElementById("cspWrapper");
    const cspOriginalString = document.getElementById("cspOriginalString");
    const tbody = document.getElementById("cspTableBody");
    
    if (!tbody) return;
    tbody.innerHTML = "";

    let cspHeader = null;
    if (headers) {
        cspHeader = headers.find(h => h.name.toLowerCase() === "content-security-policy");
    }

    if (!cspHeader || !cspHeader.current_value) {
        noCspMsg.classList.remove("d-none");
        cspWrapper.classList.add("d-none");
        return;
    }

    noCspMsg.classList.add("d-none");
    cspWrapper.classList.remove("d-none");
    
    cspOriginalString.innerText = cspHeader.current_value;

    const directives = cspHeader.current_value.split(';').map(d => d.trim()).filter(d => d.length > 0);
    
    directives.forEach(d => {
        const parts = d.trim().split(/\s+/);
        const name = parts[0];
        const values = parts.slice(1);
        const isScriptDirective = ["script-src", "script-src-elem", "script-src-attr", "default-src", "object-src", "base-uri"].includes(name.toLowerCase());
        
        const hasStrictDynamic = values.some(v => v.toLowerCase() === "'strict-dynamic'");
        const hasNonceOrHash = values.some(v => {
            const vLower = v.toLowerCase();
            return vLower.startsWith("'nonce-") || vLower.startsWith("'sha");
        });
        const isBackwardCompatible = hasStrictDynamic && hasNonceOrHash;

        let valuesHtml = values.map(v => {
            const vLower = v.toLowerCase();
            if (["'unsafe-inline'", "'unsafe-eval'", "*", "data:", "http:"].includes(vLower)) {
                if (isScriptDirective) {
                    if (vLower === "'unsafe-inline'" && isBackwardCompatible) {
                        return `<span class="badge badge-info badge-sm mb-1">${escapeHTML(v)}</span>`;
                    }
                    return `<span class="badge badge-error badge-sm mb-1">${escapeHTML(v)}</span>`;
                } else {
                    return `<span class="badge badge-warning badge-sm mb-1">${escapeHTML(v)}</span>`;
                }
            } else if (vLower.startsWith("'nonce-") || vLower.startsWith("'sha")) {
                return `<span class="badge badge-success badge-sm mb-1">${escapeHTML(v)}</span>`;
            } else {
                return `<span class="badge badge-default badge-sm mb-1">${escapeHTML(v)}</span>`;
            }
        }).join(" ");
        
        if (values.length === 0) {
            valuesHtml = '<span class="text-secondary italic">Không có giá trị</span>';
        }

        tbody.insertAdjacentHTML("beforeend", `
            <tr class="security-headers__tr">
                <td data-label="Chỉ thị (Directive)" class="font-bold">${escapeHTML(name)}</td>
                <td data-label="Các giá trị (Values)">${valuesHtml}</td>
            </tr>
        `);
    });

    const cspIssuesWrapper = document.getElementById("cspIssuesWrapper");
    const cspIssuesList = document.getElementById("cspIssuesList");
    
    if (cspHeader.csp_issues && cspHeader.csp_issues.length > 0) {
        cspIssuesWrapper.classList.remove("d-none");
        cspIssuesList.innerHTML = "";
        
        cspHeader.csp_issues.forEach(issue => {
            let icon = "fa-info-circle text-info";
            let colorClass = "text-info";
            let bgClass = "bg-surface";
            
            if (issue.severity === "high") {
                icon = "fa-circle-xmark";
                colorClass = "text-error";
                bgClass = "bg-error";
            } else if (issue.severity === "medium") {
                icon = "fa-triangle-exclamation";
                colorClass = "text-warning";
                bgClass = "bg-warning";
            } else if (issue.severity === "low") {
                icon = "fa-info-circle text-secondary";
                colorClass = "text-secondary";
            }
            
            cspIssuesList.insertAdjacentHTML("beforeend", `
                <div class="d-flex flex-row p-3 rounded-md ${bgClass} border border-border">
                    <div class="mr-3 mt-1 ${colorClass}">
                        <i class="fa-solid ${icon}"></i>
                    </div>
                    <div class="d-flex flex-col">
                        <span class="font-bold mb-1">Chỉ thị: <code class="bg-surface px-1 py-0.5 rounded-sm">${escapeHTML(issue.directive)}</code></span>
                        <span class="text-sm">${escapeHTML(issue.message)}</span>
                    </div>
                </div>
            `);
        });
    } else {
        cspIssuesWrapper.classList.add("d-none");
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
                box.classList.remove("d-block");
                box.classList.add("d-none");
            });
            const targetBox = document.getElementById(targetId);
            targetBox.classList.remove("d-none");
            targetBox.classList.add("d-block");
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
    const followCheckbox = document.getElementById("followRedirects");
    const isFollow = followCheckbox && followCheckbox.checked;
    return `${baseUrl}?url=${encodeURIComponent(targetUrl)}${isFollow ? '&followRedirects=true' : ''}`;
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

// ===========================
// RENDER: RAW HEADERS TAB
// ===========================

// Header bảo mật để highlight trong raw headers table
const SECURITY_HEADER_NAMES = new Set([
    'content-security-policy', 'content-security-policy-report-only',
    'strict-transport-security', 'x-frame-options', 'x-content-type-options',
    'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy',
    'cross-origin-embedder-policy', 'cross-origin-resource-policy',
    'x-xss-protection', 'report-to', 'reporting-endpoints', 'nel', 'expect-ct', 'feature-policy', 'set-cookie', 'server', 'x-powered-by',
]);

function renderRawHeaders(rawHeaders) {
    const tbody = document.getElementById("rawHeadersTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!rawHeaders || rawHeaders.length === 0) {
        tbody.innerHTML = `<tr><td colspan="2" class="text-secondary text-center">Không có dữ liệu.</td></tr>`;
        return;
    }

    rawHeaders.forEach(h => {
        const isSecHeader = SECURITY_HEADER_NAMES.has(h.name.toLowerCase());
        const nameClass = isSecHeader ? "font-bold text-success" : "font-bold";
        tbody.insertAdjacentHTML("beforeend", `
            <tr class="security-headers__tr">
                <td class="${nameClass}" data-label="Header">${escapeHTML(h.name)}</td>
                <td class="raw-header-value" data-label="Giá trị">${escapeHTML(h.value)}</td>
            </tr>
        `);
    });
}

// ===========================
// RENDER: ADDITIONAL INFO SECTION
// ===========================

function renderAdditionalInfo(additionalInfo) {
    const tbody = document.getElementById("additionalInfoTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!additionalInfo || additionalInfo.length === 0) return;

    additionalInfo.forEach(item => {
        let badgeHtml = "";
        switch (item.status) {
            case "ok":
                badgeHtml = `<span class="badge badge-success"><i class="fa-solid fa-check mr-1"></i> Tốt</span>`;
                break;
            case "warning":
                badgeHtml = `<span class="badge badge-warning"><i class="fa-solid fa-triangle-exclamation mr-1"></i> Cảnh báo</span>`;
                break;
            case "deprecated":
                badgeHtml = `<span class="badge badge-warning"><i class="fa-solid fa-clock mr-1"></i> Deprecated</span>`;
                break;
            default: // "info"
                if (item.present) {
                    badgeHtml = `<span class="badge badge-info"><i class="fa-solid fa-circle-info mr-1"></i> Có</span>`;
                } else {
                    const deprecatedHeaders = ['x-xss-protection', 'expect-ct', 'feature-policy'];
                    if (deprecatedHeaders.includes(item.name.toLowerCase())) {
                        badgeHtml = `<span class="badge badge-default"><i class="fa-solid fa-minus mr-1"></i> Không cần thiết</span>`;
                    } else {
                        badgeHtml = `<span class="badge badge-default"><i class="fa-solid fa-minus mr-1"></i> Không có</span>`;
                    }
                }
        }

        const valueHtml = item.value
            ? `<span class="additional-info-value">${escapeHTML(item.value)}</span>`
            : `<span class="text-secondary">—</span>`;

        tbody.insertAdjacentHTML("beforeend", `
            <tr class="security-headers__tr">
                <td class="font-bold" data-label="Header">${escapeHTML(item.name)}</td>
                <td data-label="Trạng thái">${badgeHtml}</td>
                <td data-label="Giá trị">${valueHtml}</td>
                <td class="additional-info__desc" data-label="Mô tả">${escapeHTML(item.description)}</td>
            </tr>
        `);
    });
}
