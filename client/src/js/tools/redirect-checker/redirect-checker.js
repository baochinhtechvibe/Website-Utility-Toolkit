/**
 * redirect.js
 * Logic cho Redirect Analyzer Tool
 */

import { $, $$, createRealtimeURLValidator } from '../../utils/index.js';
import { API_BASE_URL } from '../../config.js';

// ==============================
// Khởi tạo
// ==============================
document.addEventListener('DOMContentLoaded', () => {
    console.log("🚀 Redirect Analyzer Tool Initialized");
    initRedirectAnalyzer();
});

function initRedirectAnalyzer() {
    setupEventListeners();
    loadFromURL();
}

// ==============================
// Event Listeners
// ==============================
function setupEventListeners() {
    const form = $('#redirectForm');
    const uaSelect = $('#userAgent');
    const compareCheckbox = $('#compareUAs');
    const urlInput = $('#redirectUrl');

    form?.addEventListener('submit', (e) => {
        e.preventDefault();
        handleAnalyze();
    });

    // ---- Realtime URL validation (dùng utility dùng chung) ----
    if (urlInput) {
        createRealtimeURLValidator(
            urlInput,
            $('#urlValidationError'),
            $('#btnAnalyze')
        );

        // Ẩn bảng lỗi và bảng kết quả cũ khi bắt đầu gõ URL mới
        urlInput.addEventListener('input', () => {
            hideError();
            hideResults();
        });
    }

    // Hiện/ẩn Custom UA input
    uaSelect?.addEventListener('change', () => {
        const customField = $('#customUAField');
        if (uaSelect.value === 'custom') {
            customField?.classList.remove('d-none');
        } else {
            customField?.classList.add('d-none');
        }
    });

    // Hiện/ẩn compare card khi check
    compareCheckbox?.addEventListener('change', () => {
        const compareCard = $('#compareCard');
        if (compareCheckbox.checked) {
            compareCard?.classList.remove('d-none');
        } else {
            compareCard?.classList.add('d-none');
        }
    });

    // Làm mới (Refresh)
    $('#btnBypassCacheRedirect')?.addEventListener('click', () => {
        handleAnalyze();
    });

    // Copy chain
    $('#btnCopyChain')?.addEventListener('click', copyChain);

    // Export JSON
    $('#btnExportJson')?.addEventListener('click', exportJson);

    // Copy share link
    $('#btnCopyLink')?.addEventListener('click', () => {
        const text = $('#shareLink')?.value;
        copyText(text, $('#btnCopyLink'));
    });

    // Global copy handler for .js-copy-code (code-blocks)
    document.addEventListener("click", async (e) => {
        const btn = e.target.closest(".js-copy-code");
        if (!btn) return;
        if (btn.disabled) return;

        try {
            const selector = btn.getAttribute("data-clipboard-target");
            if (!selector) return;

            const codeEl = document.querySelector(selector);
            if (!codeEl) return;

            btn.disabled = true;
            const textToCopy = codeEl.innerText || codeEl.textContent;
            await navigator.clipboard.writeText(textToCopy.trim());

            const originalHTML = btn.innerHTML;
            btn.innerHTML = `<i class="fa-solid fa-check"></i>`;

            setTimeout(() => {
                btn.innerHTML = originalHTML;
                btn.disabled = false;
            }, 2000);
        } catch (err) {
            btn.disabled = false;
            console.error("COPY FAIL:", err);
        }
    });
}

// (validateURLRealtime đã được chuyển vào utils/validation.js)


// ==============================
// Đọc URL params khi mở link chia sẻ
// ==============================
function loadFromURL() {
    const params = new URLSearchParams(window.location.search);
    const url = params.get('url');
    if (url) {
        const input = $('#redirectUrl');
        if (input) input.value = url;
        handleAnalyze();
    }
}

// ==============================
// Handler chính: gọi API
// ==============================
async function handleAnalyze() {
    const urlInput = $('#redirectUrl');
    const url = urlInput?.value.trim();

    // Validate URL
    hideError();
    if (!url || !isValidURL(url)) {
        showURLValidationError();
        return;
    }

    const ua = getEffectiveUA();
    const deepScan = $('#deepScan')?.checked ?? false;
    const ignoreTlsErrors = $('#ignoreTLSErrors')?.checked ?? false;
    const compareMode = $('#compareUAs')?.checked ?? false;

    setLoading(true);
    hideResults();
    const cacheNoticeAtStart = $('#cacheNoticeRedirect');
    if (cacheNoticeAtStart) {
        cacheNoticeAtStart.classList.add('d-none');
        cacheNoticeAtStart.classList.remove('d-flex');
    }

    try {
        const data = await fetchAnalysis(url, ua, deepScan, ignoreTlsErrors);
        renderResults(data.data, url);

        if (compareMode) {
            const compData = await fetchCompareUAs(url);
            renderCompare(compData);
        }

        updateShareLink(url);
        updateURL(url);
    } catch (err) {
        showError(err.message || 'Không thể kết nối tới URL. Vui lòng thử lại!');
    } finally {
        setLoading(false);
    }
}

// ==============================
// Lấy User-Agent hiệu lực
// ==============================
function getEffectiveUA() {
    const select = $('#userAgent');
    if (!select) return '';
    if (select.value === 'custom') {
        return $('#customUserAgent')?.value.trim() || select.value;
    }
    return select.value;
}

// ==============================
// Gọi API phân tích redirect
// ==============================
async function fetchAnalysis(url, ua, deepScan, ignoreTlsErrors = false) {
    const response = await fetch(`${API_BASE_URL}/redirect-checker/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, userAgent: ua, deepScan, ignoreTlsErrors })
    });

    if (!response.ok) {
        if (response.status === 404) throw new Error("URL không tồn tại (404)");
        if (response.status === 403) throw new Error("Truy cập bị chặn (403)");
        if (response.status === 504) throw new Error("Backend timeout (504)");
        throw new Error(`Lỗi HTTP: ${response.status}`);
    }

    const jsonData = await response.json();

    if (!jsonData.success) {
        throw new Error(jsonData.message || `Lỗi server: ${response.status}`);
    }
    return jsonData;
}

// ==============================
// Gọi API so sánh nhiều UA
// ==============================
async function fetchCompareUAs(url) {
    const UAs = [
        { label: 'Chrome Desktop', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36' },
        { label: 'iPhone Safari', ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1' },
        { label: 'Googlebot', ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' },
        { label: 'Facebook Bot', ua: 'facebookexternalhit/1.1' },
    ];

    const results = await Promise.allSettled(
        UAs.map(({ label, ua }) =>
            fetchAnalysis(url, ua, false)
                .then(data => ({ label, data }))
                .catch(() => ({ label, data: null }))
        )
    );

    return results.map(r => r.value ?? { label: '?', data: null });
}

// ==============================
// Render toàn bộ kết quả
// ==============================
let _lastData = null;

function renderResults(res, url) {
    if (!res) return;
    
    const chain = res.chain || [];
    const sec = res.security || {};
    const perf = res.performance || {};
    
    // 1. Map Timings & Location Headers & Detect Loop
    const urls = new Set();
    let hasLoop = false;
    
    chain.forEach(step => {
        // Map timings
        if (step.timings) {
            step.dnsMs = step.timings.dnsLookup;
            step.tcpMs = step.timings.tcpConnection;
            step.tlsMs = step.timings.tlsHandshake;
            step.ttfbMs = step.timings.ttfb;
            step.totalMs = step.timings.total;
        }
        
        // Map location
        if (step.headers) {
            const locHead = Object.keys(step.headers).find(k => k.toLowerCase() === 'location');
            if (locHead && step.headers[locHead].length > 0) {
                step.location = step.headers[locHead][0];
            }
        }
        
        // Detect loop
        if (urls.has(step.url)) {
            hasLoop = true;
            step.isLoop = true;
        }
        urls.add(step.url);
    });

    // 2. Computed Security
    res.computedSecurity = {
        httpsDowngrade: sec.isHttpsDowngrade || false,
        openRedirect: sec.isOpenRedirect || false,
        redirectLoop: hasLoop,
        tooManyRedirects: perf.tooMany || (chain.length > 3)
    };

    // 3. Compute Score
    let score = 100;
    let issues = [];
    
    if (res.computedSecurity.httpsDowngrade) { score -= 30; issues.push({type: 'deduct', label: 'HTTPS Downgrade', value: 30}); }
    if (res.computedSecurity.openRedirect) { score -= 40; issues.push({type: 'deduct', label: 'Có thể bị Open Redirect', value: 40}); }
    if (res.computedSecurity.redirectLoop) { score -= 100; issues.push({type: 'deduct', label: 'Vòng lặp Redirect', value: 100}); }
    if (res.computedSecurity.tooManyRedirects) { score -= 20; issues.push({type: 'deduct', label: 'Quá nhiều bước redirect', value: 20}); }
    
    let totalMs = perf.totalTime || 0;
    if (totalMs > 1000) { score -= 15; issues.push({type: 'deduct', label: 'Tổng request chậm (>1s)', value: 15}); }
    else if (totalMs > 500) { score -= 5; issues.push({type: 'deduct', label: 'Dấu hiệu chậm (>500ms)', value: 5}); }
    
    const validRedirectsCount = (chain.length > 0) ? chain.length - 1 : 0;
    if (validRedirectsCount > 0 && !hasLoop && !res.computedSecurity.tooManyRedirects) {
         issues.push({type: 'deduct', label: `Bị delay bởi ${validRedirectsCount} bước redirect`, value: validRedirectsCount*5});
         score -= validRedirectsCount*5;
    }
    
    res.score = Math.max(0, score);
    res.scoreIssues = issues;
    
    // Mock save
    _lastData = res;
    showResults();

    // Show cache notice with timestamp
    const cacheNotice = $('#cacheNoticeRedirect');
    const cacheTime = $('#cacheTimeRedirect');
    if (cacheNotice && cacheTime) {
        const now = new Date();
        const timeStr = now.toLocaleTimeString('vi-VN', { hour12: false }) + ' ' + now.toLocaleDateString('vi-VN');
        cacheTime.textContent = timeStr;
        cacheNotice.classList.remove('d-none');
        cacheNotice.classList.add('d-flex');
    }

    renderScore(res);
    renderChain(chain);
    renderSecurity(res.computedSecurity);
    renderPerformance(chain);
    renderSEO(res.seo || {});
    renderCurl(url, chain);
}

// ==============================
// 1. Score
// ==============================
function renderScore(data) {
    const badge = $('#scoreBadge');
    const breakdown = $('#scoreBreakdown');
    if (!badge || !breakdown) return;

    const score = data.score ?? 100;
    const issues = data.scoreIssues ?? [];

    badge.className = 'redirect-score__badge ' + scoreClass(score);
    badge.innerHTML = `<span id="scoreValue">${score}</span><small>/100</small>`;

    breakdown.innerHTML = issues.length === 0
        ? `<span class="redirect-score__item redirect-score__item--ok"><i class="fa-solid fa-circle-check"></i> Không có vấn đề nào phát hiện</span>`
        : issues.map(i => `
            <div class="redirect-score__item redirect-score__item--${i.type}">
                <i class="fa-solid fa-${i.type === 'deduct' ? 'minus' : 'check'}-circle"></i>
                ${escHtml(i.label)} <strong>(${i.value > 0 ? '-' : ''}${Math.abs(i.value)})</strong>
            </div>`).join('');
}

function scoreClass(s) {
    if (s >= 90) return 'redirect-score__badge--great';
    if (s >= 70) return 'redirect-score__badge--good';
    if (s >= 50) return 'redirect-score__badge--warn';
    return 'redirect-score__badge--bad';
}

// ==============================
// 2. Visual Chain
// ==============================
function renderChain(steps) {
    const container = $('#redirectChain');
    const penaltySummary = $('#penaltySummary');
    const totalPenaltyEl = $('#totalPenalty');
    if (!container) return;

    if (steps.length === 0) {
        container.innerHTML = `<p class="text-muted text-sm">Không có dữ liệu chuỗi redirect.</p>`;
        return;
    }

    // Tìm step chậm nhất
    const maxTime = Math.max(...steps.map(s => s.totalMs ?? 0));
    const totalPenalty = steps.slice(0, -1).reduce((sum, s) => sum + (s.totalMs ?? 0), 0);

    container.innerHTML = steps.map((step, idx) => {
        const isFinal = idx === steps.length - 1;
        const isSlowest = maxTime > 0 && (step.totalMs ?? 0) === maxTime && steps.length > 1;
        const isLoop = step.isLoop ?? false;

        const nodeClass = isLoop ? 'redirect-step__node--loop'
            : isFinal ? `redirect-step__node--${statusClass(step.statusCode)}`
            : `redirect-step__node--${statusClass(step.statusCode)}`;

        const contentExtra = isLoop ? 'redirect-step__content--loop'
            : isSlowest ? 'redirect-step__content--slowest' : '';

        const badges = buildStatusBadge(step.statusCode);
        const locationLine = step.location
            ? `<span class="redirect-step__badge--location">→ ${escHtml(step.location)}</span>` : '';

        const slowTag = isSlowest && steps.length > 1
            ? `<span class="redirect-step__badge" style="background:var(--orange-100);color:var(--orange-700)"><i class="fa-solid fa-fire"></i> Chậm nhất</span>` : '';

        const loopTag = isLoop
            ? `<span class="redirect-step__badge" style="background:var(--purple-100);color:var(--purple-700)"><i class="fa-solid fa-arrow-rotate-left"></i> LOOP</span>` : '';

        return `
        <div class="redirect-step">
            <div class="redirect-step__node ${nodeClass}">${step.statusCode ?? '?'}</div>
            <div class="redirect-step__content ${contentExtra}">
                <div class="redirect-step__header">
                    <span class="redirect-step__url">${escHtml(step.url ?? '')}</span>
                    <div class="redirect-step__meta">
                        ${badges}
                        ${slowTag}
                        ${loopTag}
                        <span class="redirect-step__timing">${step.totalMs != null ? step.totalMs + 'ms' : ''}</span>
                    </div>
                </div>
                ${locationLine}
            </div>
        </div>`;
    }).join('');

    // Penalty summary
    if (steps.length > 1 && penaltySummary && totalPenaltyEl) {
        totalPenaltyEl.textContent = `+${totalPenalty}ms`;
        penaltySummary.classList.remove('d-none');
    }
}

function statusClass(code) {
    if (!code) return '3xx';
    if (code === 301) return '301';
    if (code === 302) return '302';
    if (code >= 200 && code < 300) return '2xx';
    if (code >= 300 && code < 400) return '3xx';
    if (code >= 400 && code < 500) return '4xx';
    if (code >= 500) return '5xx';
    return '3xx';
}

function buildStatusBadge(code) {
    const colors = {
        '2xx': 'var(--green-100)', '2xx-t': 'var(--green-800)',
        '301': 'var(--yellow-100)', '301-t': 'var(--yellow-800)',
        '302': 'var(--orange-100)', '302-t': 'var(--orange-800)',
        '3xx': 'var(--orange-50)', '3xx-t': 'var(--orange-700)',
        '4xx': 'var(--red-100)', '4xx-t': 'var(--red-800)',
        '5xx': 'var(--red-200)', '5xx-t': 'var(--red-900)',
    };
    const cls = statusClass(code);
    const bg = colors[cls] ?? 'var(--gray-100)';
    const fg = colors[`${cls}-t`] ?? 'var(--gray-800)';
    return `<span class="redirect-step__badge" style="background:${bg};color:${fg}">${code ?? '?'}</span>`;
}

// ==============================
// 3. Security Audit
// ==============================
function renderSecurity(sec) {
    const container = $('#securityResults');
    if (!container) return;

    const checks = [
        {
            key: 'httpsDowngrade',
            title: 'HTTPS → HTTP Downgrade',
            passDesc: 'Không phát hiện downgrade từ HTTPS về HTTP.',
            failDesc: 'Phát hiện ít nhất một bước chuyển từ HTTPS xuống HTTP! Điều này có thể lộ dữ liệu người dùng.',
        },
        {
            key: 'openRedirect',
            title: 'Open Redirect',
            passDesc: 'Không phát hiện dấu hiệu lỗ hổng Open Redirect.',
            failDesc: 'Cảnh báo: URL có thể bị lợi dụng để chuyển hướng đến trang lừa đảo bên ngoài.',
        },
        {
            key: 'redirectLoop',
            title: 'Redirect Loop',
            passDesc: 'Không phát hiện vòng lặp trong chuỗi redirect.',
            failDesc: 'Phát hiện vòng lặp redirect (A → B → A). Trang sẽ không tải được!',
        },
        {
            key: 'tooManyRedirects',
            title: 'Quá nhiều bước redirect',
            passDesc: 'Số lượng redirect nằm trong ngưỡng an toàn (≤ 3 bước).',
            failDesc: 'Chuỗi redirect quá dài (> 3 bước). Gây hại cho SEO và làm chậm trải nghiệm người dùng.',
        },
    ];

    container.innerHTML = checks.map(c => {
        const val = sec[c.key]; // true = có vấn đề, false = ok
        const status = val ? 'fail' : 'pass';
        const icon = val ? 'fa-triangle-exclamation' : 'fa-circle-check';
        const desc = val ? c.failDesc : c.passDesc;
        return `
        <div class="security-item security-item--${status}">
            <div class="security-item__icon"><i class="fa-solid ${icon}"></i></div>
            <div>
                <div class="security-item__title">${escHtml(c.title)}</div>
                <div class="security-item__desc">${escHtml(desc)}</div>
            </div>
        </div>`;
    }).join('');
}

// ==============================
// 4. Performance table
// ==============================
function renderPerformance(steps) {
    const tbody = $('#perfTableBody');
    if (!tbody) return;

    tbody.innerHTML = steps.map((s, i) => {
        const slow = ms => (ms != null && ms > 500) ? 'perf-cell--slow' : '';
        return `<tr>
            <td>${i + 1}</td>
            <td style="font-family:var(--font-family-mono);font-size:var(--text-xs);word-break:break-all">${escHtml(s.url ?? '')}</td>
            <td class="${slow(s.dnsMs)}">${s.dnsMs != null ? s.dnsMs + 'ms' : '-'}</td>
            <td class="${slow(s.tcpMs)}">${s.tcpMs != null ? s.tcpMs + 'ms' : '-'}</td>
            <td class="${slow(s.tlsMs)}">${s.tlsMs != null ? s.tlsMs + 'ms' : '-'}</td>
            <td class="${slow(s.ttfbMs)}">${s.ttfbMs != null ? s.ttfbMs + 'ms' : '-'}</td>
            <td class="${slow(s.totalMs)}"><strong>${s.totalMs != null ? s.totalMs + 'ms' : '-'}</strong></td>
        </tr>`;
    }).join('');
}

// ==============================
// 5. SEO & Social Meta
// ==============================
function renderSEO(seo) {
    const container = $('#seoResults');
    if (!container) return;

    const items = [
        { label: 'Final URL Status',   value: seo.finalStatus ?? null, key: 'finalStatus' },
        { label: 'Canonical URL',      value: seo.canonical  ?? null },
        { label: 'Robots Meta',        value: seo.robots     ?? null },
        { label: 'OG Title',           value: seo.ogTitle    ?? null },
        { label: 'OG Image',           value: seo.ogImage    ?? null },
        { label: 'OG URL',             value: seo.ogUrl      ?? null },
        { label: 'Twitter Card',       value: seo.twitterCard ?? null },
    ];

    container.innerHTML = items.map(item => {
        const isMissing = item.value == null || item.value === '';
        const display = isMissing ? 'Không tìm thấy' : item.value;
        const valueCls = isMissing ? 'seo-item__value--missing' : 'seo-item__value';
        return `
        <div class="seo-item">
            <span class="seo-item__label">${escHtml(item.label)}</span>
            <span class="${valueCls}">${escHtml(display)}</span>
        </div>`;
    }).join('');
}

// ==============================
// 6. cURL Output
// ==============================
function renderCurl(url, steps) {
    const curlEl = $('#curlOutput');
    const pathEl = $('#pathOutput');

    if (curlEl) {
        curlEl.textContent = `curl -v -L -A "Mozilla/5.0 (compatible; RedirectAnalyzer/1.0)" \\\n  "${url}"`;
    }

    if (pathEl) {
        pathEl.textContent = steps.map((s, i) => `# Step ${i + 1} → ${s.statusCode ?? '?'} ${s.url ?? ''}`).join('\n');
    }
}

// ==============================
// 7. So sánh UA
// ==============================
function renderCompare(results) {
    const tbody = $('#compareTableBody');
    const warningEl = $('#compareWarning');
    const warningMsg = $('#compareWarningMsg');
    if (!tbody) return;

    const finalUrls = results.map(r => r.data?.steps?.at(-1)?.url ?? '').filter(Boolean);
    const allSame = finalUrls.every(u => u === finalUrls[0]);

    tbody.innerHTML = results.map(r => {
        const steps = r.data?.data?.chain ?? [];
        const lastStep = steps.at(-1);
        return `<tr>
            <td style="font-size:var(--text-sm)">${escHtml(r.label)}</td>
            <td>${steps.length}</td>
            <td style="font-family:var(--font-family-mono);font-size:var(--text-xs);word-break:break-all">${escHtml(lastStep?.url ?? '-')}</td>
            <td>${buildStatusBadge(lastStep?.statusCode)}</td>
        </tr>`;
    }).join('');

    if (!allSame && warningEl && warningMsg) {
        warningMsg.textContent = 'Các User-Agent khác nhau nhận được redirect khác nhau. Hãy kiểm tra cấu hình server!';
        warningEl.classList.remove('d-none');
    }
}

// ==============================
// UI State helpers
// ==============================
function setLoading(state) {
    const icon = $('#analyzeIcon');
    const spinner = $('#analyzeLoading');
    const btn = $('#btnAnalyze');
    if (state) {
        icon?.classList.add('d-none');
        spinner?.classList.remove('d-none');
        if (btn) btn.disabled = true;
    } else {
        icon?.classList.remove('d-none');
        spinner?.classList.add('d-none');
        if (btn) btn.disabled = false;
    }
}

function showResults() {
    $('#resultSection')?.classList.remove('d-none');
    $('#errorCard')?.classList.add('d-none');
}

function hideResults() {
    $('#resultSection')?.classList.add('d-none');
}

function showError(msg) {
    const card = $('#errorCard');
    const msgEl = $('#errorMessage');
    if (msgEl) msgEl.textContent = msg;
    card?.classList.remove('d-none');
}

function hideError() {
    $('#errorCard')?.classList.add('d-none');
}

function showURLValidationError() {
    $('#urlValidationError')?.classList.remove('d-none');
    $('#redirectUrl')?.classList.add('is-invalid');
}

function updateShareLink(url) {
    const input = $('#shareLink');
    if (!input) return;
    const shareUrl = `${window.location.origin}${window.location.pathname}?url=${encodeURIComponent(url)}`;
    input.value = shareUrl;
}

function updateURL(url) {
    const params = new URLSearchParams(window.location.search);
    params.set('url', url);
    const newURL = `${window.location.pathname}?${params.toString()}`;
    window.history.pushState({ url }, '', newURL);
}

// ==============================
// Copy & Export helpers
// ==============================
function copyChain() {
    const steps = _lastData?.chain ?? [];
    const text = steps.map((s, i) => `${i + 1}. [${s.statusCode}] ${s.url}`).join('\n');
    copyText(text, $('#btnCopyChain'));
}

function exportJson() {
    if (!_lastData) return;
    const json = JSON.stringify(_lastData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'redirect-analysis.json';
    a.click();
}

async function copyText(text, btn) {
    if (!text) return;
    try {
        await navigator.clipboard.writeText(text);
        const original = btn?.innerHTML;
        if (btn) btn.innerHTML = '<i class="fa-solid fa-check"></i>';
        setTimeout(() => { if (btn) btn.innerHTML = original; }, 1500);
    } catch { /* ignore */ }
}

// ==============================
// Utils
// ==============================
function isValidURL(str) {
    try {
        const u = new URL(str);
        return u.protocol === 'http:' || u.protocol === 'https:';
    } catch { return false; }
}

function escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
