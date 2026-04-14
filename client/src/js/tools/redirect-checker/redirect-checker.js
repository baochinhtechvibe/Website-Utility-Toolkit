/**
 * redirect-checker.js
 * Logic cho Redirect Analyzer Tool
 * Refactored for Design System compliance
 */

import { $, $$, createRealtimeURLValidator } from '../../utils/index.js';
import { API_BASE_URL } from '../../config.js';

// ==============================
// State & Initialization
// ==============================
let isProcessing = false;
let _lastData = null;

/**
 * Initialize the tool
 */
function init() {
    console.log("🚀 Redirect Analyzer Tool Initialized");
    setupEventListeners();
    loadFromURL();

    // Handle back/forward browser buttons
    window.addEventListener("popstate", (e) => {
        const url = e.state?.url || new URLSearchParams(window.location.search).get('url');
        const input = $('#redirectUrl');
        
        if (url) {
            if (input) input.value = url;
            handleAnalyze();
        } else {
            if (input) input.value = '';
            hideResults();
            hideError();
        }
    });
}

// Khởi chạy khi DOM sẵn sàng
document.addEventListener('DOMContentLoaded', init);

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

    // Real-time URL validation
    if (urlInput) {
        createRealtimeURLValidator(
            urlInput,
            $('#urlValidationError'),
            $('#btnAnalyze')
        );

        // Clear UI when user starts typing new URL
        urlInput.addEventListener('input', () => {
            hideError();
            hideResults();
            const btn = $('#btnAnalyze');
            if (btn) btn.disabled = !isValidURL(urlInput.value.trim());
        });
    }

    // Toggle Custom User-Agent input
    uaSelect?.addEventListener('change', () => {
        const customField = $('#customUAField');
        if (uaSelect.value === 'custom') {
            customField?.classList.remove('d-none');
        } else {
            customField?.classList.add('d-none');
        }
    });

    // Toggle comparison card visibility
    compareCheckbox?.addEventListener('change', () => {
        const compareCard = $('#compareCard');
        if (compareCheckbox.checked) {
            compareCard?.classList.remove('d-none');
        } else {
            compareCard?.classList.add('d-none');
        }
    });

    // Refresh button (Bypass Cache)
    $('#btnBypassCache')?.addEventListener('click', () => {
        handleAnalyze(true);
    });

    // Actions
    $('#btnCopyChain')?.addEventListener('click', copyChain);
    $('#btnExportJson')?.addEventListener('click', exportJson);
    $('#btnCopyLink')?.addEventListener('click', () => {
        const text = $('#shareLink')?.value;
        copyText(text, $('#btnCopyLink'));
    });

    // Code block copy handler
    document.addEventListener("click", async (e) => {
        const btn = e.target.closest(".js-copy-code");
        if (!btn) return;
        if (btn.disabled) return;

        try {
            const selector = btn.getAttribute("data-clipboard-target");
            if (!selector) return;

            const codeEl = $(selector);
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

// ==============================
// Analysis Logic
// ==============================

/**
 * Handle analysis from URL params
 */
function loadFromURL() {
    const params = new URLSearchParams(window.location.search);
    const url = params.get('url');
    if (url) {
        const input = $('#redirectUrl');
        if (input) input.value = url;
        handleAnalyze();
    }
}

/**
 * Main analysis handler
 */
async function handleAnalyze(bypassCache = false) {
    const urlInput = $('#redirectUrl');
    const url = urlInput?.value.trim();

    if (!url || !isValidURL(url)) {
        showURLValidationError();
        return;
    }

    if (isProcessing) return;
    isProcessing = true;

    const ua = getEffectiveUA();
    const deepScan = $('#deepScan')?.checked ?? false;
    const ignoreTlsErrors = $('#ignoreTLSErrors')?.checked ?? false;
    const compareMode = $('#compareUAs')?.checked ?? false;

    setLoading(true);
    hideResults();
    hideError();
    
    // Hide cache notice before starting
    const cn = $('#cacheNotice');
    if (cn) cn.classList.add('d-none');

    try {
        const data = await fetchAnalysis(url, ua, deepScan, ignoreTlsErrors, bypassCache);
        renderResults(data.data, url, data.meta);

        if (compareMode) {
            const compData = await fetchCompareUAs(url);
            renderCompare(compData);
        }

        updateShareLink(url);
        updateURL(url);
    } catch (err) {
        showError(err.message || 'Không thể phân tích chuyển hướng. Vui lòng thử lại!');
    } finally {
        isProcessing = false;
        setLoading(false);
    }
}

/**
 * Fetch analysis data from API
 */
async function fetchAnalysis(url, ua, deepScan, ignoreTlsErrors = false, bypassCache = false) {
    let endpoint = `${API_BASE_URL}/redirect-checker/analyze`;
    if (bypassCache) {
        endpoint += '?bypassCache=true';
    }

    const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, userAgent: ua, deepScan, ignoreTlsErrors })
    });

    if (!response.ok) {
        const text = await response.text();
        let errorMsg = `Lỗi hệ thống (${response.status})`;
        try {
            const errJson = JSON.parse(text);
            errorMsg = errJson.error || errJson.message || errorMsg;
        } catch(e) {}
        throw new Error(errorMsg);
    }

    return await response.json();
}

/**
 * Get effective User-Agent string
 */
function getEffectiveUA() {
    const select = $('#userAgent');
    if (!select) return '';
    if (select.value === 'custom') {
        return $('#customUserAgent')?.value.trim() || 'Custom Bot';
    }
    return select.value;
}

/**
 * Multi-UA Comparison
 */
async function fetchCompareUAs(url) {
    const UAs = [
        { label: 'Chrome Desktop', ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36' },
        { label: 'iPhone Safari', ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1' },
        { label: 'Googlebot', ua: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' }
    ];

    const results = await Promise.allSettled(
        UAs.map(({ label, ua }) =>
            fetchAnalysis(url, ua, false)
                .then(data => ({ label, data }))
                .catch(() => ({ label, data: null }))
        )
    );

    return results.map(r => r.value || { label: '?', data: null });
}

// ==============================
// Rendering Logic
// ==============================

/**
 * Render all results
 */
function renderResults(res, url, meta) {
    if (!res) return;
    
    _lastData = res;
    
    // Process logic for Chain
    const chain = res.chain || [];
    const sec = res.security || {};
    const perf = res.performance || {};
    
    const lastHop = chain[chain.length - 1];
    const isError = lastHop && lastHop.statusCode >= 400;

    // Manage dynamic title
    const titleEl = $('#resultsTitle');
    if (titleEl) {
        if (isError) {
            titleEl.innerHTML = `<i class="fa-solid fa-circle-xmark text-error mr-2"></i> Phát hiện lỗi ${lastHop.statusCode} tại trang đích`;
            titleEl.classList.add('text-error');
        } else {
            titleEl.innerHTML = `<i class="fa-solid fa-circle-check text-success mr-2"></i> Kết quả phân tích cho "${escHtml(url)}"`;
            titleEl.classList.remove('text-error');
        }
    }

    // Managed Cache Notice
    const cacheNotice = $('#cacheNotice');
    if (cacheNotice && meta && meta.fetched_at) {
        const cacheTime = $('#cacheTime');
        const cacheText = $('#cacheText');
        
        const date = new Date(meta.fetched_at);
        const timeStr = date.toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + ' ' + date.toLocaleDateString('vi-VN');
        
        if (cacheTime) cacheTime.textContent = timeStr;
        if (cacheText) {
            cacheText.textContent = meta.cached 
                ? "Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc" 
                : "Kết quả tra cứu mới nhất lúc";
        }

        cacheNotice.classList.remove('d-none');
    }
    
    const urlsInChain = new Set();
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
        
        // Detect loop
        if (urlsInChain.has(step.url)) {
            hasLoop = true;
            step.isLoop = true;
        }
        urlsInChain.add(step.url);
    });

    // Score Calculation
    let score = 100;
    let issues = [];
    
    if (isError) {
        score -= 50;
        issues.push({ type: 'deduct', label: `Trang đích trả về lỗi ${lastHop.statusCode}`, value: 50 });
    }
    if (sec.isHttpsDowngrade) { score -= 30; issues.push({ type: 'deduct', label: 'HTTPS Downgrade (Nguy hiểm)', value: 30 }); }
    if (sec.isOpenRedirect) { score -= 40; issues.push({ type: 'deduct', label: 'Có dấu hiệu Open Redirect', value: 40 }); }
    if (hasLoop) { score -= 100; issues.push({ type: 'deduct', label: 'Vòng lặp (Redirect Loop)', value: 100 }); }
    
    const totalHops = chain.length > 0 ? chain.length : 0;
    const actualRedirectHops = chain.filter(h => h.statusCode >= 300 && h.statusCode < 400).length;
    
    if (actualRedirectHops > 3) {
        score -= 20;
        issues.push({ type: 'deduct', label: `Quá nhiều bước chuyển hướng (${actualRedirectHops} bước)`, value: 20 });
    } else if (actualRedirectHops > 0) {
        const malus = actualRedirectHops * 5;
        score -= malus;
        issues.push({ type: 'deduct', label: `Bị chậm bởi ${actualRedirectHops} bước redirect`, value: malus });
    }

    const totalTime = perf.totalTime || 0;
    if (totalTime > 1500) { score -= 15; issues.push({ type: 'deduct', label: 'Tổng thời gian phản hồi quá chậm (>1.5s)', value: 15 }); }

    res.computedScore = Math.max(0, score);
    res.computedIssues = issues;

    // Trigger rendering of components
    showResults();
    renderScore(res);
    renderChain(chain);
    renderSecurity(sec, hasLoop, actualRedirectHops);
    renderPerformance(chain);
    renderSEO(res.seo || {}, lastHop?.statusCode);
    renderCurl(url, chain);
}

/**
 * 1. Render Score Section
 */
function renderScore(res) {
    const badge = $('#scoreBadge');
    const breakdown = $('#scoreBreakdown');
    if (!badge || !breakdown) return;

    const score = res.computedScore;
    const issues = res.computedIssues;

    badge.className = `redirect-score__badge ${getScoreClass(score)}`;
    badge.innerHTML = `<span id="scoreValue">${score}</span><small>/100</small>`;

    if (issues.length === 0) {
        breakdown.innerHTML = `<div class="redirect-score__item redirect-score__item--ok"><i class="fa-solid fa-circle-check"></i> Hoàn hảo - Không có vấn đề nào được phát hiện.</div>`;
    } else {
        breakdown.innerHTML = issues.map(i => `
            <div class="redirect-score__item redirect-score__item--deduct">
                <i class="fa-solid fa-minus-circle"></i>
                ${escHtml(i.label)} <strong>(-${i.value})</strong>
            </div>
        `).join('');
    }
}

function getScoreClass(s) {
    if (s >= 90) return 'redirect-score__badge--great';
    if (s >= 70) return 'redirect-score__badge--good';
    if (s >= 40) return 'redirect-score__badge--warn';
    return 'redirect-score__badge--bad';
}

/**
 * 2. Render Vertical Chain
 */
function renderChain(steps) {
    const container = $('#redirectChain');
    const penaltySummary = $('#penaltySummary');
    const totalPenaltyEl = $('#totalPenalty');
    if (!container) return;

    if (steps.length === 0) {
        container.innerHTML = `<p class="text-muted">Không có dữ liệu chuỗi chuyển hướng.</p>`;
        return;
    }

    const maxTime = Math.max(...steps.map(s => s.totalMs || 0));
    const totalWait = steps.slice(0, -1).reduce((sum, s) => sum + (s.totalMs || 0), 0);

    container.innerHTML = steps.map((step, idx) => {
        const isFinal = idx === steps.length - 1;
        const isSlowest = maxTime > 0 && (step.totalMs || 0) === maxTime && steps.length > 1;
        const isLoop = step.isLoop || false;

        const nodeClass = isLoop ? 'redirect-step__node--loop' : 
                         (isFinal ? 'redirect-step__node--final' : `redirect-step__node--${getStatusGroup(step.statusCode)}`);

        const contentClass = isLoop ? 'redirect-step__content--loop' : (isSlowest ? 'redirect-step__content--slowest' : '');
        
        // Extract location
        let location = '';
        if (step.headers) {
            const keys = Object.keys(step.headers);
            const locKey = keys.find(k => k.toLowerCase() === 'location');
            if (locKey && step.headers[locKey].length > 0) location = step.headers[locKey][0];
        }

        return `
        <div class="redirect-step">
            <div class="redirect-step__node ${nodeClass}">${step.statusCode || '?'}</div>
            <div class="redirect-step__content ${contentClass}">
                <div class="redirect-step__header">
                    <span class="redirect-step__url">${escHtml(step.url || '')}</span>
                    <div class="redirect-step__meta">
                        ${renderBadge(step.statusCode)}
                        ${isSlowest && steps.length > 1 ? '<span class="badge badge-warning">CHẬM NHẤT</span>' : ''}
                        ${isLoop ? '<span class="badge badge-error">VÒNG LẶP</span>' : ''}
                        <span class="redirect-step__timing">${step.totalMs != null ? step.totalMs + 'ms' : ''}</span>
                    </div>
                </div>
                ${location ? `<span class="redirect-step__badge--location">→ ${escHtml(location)}</span>` : ''}
                ${step.error ? `<div class="redirect-step__error mt-2"><i class="fa-solid fa-triangle-exclamation mr-1"></i>${escHtml(step.error)}</div>` : ''}
            </div>
        </div>`;
    }).join('');

    if (steps.length > 1 && penaltySummary && totalPenaltyEl) {
        totalPenaltyEl.textContent = `${totalWait}ms`;
        penaltySummary.classList.remove('d-none');
    } else if (penaltySummary) {
        penaltySummary.classList.add('d-none');
    }
}

function getStatusGroup(code) {
    if (!code) return '3xx';
    if (code === 301) return '301';
    if (code === 302) return '302';
    if (code >= 200 && code < 300) return '2xx';
    if (code >= 300 && code < 400) return '3xx';
    if (code >= 400 && code < 500) return '4xx';
    return '5xx';
}

function renderBadge(code) {
    if (!code) return '<span class="badge badge-default">?</span>';
    const group = getStatusGroup(code);
    const map = {
        '2xx': 'badge-success',
        '301': 'badge-info',
        '302': 'badge-warning',
        '3xx': 'badge-warning',
        '4xx': 'badge-error',
        '5xx': 'badge-error'
    };
    return `<span class="badge ${map[group] || 'badge-default'}">${code}</span>`;
}

/**
 * 3. Render Security Items
 */
function renderSecurity(sec, hasLoop, hops) {
    const container = $('#securityResults');
    if (!container) return;

    const checks = [
        {
            key: 'https',
            title: 'HTTPS Downgrade',
            fail: sec.isHttpsDowngrade,
            passDesc: 'Không phát hiện bước hạ cấp HTTP không an toàn.',
            failDesc: 'Phát hiện bước chuyển hướng từ HTTPS về HTTP. Rất nguy hiểm!'
        },
        {
            key: 'open',
            title: 'Open Redirect',
            fail: sec.isOpenRedirect,
            passDesc: 'Không phát hiện rủi ro chuyển hướng hở cửa.',
            failDesc: 'Phát hiện mẫu URL có nguy cơ bị lợi dụng để Open Redirect.'
        },
        {
            key: 'loop',
            title: 'Redirect Loop',
            fail: hasLoop,
            passDesc: 'Không phát hiện vòng lặp vô hạn.',
            failDesc: 'Phát hiện vòng lặp vô hạn khiến trình duyệt không thể truy cập.'
        },
        {
            key: 'hops',
            title: 'Redirect Length',
            fail: hops > 3,
            passDesc: 'Số bước chuyển hướng nằm trong ngưỡng tối ưu (≤ 3).',
            failDesc: `Chuỗi chuyển hướng quá dài (${hops} bước). Ảnh hưởng xấu tới SEO.`
        }
    ];

    container.innerHTML = checks.map(c => `
        <div class="security-item security-item--${c.fail ? 'fail' : 'pass'}">
            <div class="security-item__icon">
                <i class="fa-solid ${c.fail ? 'fa-triangle-exclamation' : 'fa-circle-check'}"></i>
            </div>
            <div>
                <div class="security-item__title">${escHtml(c.title)}</div>
                <div class="security-item__desc">${escHtml(c.fail ? c.failDesc : c.passDesc)}</div>
            </div>
        </div>
    `).join('');
}

/**
 * 4. Render Latency Table
 */
function renderPerformance(steps) {
    const tbody = $('#perfTableBody');
    if (!tbody) return;

    tbody.innerHTML = steps.map((s, i) => {
        const isSlow = (val) => (val != null && val > 400) ? 'perf-cell--slow' : '';
        return `
        <tr>
            <td>${i + 1}</td>
            <td class="font-mono break-all">${escHtml(s.url || '')}</td>
            <td class="${isSlow(s.dnsMs)}">${s.dnsMs != null ? s.dnsMs + 'ms' : '-'}</td>
            <td class="${isSlow(s.tcpMs)}">${s.tcpMs != null ? s.tcpMs + 'ms' : '-'}</td>
            <td class="${isSlow(s.tlsMs)}">${s.tlsMs != null ? s.tlsMs + 'ms' : '-'}</td>
            <td class="${isSlow(s.ttfbMs)}">${s.ttfbMs != null ? s.ttfbMs + 'ms' : '-'}</td>
            <td class="${isSlow(s.totalMs)}"><strong>${s.totalMs != null ? s.totalMs + 'ms' : '-'}</strong></td>
        </tr>`;
    }).join('');
}

/**
 * 5. Render SEO Items
 */
function renderSEO(seo, finalStatus) {
    const container = $('#seoResults');
    if (!container) return;

    const fields = [
        { label: 'Trạng thái đích', value: finalStatus, code: true },
        { label: 'Thẻ Tiêu đề', value: seo.title },
        { label: 'Canonical', value: seo.canonical, mono: true },
        { label: 'Robots', value: seo.robots },
        { label: 'Open Graph Title', value: seo.ogTitle },
        { label: 'OG Image', value: seo.ogImage, mono: true }
    ];

    container.innerHTML = fields.map(f => {
        const missing = !f.value;
        const display = missing ? 'Không phát hiện' : f.value;
        const valClass = missing ? 'seo-item__value--missing' : (f.mono ? 'seo-item__value font-mono text-xs break-all' : 'seo-item__value');
        
        return `
        <div class="seo-item card card--flat">
            <div class="seo-item__body">
                <span class="badge badge-info uppercase mb-2">${escHtml(f.label)}</span>
                <div class="${valClass}">
                    ${f.code && !missing ? renderBadge(f.value) : escHtml(display)}
                </div>
            </div>
        </div>`;
    }).join('');
}

/**
 * 6. cURL & Path rendering
 */
function renderCurl(url, steps) {
    const curlEl = $('#curlOutput');
    const pathEl = $('#pathOutput');
    if (curlEl) curlEl.textContent = `curl -v -L -A "${getEffectiveUA()}" "${url}"`;
    if (pathEl) {
        pathEl.textContent = steps.map((s, i) => `Step ${i+1}: [${s.statusCode || '??'}] ${s.url}`).join('\n');
    }
}

/**
 * 7. Compare User-Agents
 */
function renderCompare(results) {
    const tbody = $('#compareTableBody');
    const warn = $('#compareWarning');
    const msg = $('#compareWarningMsg');
    if (!tbody) return;

    const destinations = results.map(r => r.data?.data?.chain?.at(-1)?.url || '').filter(Boolean);
    const differs = destinations.length > 1 && !destinations.every(d => d === destinations[0]);

    tbody.innerHTML = results.map(r => {
        const steps = r.data?.data?.chain || [];
        const last = steps.at(-1);
        return `
        <tr>
            <td class="text-sm">${escHtml(r.label)}</td>
            <td>${steps.length} bước</td>
            <td class="font-mono text-xs break-all">${escHtml(last?.url || '-')}</td>
            <td>${renderBadge(last?.statusCode)}</td>
        </tr>`;
    }).join('');

    if (differs && warn && msg) {
        msg.textContent = 'Phát hiện sự khác biệt về đích đến giữa các trình duyệt. Trang web có thể đang thực hiện Cloaking hoặc redirect theo thiết bị không đồng nhất.';
        warn.classList.remove('d-none');
    }
}

// ==============================
// UI Helpers
// ==============================
function setLoading(loading) {
    const icon = $('#analyzeIcon');
    const spin = $('#analyzeLoading');
    const btn = $('#btnAnalyze');
    if (loading) {
        icon?.classList.add('d-none');
        spin?.classList.remove('d-none');
        if (btn) btn.disabled = true;
    } else {
        icon?.classList.remove('d-none');
        spin?.classList.add('d-none');
        if (btn) btn.disabled = false;
    }
}

function showResults() {
    $('#resultSection')?.classList.remove('d-none');
}

function hideResults() {
    $('#resultSection')?.classList.add('d-none');
}

function showError(m) {
    const card = $('#errorCard');
    const msg = $('#errorMessage');
    if (msg) msg.textContent = m;
    card?.classList.remove('d-none');
}

function hideError() {
    $('#errorCard')?.classList.add('d-none');
    $('#urlValidationError')?.classList.add('d-none');
}

function showURLValidationError() {
    $('#urlValidationError')?.classList.remove('d-none');
}

function isValidURL(s) {
    try {
        const u = new URL(s);
        return u.protocol === 'http:' || u.protocol === 'https:';
    } catch { return false; }
}

function escHtml(s) {
    if (!s) return '';
    return String(s).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

function updateShareLink(url) {
    const input = $('#shareLink');
    if (!input) return;
    input.value = `${window.location.origin}${window.location.pathname}?url=${encodeURIComponent(url)}`;
}

function updateURL(url) {
    const params = new URLSearchParams(window.location.search);
    params.set('url', url);
    window.history.pushState({ url }, '', `${window.location.pathname}?${params.toString()}`);
}

/**
 * Actions
 */
function copyChain() {
    const steps = _lastData?.chain || [];
    const text = steps.map((s, i) => `${i + 1}. [${s.statusCode}] ${s.url}`).join('\n');
    copyText(text, $('#btnCopyChain'));
}

function exportJson() {
    if (!_lastData) return;
    const blob = new Blob([JSON.stringify(_lastData, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `redirect-checker-${new Date().getTime()}.json`;
    a.click();
}

async function copyText(text, btn) {
    if (!text) return;
    try {
        await navigator.clipboard.writeText(text);
        const original = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check"></i>';
        setTimeout(() => { btn.innerHTML = original; }, 2000);
    } catch (e) {
        console.error("Copy failed", e);
    }
}
