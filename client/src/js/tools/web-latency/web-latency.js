/**
 * web-latency.js
 * Logic cho phần Web Latency Inspector Tool
 */

import { $, createRealtimeURLValidator } from '../../utils/index.js';
import { API_BASE_URL } from '../../config.js';

class AbortedError extends Error {
    constructor() {
        super('aborted');
        this.name = 'AbortedError';
        this.aborted = true;
    }
}

let currentController = null;
let currentRequestId = 0;
let isAnalyzing = false;

document.addEventListener('DOMContentLoaded', () => {
    console.log("🚀 Web Latency Inspector Initialized");
    initWebLatency();
});

function initWebLatency() {
    setupEventListeners();
    loadFromURL();

    window.addEventListener("popstate", () => {
        const params = new URLSearchParams(window.location.search);
        const url = params.get('url');
        const isDeepTest = params.get('deep') === 'true';
        const input = $('#url');
        const deepTestCheckbox = $('#deepTest');
        
        if (url) {
            if (input) input.value = url;
            if (deepTestCheckbox) deepTestCheckbox.checked = isDeepTest;
            handleAnalyze();
        } else {
            if (input) input.value = '';
            if (deepTestCheckbox) deepTestCheckbox.checked = false;
            hideResults();
            hideError();
        }
    });
}

function setupEventListeners() {
    const form = $('#latencyForm');
    const urlInput = $('#url');

    form?.addEventListener('submit', (e) => {
        e.preventDefault();
        handleAnalyze();
    });

    if (urlInput) {
        createRealtimeURLValidator(
            urlInput,
            $('#urlValidationError'),
            $('#btnAnalyze')
        );

        urlInput.addEventListener('input', () => {
            hideError();
            hideResults();
        });
    }

    // Custom UI copies
    $('#btnCopyLink')?.addEventListener('click', () => {
        const text = $('#shareLink')?.value;
        copyText(text, $('#btnCopyLink'));
    });

    $('#btnBypassCache')?.addEventListener('click', () => {
        handleAnalyze(true);
    });
}

function loadFromURL() {
    const params = new URLSearchParams(window.location.search);
    const url = params.get('url');
    if (url) {
        const input = $('#url');
        if (input) input.value = url;
        
        const isDeepTest = params.get('deep') === 'true';
        const deepTestCheckbox = $('#deepTest');
        if (deepTestCheckbox) deepTestCheckbox.checked = isDeepTest;

        handleAnalyze();
    }
}

async function handleAnalyze(bypassCache = false) {
    if (isAnalyzing) return;

    const urlInput = $('#url');
    let url = urlInput?.value.trim();

    if (!url) {
        showURLValidationError();
        return;
    }
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
        if(urlInput) urlInput.value = url;
    }

    const deepTest = $('#deepTest')?.checked ?? false;
    const requestId = ++currentRequestId;

    isAnalyzing = true;
    setLoading(true);
    hideResults();
    hideError();

    try {
        const data = await fetchLatency(url, deepTest, bypassCache);
        renderResults(data.data);
        
        // Handle Cache Banner (Rule 11)
        const cacheNoticeBox = $('#cacheNotice');
        if (cacheNoticeBox && data.meta && data.meta.fetched_at) {
            const date = new Date(data.meta.fetched_at);
            const timeStr = date.toLocaleTimeString('vi-VN', { hour12: false }) + ' ' + date.toLocaleDateString('vi-VN');
            
            const spanEl = cacheNoticeBox.querySelector("span");
            if (spanEl) {
                if (data.meta.cached) {
                    spanEl.innerHTML = `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b id="cacheTime">${timeStr}</b>`;
                } else {
                    spanEl.innerHTML = `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b id="cacheTime">${timeStr}</b>`;
                }
            }

            cacheNoticeBox.classList.remove('d-none');
            cacheNoticeBox.classList.add('d-flex');
        } else {
            cacheNoticeBox?.classList.add('d-none');
            cacheNoticeBox?.classList.remove('d-flex');
        }

        updateShareLink(url, deepTest);
        updateURL(url, deepTest);
    } catch (err) {
        if (err instanceof AbortedError) return; // Silent for user intent-based aborts
        showError(err.message || 'Không thể kết nối. Vui lòng thử lại!');
    } finally {
        // Chỉ tắt loading nếu đây là request cuối cùng
        if (requestId === currentRequestId) {
            isAnalyzing = false;
            setLoading(false);
        }
    }
}

async function fetchLatency(url, deepTest, bypassCache) {
    if (currentController) {
        currentController.abort();
    }
    currentController = new AbortController();

    try {
        const response = await fetch(`${API_BASE_URL}/web-latency`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, deepTest, bypassCache }),
            signal: currentController.signal
        });

        if (!response.ok) {
            throw new Error(`Lỗi HTTP: ${response.status}`);
        }

        const jsonData = await response.json();

        if (!jsonData.success) {
            throw new Error(jsonData.message || `Lỗi từ server`);
        }
        return jsonData;
    } catch (err) {
        if (err.name === 'AbortError') {
            throw new AbortedError();
        }
        throw err;
    }
}

// Format duration
function formatDuration(ns) {
    if (ns == null || ns === 0) return "0ms";
    const ms = ns / 1_000_000;
    if (ms < 1 && ms > 0) return "< 1ms";
    return Math.round(ms) + "ms";
}

function escHtml(str) {
    if (!str) return "";
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function renderResults(data) {
    if (!data?.primaryMetrics) {
        showError('Dữ liệu kết quả không hợp lệ hoặc bị thiếu. Vui lòng thử lại!');
        return;
    }

    const primary = data.primaryMetrics;
    const totalRaw = primary.total || 0;
    
    renderAlerts(primary, data);
    renderTimelineChart(primary, totalRaw);
    renderCompressionHeader(data.compression);
    renderRedirectHops(data.redirectHops);

    const deepTestBox = $('#deepTestResults');
    if (data.deepTestResults) {
        deepTestBox?.classList.remove('d-none');
        $('#dtMin').textContent = formatDuration(data.deepTestResults.minTtfb);
        $('#dtMedian').textContent = formatDuration(data.deepTestResults.medianTtfb);
        $('#dtMax').textContent = formatDuration(data.deepTestResults.maxTtfb);
    } else {
        deepTestBox?.classList.add('d-none');
    }

    showResults();
}

function renderAlerts(metrics, data) {
    const alertsBox = $('#scoringAlerts');
    if (!alertsBox) return;

    let alertsHTML = '';
    const ttfbMs = metrics.ttfb / 1_000_000;

    if (ttfbMs > 600) {
        alertsHTML += `
        <div class="message-card message-card--error">
            <div class="message-card__header"><h4 class="message-card__title"><i class="fa-solid fa-triangle-exclamation"></i> Cảnh báo: TTFB quá chậm</h4></div>
            <div class="message-card__body">
                <p class="message-card__message">Thời gian phản hồi byte đầu tiên (TTFB) là ${formatDuration(metrics.ttfb)}, vượt mức 600ms. Máy chủ xử lý quá chậm hoặc đường truyền gặp sự cố lớn.</p>
                <div class="mt-2 text-muted">
                    <strong>Cách khắc phục:</strong> Kiểm tra tải tài nguyên (CPU/RAM) của máy chủ, tối ưu truy vấn Database, phân tích code backend, hoặc thiết lập Full Page Cache thông qua WP-Rocket, Cloudflare, v.v.
                </div>
            </div>
        </div>`;
    } else if (ttfbMs > 300) {
        alertsHTML += `
        <div class="message-card message-card--warning">
            <div class="message-card__header"><h4 class="message-card__title"><i class="fa-solid fa-circle-exclamation"></i> Cảnh báo: TTFB chưa tối ưu</h4></div>
            <div class="message-card__body">
                <p class="message-card__message">Thời gian phản hồi byte đầu tiên (TTFB) là ${formatDuration(metrics.ttfb)}. Tốc độ này xấp xỉ mức trung bình nhưng vẫn có thể làm chậm trải nghiệm.</p>
                <div class="mt-2 text-muted">
                    <strong>Cách khắc phục:</strong> Nên xem xét kích hoạt các lớp bộ nhớ đệm (Object Cache) như Redis/Memcached hoặc tinh chỉnh các plugin Cache Page để phản hồi HTML tức thì.
                </div>
            </div>
        </div>`;
    } else {
        alertsHTML += `
        <div class="message-card message-card--info">
            <div class="message-card__header"><h4 class="message-card__title"><i class="fa-solid fa-circle-check"></i> Tuyệt vời: Tối ưu TTFB tốt</h4></div>
            <div class="message-card__body"><p class="message-card__message">Mức TTFB máy chủ đạt ${formatDuration(metrics.ttfb)}, phản hồi RẤT nhanh.</p></div>
        </div>`;
    }

    if (data.compression && data.compression.isCompressed === false) {
        const ct = data.compression.contentType || '';
        if (ct.includes('html') || ct.includes('json') || ct.includes('text')) {
            alertsHTML += `
            <div class="message-card message-card--warning">
                <div class="message-card__header"><h4 class="message-card__title"><i class="fa-solid fa-file-zipper"></i> Chưa bật nén nội dung</h4></div>
                <div class="message-card__body">
                    <p class="message-card__message">Phát hiện Content-Type là text (hoặc JSON/HTML) nhưng Server KHÔNG nén (Gzip/Brotli). Điều này làm tăng thời gian Download và tốn băng thông.</p>
                    <div class="mt-2 text-muted">
                        <strong>Cách khắc phục:</strong> Cần chỉnh sửa file cấu hình máy chủ (Nginx/Apache/LiteSpeed, v.v.) và bật tham số phân phối qua <code>gzip</code> hoặc <code>brotli</code> cho các định dạng MIME cơ bản tĩnh (<code>text/html</code>, <code>text/css</code>, <code>application/javascript</code>, v.v.). Nếu dùng Cloudflare, hãy bật tính năng Auto Minify và Brotli ở mục Tốc độ (Speed).
                    </div>
                </div>
            </div>`;
        }
    }

    alertsBox.innerHTML = alertsHTML;
}

function renderTimelineChart(metrics, totalNs) {
    const timelineBox = $('#timelineBars');
    if (!timelineBox) return;

    if (totalNs === 0) totalNs = 1; // avoid division by zero 

    const phases = [
        { id: 'dns', label: 'DNS Lookup', ns: metrics.dnsLookup, class: 'timeline-bar--dns' },
        { id: 'tcp', label: 'TCP Connect', ns: metrics.tcpConnect, class: 'timeline-bar--tcp' },
        { id: 'tls', label: 'TLS Handshake', ns: metrics.tlsHandshake, class: 'timeline-bar--tls' },
        { id: 'ttfb', label: 'TTFB', ns: metrics.ttfb, class: 'timeline-bar--ttfb' },
        { id: 'download', label: 'Download', ns: metrics.contentDownload, class: 'timeline-bar--download' }
    ];

    let currentOffsetNs = 0;
    
    let html = '';
    phases.forEach(p => {
        const durationNs = p.ns || 0;
        const widthPct = Math.max((durationNs / totalNs) * 100, 0); // min visual width handled in CSS if needed
        const leftPct = (currentOffsetNs / totalNs) * 100;
        
        html += `
        <div class="timeline-item">
            <div class="timeline-label">${p.label}</div>
            <div class="timeline-bar-container">
                <div class="timeline-bar ${p.class}" style="left: ${leftPct}%; width: ${Math.max(widthPct, 2)}%;"></div>
            </div>
            <div class="timeline-value">${formatDuration(durationNs)}</div>
        </div>
        `;
        currentOffsetNs += durationNs;
    });

    // Total row
    html += `
    <div class="timeline-item mt-2 pt-2" style="border-top: 1px dotted var(--color-border)">
        <div class="timeline-label text-success"><strong>TOTAL</strong></div>
        <div class="timeline-bar-container" style="background: transparent;">
            <div class="timeline-bar timeline-bar--total"></div>
        </div>
        <div class="timeline-value text-success"><strong>${formatDuration(metrics.total)}</strong></div>
    </div>
    `;

    timelineBox.innerHTML = html;
}

function renderCompressionHeader(comp) {
    const list = $('#serverInfoList');
    if (!list) return;

    const data = [
        { label: 'HTTP Version', value: comp.httpVersion || '-' },
        { label: 'Server Software', value: comp.server || 'Ẩn/Không xác định' },
        { label: 'Content-Type', value: comp.contentType || '-' },
        { label: 'Content-Encoding', value: comp.isCompressed ? `<span class="badge badge-success px-2 py-1">${comp.encoding}</span>` : `<span class="badge badge-default px-2 py-1">Không nén</span>` },
        { label: 'Cache-Control', value: comp.cacheControl || '-' },
        { label: 'ETag', value: comp.etag ? 'Có ETag' : 'Không có' },
        { label: 'X-Cache / CDN', value: comp.xCache || 'Không phát hiện CDN Cache' }
    ];

    list.innerHTML = data.map(d => `
        <li class="info-list-item">
            <span>${d.label}</span>
            <span>${d.value}</span>
        </li>
    `).join('');
}


function renderRedirectHops(hops) {
    const list = $('#redirectHopsList');
    if (!list) return;

    if (!hops || hops.length === 0) {
         list.innerHTML = `<li class="text-secondary">Không có dữ liệu</li>`;
         return;
    }

    if (hops.length === 1) {
        list.innerHTML = `<li class="info-list-item text-success"><i class="fa-solid fa-check"></i> Trực tiếp 200 OK (0 hop)</li>`;
        return;
    }

    list.innerHTML = hops.map((h, idx) => {
        const isFinal = idx === hops.length - 1;
        const badgeCls = isFinal ? 'badge-success' : 'badge-warning';
        return `
        <li class="d-flex flex-col gap-1 pb-2 mb-2" style="border-bottom: var(--border-subtle);">
            <div class="d-flex flex-row justify-between w-full">
                <span class="font-bold text-truncate" title="${escHtml(h.url)}" style="max-width: 75%;">${escHtml(h.url)}</span>
                <span class="badge ${badgeCls}">${h.statusCode}</span>
            </div>
            <div class="text-secondary ml-2"><i class="fa-solid fa-clock"></i> Took ${formatDuration(h.metrics.total)}</div>
        </li>
        `;
    }).join('');
}


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
    $('#resultCard')?.classList.remove('d-none');
    $('#errorCard')?.classList.add('d-none');
    $('#shareCard')?.classList.remove('d-none');
}

function hideResults() {
    $('#resultCard')?.classList.add('d-none');
    $('#shareCard')?.classList.add('d-none');
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
    $('#url')?.classList.add('is-invalid');
}

function updateShareLink(url, deepTest) {
    const input = $('#shareLink');
    if (!input) return;
    const shareUrl = `${window.location.origin}${window.location.pathname}?url=${encodeURIComponent(url)}&deep=${deepTest}`;
    input.value = shareUrl;
}

function updateURL(url, deepTest) {
    const params = new URLSearchParams(window.location.search);
    params.set('url', url);
    params.set('deep', deepTest);
    const newSearch = `?${params.toString()}`;
    const newURL = `${window.location.pathname}${newSearch}`;
    if (window.location.search !== newSearch) {
        window.history.pushState({ url, deep: deepTest }, '', newURL);
    }
}

async function copyText(text, btn) {
    if (!text) return;
    try {
        await navigator.clipboard.writeText(text);
        const original = btn?.innerHTML;
        if (btn) btn.innerHTML = '<i class="fa-solid fa-check"></i><span>Copied</span>';
        setTimeout(() => { if (btn) btn.innerHTML = original; }, 1500);
    } catch { /* ignore */ }
}
