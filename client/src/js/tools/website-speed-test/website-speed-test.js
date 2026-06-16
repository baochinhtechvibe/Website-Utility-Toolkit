import {
    showError,
    hide,
    toggleLoading,
    copyToClipboard,
    setElementsEnabled
} from '../../utils/dom.js';
import { createRealtimeURLValidator } from '../../utils/validation.js';
import { API_BASE_URL } from '../../config.js';
import { escapeHTML } from '../../utils/format.js';

let currentData = null;
let currentAbortController = null;

function init() {
    const form = document.getElementById('speedTestForm');
    const urlInput = document.getElementById('url');
    const btnAnalyze = document.getElementById('btnAnalyze');
    const btnCopyLink = document.getElementById('btnCopyLink');
    const btnBypassCache = document.getElementById('btnBypassCache');
    const errorCard = document.getElementById('errorCard');

    if (!form || !urlInput || !btnAnalyze) return;

    // 1. Realtime Validator
    const urlValidationError = document.getElementById('urlValidationError');
    createRealtimeURLValidator(urlInput, urlValidationError, btnAnalyze);
    
    urlInput.addEventListener('input', () => {
        hide(errorCard);
        document.getElementById('resultSection')?.classList.add('d-none');
        document.getElementById('shareCard')?.classList.add('d-none');
    });
    
    // Helper function to normalize URL
    const getNormalizedUrl = () => {
        let url = urlInput.value.trim();
        if (url && !/^https?:\/\//i.test(url)) {
            url = 'https://' + url;
            urlInput.value = url;
            urlInput.dispatchEvent(new Event('input'));
        }
        return url;
    };

    // 2. Form Submit
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (btnAnalyze.disabled) return;
        await runSpeedTest(getNormalizedUrl(), false);
    });

    // 3. Bypass Cache
    if (btnBypassCache) {
        btnBypassCache.addEventListener('click', async () => {
            if (btnAnalyze.disabled) return;
            await runSpeedTest(getNormalizedUrl(), true);
        });
    }

    // 4. Copy Link
    if (btnCopyLink) {
        btnCopyLink.addEventListener('click', async () => {
            const shareLinkInput = document.getElementById('shareLink');
            const originalHTML = btnCopyLink.innerHTML;
            const success = await copyToClipboard(shareLinkInput.value);
            if (success) {
                btnCopyLink.innerHTML = '<i class="fa-solid fa-check"></i><span>Copied!</span>';
                btnCopyLink.classList.add('btn-success');
                setTimeout(() => {
                    btnCopyLink.innerHTML = originalHTML;
                    btnCopyLink.classList.remove('btn-success');
                }, 2000);
            }
        });
    }

    // 5. Export JSON
    const btnExportJson = document.getElementById('btnExportJson');
    if (btnExportJson) {
        btnExportJson.addEventListener('click', () => {
            if (!currentData) return;
            const jsonStr = JSON.stringify(currentData, null, 2);
            const blob = new Blob([jsonStr], { type: 'application/json' });
            const downloadUrl = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = downloadUrl;
            const domain = new URL(currentData.targetUrl || currentData.finalUrl || urlInput.value).hostname || 'website';
            a.download = `speed_test_${domain}_${Date.now()}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(downloadUrl);
        });
    }

    // Check query params for shared link execution
    const urlParams = new URLSearchParams(window.location.search);
    const sharedUrl = urlParams.get('url');
    if (sharedUrl) {
        urlInput.value = sharedUrl;
        urlInput.dispatchEvent(new Event('input'));
        // Đợi một chút để validator realtime cập nhật trạng thái nút
        setTimeout(() => {
            if (!btnAnalyze.disabled) {
                runSpeedTest(sharedUrl, false);
            }
        }, 50);
    }
}

async function runSpeedTest(url, bypassCache) {
    const btnAnalyze = document.getElementById('btnAnalyze');
    const icon = document.getElementById('speedTestIcon');
    const loading = document.getElementById('speedTestLoading');
    const resultSection = document.getElementById('resultSection');
    const shareCard = document.getElementById('shareCard');
    const errorCard = document.getElementById('errorCard');
    const errorMessage = document.getElementById('errorMessage');

    const skeletonLoader = document.getElementById('skeletonLoader');
    const urlInput = document.getElementById('url');

    hide(errorCard);
    resultSection.classList.add('d-none');
    shareCard.classList.add('d-none');
    
    toggleLoading(btnAnalyze, icon, loading, true);
    setElementsEnabled([urlInput], false);
    skeletonLoader.classList.remove('d-none');

    // Cancel old request if running
    if (currentAbortController) {
        currentAbortController.abort();
    }
    const controller = new AbortController();
    currentAbortController = controller;

    try {
        const payload = { url, bypassCache };
        const response = await fetch(`${API_BASE_URL}/website-speed-test/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            signal: controller.signal
        });

        let data;
        try {
            data = await response.json();
        } catch (e) {
            // Handle cases where backend returns HTML (e.g. 502, 504) or empty body (429)
            if (controller !== currentAbortController) return; // Stale guard
            showError(errorCard, errorMessage, `Lỗi hệ thống: Phản hồi không hợp lệ (${response.status} ${response.statusText}).`);
            return;
        }

        if (controller !== currentAbortController) return; // Stale guard

        if (!response.ok || !data.success) {
            showError(errorCard, errorMessage, data.message || `Lỗi máy chủ (${response.status}).`);
            return;
        }

        currentData = data.data;
        renderResults(currentData, data.meta);
        
        resultSection.classList.remove('d-none');
        shareCard.classList.remove('d-none');
        
        // Update Share Link
        const shareLinkInput = document.getElementById('shareLink');
        const shareUrlObj = new URL(window.location.href);
        shareUrlObj.searchParams.set('url', url);
        shareLinkInput.value = shareUrlObj.toString();
        
        // Sync URL param without reloading the page
        if (new URL(window.location.href).searchParams.get('url') !== url) {
            window.history.pushState({ path: shareUrlObj.href }, '', shareUrlObj.href);
        }
        
    } catch (err) {
        if (err.name === 'AbortError' || controller !== currentAbortController) return;
        showError(errorCard, errorMessage, 'Lỗi hệ thống. Vui lòng kiểm tra lại mạng hoặc thử lại sau.');
    } finally {
        if (controller === currentAbortController) {
            toggleLoading(btnAnalyze, icon, loading, false);
            setElementsEnabled([urlInput], true);
            skeletonLoader.classList.add('d-none');
            currentAbortController = null;
        }
    }
}

function renderResults(data, meta) {
    // Render Cache Notice
    const cacheNotice = document.getElementById('cacheNotice');
    if (meta && (meta.cached !== undefined || meta.fetched_at || meta.timestamp)) {
        const cacheTimeEl = document.getElementById('cacheTime');
        const cacheTextEl = document.getElementById('cacheText');
        const icon = cacheNotice.querySelector('i');
        
        const timestampStr = new Date(meta.fetched_at || meta.fetchedAt || meta.timestamp || Date.now()).toLocaleString('vi-VN');
        cacheTimeEl.textContent = timestampStr;
        
        if (meta.cached) {
            icon.className = 'fa-solid fa-clock';
            if (cacheTextEl) cacheTextEl.textContent = 'Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc';
        } else {
            icon.className = 'fa-solid fa-bolt';
            if (cacheTextEl) cacheTextEl.textContent = 'Kết quả tra cứu mới nhất lúc';
        }
        cacheNotice.classList.remove('d-none');
    } else {
        cacheNotice.classList.add('d-none');
    }

    // 1. Render Summary Strip
    document.getElementById('gradeScore').textContent = data.performanceLetter || '?';
    document.getElementById('gradeNumber').textContent = data.performanceGrade || '0';
    
    // Set color based on grade (A, B = success; C = warning; D, F = danger)
    const gradeEl = document.getElementById('gradeScore');
    const gradeIcon = document.getElementById('gradeIcon');
    gradeEl.className = 'speed-summary-cell__value speed-summary-cell__value--large';
    gradeIcon.className = 'speed-summary-cell__icon';
    if (['A', 'B'].includes(data.performanceLetter)) {
        gradeEl.classList.add('text-success');
        gradeIcon.classList.add('text-success');
    } else if (data.performanceLetter === 'C') {
        gradeEl.classList.add('text-warning');
        gradeIcon.classList.add('text-warning');
    } else {
        gradeEl.classList.add('text-danger');
        gradeIcon.classList.add('text-danger');
    }

    // Page Size in MB/KB
    const sizeMB = (data.pageSizeBytes / (1024 * 1024)).toFixed(2);
    document.getElementById('pageSize').textContent = sizeMB > 0.1 ? `${sizeMB} MB` : `${(data.pageSizeBytes / 1024).toFixed(1)} KB`;
    
    // Load time in seconds
    document.getElementById('loadTime').textContent = `${(data.loadTimeMs / 1000).toFixed(2)} s`;
    
    // Total Requests
    document.getElementById('totalRequests').textContent = data.totalRequests || '0';

    // 2. Render Accordion
    renderAccordion(data.grades || []);

    // 3. Render Content Stats
    renderContentStats(data.contentStats || [], data.pageSizeBytes, data.totalRequests);
    
    // Render Domain Stats
    renderDomainStats(data.domainStats || [], data.pageSizeBytes, data.totalRequests);

    // Render Response Codes
    renderResponseCodes(data.requests || []);

    // 4. Render Waterfall
    renderWaterfall(data.requests, data.loadTimeMs);
}

function renderAccordion(grades) {
    const container = document.getElementById('performanceAccordion');
    container.innerHTML = `
        <div class="d-flex items-center justify-between p-3 border-b border-border border-t border-l border-r bg-surface-sunken text-xs text-muted font-bold uppercase" style="border-radius: var(--radius-md) var(--radius-md) 0 0;">
            <div class="d-flex items-center gap-4 flex-1">
                <div style="width: 70px;">Xếp loại</div>
                <div class="flex-1 pl-4">Đề xuất</div>
            </div>
            <div style="width: 28px; height: 28px;"></div>
        </div>
        <div id="accordionList" class="border-l border-r border-b border-border" style="border-radius: 0 0 var(--radius-md) var(--radius-md); overflow: hidden;"></div>
    `;
    
    const list = container.querySelector('#accordionList');

    if (grades.length === 0) {
        list.innerHTML = '<div class="p-4 text-muted">Không có dữ liệu phân tích.</div>';
        return;
    }

    grades.forEach((grade, index) => {
        let gradeLetter = 'A';
        if (grade.score < 60) gradeLetter = 'F';
        else if (grade.score < 70) gradeLetter = 'D';
        else if (grade.score < 80) gradeLetter = 'C';
        else if (grade.score < 90) gradeLetter = 'B';
        
        const item = document.createElement('div');
        item.className = 'accordion-item border-b border-border';
        // Xóa border bottom của item cuối cùng
        if (index === grades.length - 1) item.style.borderBottom = 'none';
        
        // Cấu trúc HTML an toàn, escapeHTML các giá trị user/ngoại lai nếu có
        item.innerHTML = `
            <button class="accordion-header w-full d-flex items-center justify-between p-3 bg-transparent border-none cursor-pointer" type="button" style="transition: background 0.2s;">
                <div class="d-flex items-center gap-4 flex-1">
                    <div class="d-flex items-center justify-between" style="width: 70px;">
                        <span class="grade-badge grade-${gradeLetter} text-white font-bold text-sm rounded-sm d-flex items-center justify-center" style="width: 28px; height: 28px; margin: 0; line-height: 1;">${gradeLetter}</span>
                        <span class="font-bold text-muted" style="width: 30px; text-align: left; margin-left: 8px;">${grade.score}</span>
                    </div>
                    <span class="grade-title text-sm text-left flex-1 pl-4" style="color: var(--color-text-primary);">${escapeHTML(grade.rule || grade.title || '')}</span>
                </div>
                <div class="accordion-icon-wrap border border-border rounded-full d-flex items-center justify-center" style="width: 28px; height: 28px; background-color: var(--color-surface);">
                    <i class="fa-solid fa-chevron-down accordion-icon text-muted text-xs"></i>
                </div>
            </button>
            <div class="accordion-content p-4 text-sm text-muted hidden border-t border-border">
                ${grade.warning ? `<p class="text-danger mb-4 font-bold">⚠️ ${escapeHTML(grade.warning)}</p>` : ''}
                ${grade.description ? `<p style="line-height: 1.6; color: var(--color-text-primary);">${escapeHTML(grade.description)}</p>` : ''}
            </div>
        `;

        // Add toggle event
        const header = item.querySelector('.accordion-header');
        header.addEventListener('click', () => {
            const isActive = item.classList.contains('active');
            if (isActive) item.classList.remove('active');
            else item.classList.add('active');
        });

        // Bỏ chế độ mở sẵn mục đầu tiên để hiển thị thu gọn lúc mới tải trang theo yêu cầu.
        list.appendChild(item);
    });
}

function renderContentStats(stats, totalSize, totalReqs) {
    const sizeBody = document.getElementById('contentSizeBody');
    const reqBody = document.getElementById('contentRequestsBody');
    sizeBody.innerHTML = '';
    reqBody.innerHTML = '';

    if (stats.length === 0) {
        sizeBody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">Không có dữ liệu</td></tr>';
        reqBody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">Không có dữ liệu</td></tr>';
        return;
    }

    const getContentTypeIcon = (type) => {
        switch (type) {
            case 'Image': return '<i class="fa-regular fa-image text-muted" style="width: 20px; text-align: center; margin-right: 8px;"></i>';
            case 'Script': return '<span class="text-muted font-bold" style="display: inline-block; width: 20px; text-align: center; margin-right: 8px;">JS</span>';
            case 'CSS': return '<span class="text-muted font-bold" style="display: inline-block; width: 20px; text-align: center; margin-right: 8px;">{}</span>';
            case 'Font': return '<i class="fa-solid fa-font text-muted" style="width: 20px; text-align: center; margin-right: 8px;"></i>';
            case 'HTML': return '<i class="fa-regular fa-file-code text-muted" style="width: 20px; text-align: center; margin-right: 8px;"></i>';
            case 'Error': return '<i class="fa-solid fa-triangle-exclamation text-muted" style="width: 20px; text-align: center; margin-right: 8px;"></i>';
            case 'Redirect': return '<i class="fa-solid fa-share text-muted" style="width: 20px; text-align: center; margin-right: 8px;"></i>';
            default: return '<i class="fa-regular fa-file text-muted" style="width: 20px; text-align: center; margin-right: 8px;"></i>';
        }
    };

    // Sort by size descending
    const bySize = [...stats].sort((a, b) => b.size - a.size);
    bySize.forEach(s => {
        let sizeStr = s.size > 1024 * 1024 ? `${(s.size / (1024 * 1024)).toFixed(2)} MB` : `${(s.size / 1024).toFixed(1)} KB`;
        let percent = totalSize > 0 ? ((s.size / totalSize) * 100).toFixed(1) : 0;
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>
                <div class="d-flex items-center">
                    ${getContentTypeIcon(s.type)}
                    <span class="font-bold">${escapeHTML(s.type)}</span>
                </div>
            </td>
            <td class="text-right">${percent}%</td>
            <td class="text-right">${sizeStr}</td>
        `;
        sizeBody.appendChild(tr);
    });

    // Sort by requests descending
    const byReq = [...stats].sort((a, b) => b.requests - a.requests);
    byReq.forEach(s => {
        let percent = totalReqs > 0 ? ((s.requests / totalReqs) * 100).toFixed(1) : 0;
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>
                <div class="d-flex items-center">
                    ${getContentTypeIcon(s.type)}
                    <span class="font-bold">${escapeHTML(s.type)}</span>
                </div>
            </td>
            <td class="text-right">${percent}%</td>
            <td class="text-right">${s.requests}</td>
        `;
        reqBody.appendChild(tr);
    });
}

function renderDomainStats(stats, totalSize, totalReqs) {
    const sizeBody = document.getElementById('domainSizeBody');
    const reqBody = document.getElementById('domainRequestsBody');
    sizeBody.innerHTML = '';
    reqBody.innerHTML = '';

    if (stats.length === 0) {
        sizeBody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">Không có dữ liệu</td></tr>';
        reqBody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">Không có dữ liệu</td></tr>';
        return;
    }

    // Sort by size descending
    const bySize = [...stats].sort((a, b) => b.size - a.size);
    bySize.forEach(s => {
        let sizeStr = s.size > 1024 * 1024 ? `${(s.size / (1024 * 1024)).toFixed(2)} MB` : `${(s.size / 1024).toFixed(1)} KB`;
        let percent = totalSize > 0 ? ((s.size / totalSize) * 100).toFixed(2) : 0;
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="font-bold text-muted speed-table__domain">${escapeHTML(s.domain)}</span></td>
            <td class="text-right">${percent}%</td>
            <td class="text-right">${sizeStr}</td>
        `;
        sizeBody.appendChild(tr);
    });

    // Sort by requests descending
    const byReq = [...stats].sort((a, b) => b.requests - a.requests);
    byReq.forEach(s => {
        let percent = totalReqs > 0 ? ((s.requests / totalReqs) * 100).toFixed(2) : 0;
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="font-bold text-muted speed-table__domain">${escapeHTML(s.domain)}</span></td>
            <td class="text-right">${percent}%</td>
            <td class="text-right">${s.requests}</td>
        `;
        reqBody.appendChild(tr);
    });
}

function renderResponseCodes(requests) {
    const tbody = document.getElementById('responseCodesBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!requests || requests.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">Không có dữ liệu</td></tr>';
        return;
    }

    const HTTP_STATUS_TEXTS = {
        200: 'OK', 204: 'No Content', 206: 'Partial Content',
        301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
        400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 405: 'Method Not Allowed',
        500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout'
    };

    const codeCounts = {};
    let totalReqs = 0;
    requests.forEach(req => {
        // Nếu có lỗi mạng không có statusCode thì có thể req.error có giá trị, 
        // nhưng theo Pingdom response code chỉ tính các request có status
        const code = req.statusCode || (req.error ? 'ERR' : null);
        if (code) {
            codeCounts[code] = (codeCounts[code] || 0) + 1;
            totalReqs++;
        }
    });

    const sortedCodes = Object.keys(codeCounts).sort((a, b) => codeCounts[b] - codeCounts[a]);

    sortedCodes.forEach(code => {
        const count = codeCounts[code];
        const percent = totalReqs > 0 ? ((count / totalReqs) * 100).toFixed(2) : 0;
        
        let badgeClass = 'badge-success';
        let statusText = 'Unknown';
        
        if (code === 'ERR') {
            badgeClass = 'badge-default';
            statusText = 'Blocked / Aborted';
        } else {
            const c = parseInt(code);
            statusText = HTTP_STATUS_TEXTS[c] || (c < 300 ? 'Success' : c < 400 ? 'Redirect' : c < 500 ? 'Client Error' : 'Server Error');
            if (c >= 300 && c < 400) badgeClass = 'badge-warning';
            else if (c >= 400) badgeClass = 'badge-error';
        }

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>
                <span class="badge ${badgeClass} mr-2" style="display:inline-block; min-width: 45px; text-align: center;">${escapeHTML(code)}</span>
                <span class="text-muted font-bold">${escapeHTML(statusText)}</span>
            </td>
            <td class="text-right">${percent}%</td>
            <td class="text-right">${count}</td>
        `;
        tbody.appendChild(tr);
    });
}

let wfRequests = [];
let wfMaxTimeMs = 0;
let wfCurrentPage = 1;
let wfPerPage = 10;
let wfFilterValue = '';
let wfSortByVal = 'load_order';
let wfSortRisingVal = true;

function renderWaterfall(requests, maxTimeMs) {
    wfRequests = requests || [];
    wfMaxTimeMs = maxTimeMs;
    wfCurrentPage = 1;
    
    // Bind events if not already bound
    if (!window.wfEventsBound) {
        document.getElementById('wfFilter').addEventListener('input', (e) => {
            wfFilterValue = e.target.value.toLowerCase();
            wfCurrentPage = 1;
            updateWaterfallView();
        });
        document.getElementById('wfPerPage').addEventListener('change', (e) => {
            wfPerPage = parseInt(e.target.value) || 10;
            wfCurrentPage = 1;
            updateWaterfallView();
        });
        document.getElementById('wfBtnPrev').addEventListener('click', () => {
            if (wfCurrentPage > 1) {
                wfCurrentPage--;
                updateWaterfallView();
            }
        });
        document.getElementById('wfBtnNext').addEventListener('click', () => {
            const filtered = getFilteredRequests();
            const maxPage = Math.ceil(filtered.length / wfPerPage);
            if (wfCurrentPage < maxPage) {
                wfCurrentPage++;
                updateWaterfallView();
            }
        });
        document.getElementById('wfSortBy').addEventListener('change', (e) => {
            wfSortByVal = e.target.value;
            wfCurrentPage = 1;
            updateWaterfallView();
        });
        document.getElementById('wfSortRising').addEventListener('change', (e) => {
            wfSortRisingVal = e.target.checked;
            wfCurrentPage = 1;
            updateWaterfallView();
        });
        window.wfEventsBound = true;
    }

    updateWaterfallView();
}

function getFilteredRequests() {
    let result = [...wfRequests];
    if (wfFilterValue) {
        result = result.filter(req => req.url.toLowerCase().includes(wfFilterValue));
    }
    
    result = result.sort((a, b) => {
        let valA, valB;
        if (wfSortByVal === 'load_order') {
            valA = a.startTime || 0;
            valB = b.startTime || 0;
        } else if (wfSortByVal === 'load_time') {
            valA = a.duration || ((a.endTime || 0) - (a.startTime || 0));
            valB = b.duration || ((b.endTime || 0) - (b.startTime || 0));
        } else if (wfSortByVal === 'header_size') {
            valA = Object.entries(a.respHeaders || {}).reduce((acc, [k, v]) => acc + k.length + v.length + 4, 0);
            valB = Object.entries(b.respHeaders || {}).reduce((acc, [k, v]) => acc + k.length + v.length + 4, 0);
        } else if (wfSortByVal === 'body_size') {
            const ha = Object.entries(a.respHeaders || {}).reduce((acc, [k, v]) => acc + k.length + v.length + 4, 0);
            const hb = Object.entries(b.respHeaders || {}).reduce((acc, [k, v]) => acc + k.length + v.length + 4, 0);
            valA = Math.max(0, (a.size || 0) - ha);
            valB = Math.max(0, (b.size || 0) - hb);
        } else if (wfSortByVal === 'total_size') {
            valA = a.size || 0;
            valB = b.size || 0;
        } else if (wfSortByVal === 'status_code') {
            valA = a.statusCode || 0;
            valB = b.statusCode || 0;
        } else if (wfSortByVal === 'connect_time') {
            valA = a.timeline?.connect || 0;
            valB = b.timeline?.connect || 0;
        } else if (wfSortByVal === 'dns_time') {
            valA = a.timeline?.dns || 0;
            valB = b.timeline?.dns || 0;
        } else if (wfSortByVal === 'receive_time') {
            valA = a.timeline?.receive || 0;
            valB = b.timeline?.receive || 0;
        } else if (wfSortByVal === 'ssl_time') {
            valA = a.timeline?.ssl || 0;
            valB = b.timeline?.ssl || 0;
        } else if (wfSortByVal === 'wait_time') {
            valA = a.timeline?.wait || 0;
            valB = b.timeline?.wait || 0;
        } else if (wfSortByVal === 'content_type') {
            valA = (a.resourceType || a.mimeType || '').toLowerCase();
            valB = (b.resourceType || b.mimeType || '').toLowerCase();
            if (valA < valB) return wfSortRisingVal ? -1 : 1;
            if (valA > valB) return wfSortRisingVal ? 1 : -1;
            return 0;
        } else {
            // Default fallback
            valA = a.startTime || 0;
            valB = b.startTime || 0;
        }
        
        return wfSortRisingVal ? (valA - valB) : (valB - valA);
    });
    
    return result;
}

const getContentTypeIcon = (type, mimeType = '') => {
    if (mimeType && mimeType.toLowerCase().startsWith('image/')) {
        return '<i class="fa-regular fa-image text-muted wf-type-icon"></i>';
    }
    switch (type) {
        case 'Image': return '<i class="fa-regular fa-image text-muted wf-type-icon"></i>';
        case 'Script': return '<span class="text-muted font-bold wf-type-icon wf-type-text">JS</span>';
        case 'CSS': 
        case 'Stylesheet': return '<span class="text-muted font-bold wf-type-icon wf-type-text">{}</span>';
        case 'Font': return '<i class="fa-solid fa-font text-muted wf-type-icon"></i>';
        case 'HTML': 
        case 'Document': return '<i class="fa-regular fa-file-code text-muted wf-type-icon"></i>';
        case 'Error': return '<i class="fa-solid fa-triangle-exclamation text-muted wf-type-icon"></i>';
        case 'Redirect': return '<i class="fa-solid fa-share text-muted wf-type-icon"></i>';
        default: return '<i class="fa-regular fa-file text-muted wf-type-icon"></i>';
    }
};

function formatHeaders(headersObj) {
    if (!headersObj || Object.keys(headersObj).length === 0) return '<tr><td colspan="2" class="text-muted">Không có dữ liệu</td></tr>';
    return Object.entries(headersObj).map(([key, val]) => `<tr><th>${escapeHTML(key)}</th><td>${escapeHTML(val)}</td></tr>`).join('');
}

function updateWaterfallView() {
    const tbody = document.getElementById('waterfallBody');
    const filtered = getFilteredRequests();
    
    // Pagination logic
    const totalEntries = filtered.length;
    const maxPage = Math.max(1, Math.ceil(totalEntries / wfPerPage));
    if (wfCurrentPage > maxPage) wfCurrentPage = maxPage;
    
    document.getElementById('wfTotalEntries').textContent = `${totalEntries} requests`;
    document.getElementById('wfPageInfo').textContent = `${wfCurrentPage}/${maxPage}`;
    document.getElementById('wfBtnPrev').disabled = (wfCurrentPage === 1);
    document.getElementById('wfBtnNext').disabled = (wfCurrentPage === maxPage);

    tbody.innerHTML = '';

    if (totalEntries === 0) {
        tbody.innerHTML = '<div class="p-4 text-center text-muted">Không có dữ liệu network.</div>';
        document.getElementById('wfTimelineGrid').innerHTML = '';
        return;
    }

    const startIdx = (wfCurrentPage - 1) * wfPerPage;
    const endIdx = startIdx + wfPerPage;
    const pageData = filtered.slice(startIdx, endIdx);

    let totalTime = 0;
    if (filtered.length > 0) {
        totalTime = Math.max(...filtered.map(r => r.endTime || 0));
    }
    if (totalTime <= 0) totalTime = 1000;

    // Render Timeline Grid (Dynamic based on totalTime)
    const grid = document.getElementById('wfTimelineGrid');
    grid.innerHTML = '';
    
    // Determine reasonable step interval (0.1s, 0.2s, 0.5s, 1s, etc)
    const totalTimeSec = totalTime / 1000;
    let stepSec = 0.1;
    if (totalTimeSec > 1) stepSec = 0.2;
    if (totalTimeSec > 2) stepSec = 0.5;
    if (totalTimeSec > 5) stepSec = 1.0;
    if (totalTimeSec > 10) stepSec = 2.0;

    const numSteps = Math.ceil(totalTimeSec / stepSec);
    const timelineScale = (numSteps * stepSec * 1000) || totalTime;

    let bgImages = [];
    for (let i = 0; i <= numSteps; i++) {
        const timeSec = i * stepSec;
        const leftPct = (timeSec * 1000 / timelineScale) * 100;
        
        // Draw the label at the top
        const label = document.createElement('div');
        label.className = 'wf-timeline-grid-label';
        label.style.left = `${leftPct}%`;
        label.textContent = `${timeSec.toFixed(1)}s`;
        
        if (i === 0) {
            label.style.transform = 'translate(0, -50%)';
        } else if (i === numSteps) {
            label.style.transform = 'translate(-100%, -50%)';
        }
        
        grid.appendChild(label);
        
        if (leftPct > 0) {
            bgImages.push(`linear-gradient(to right, transparent calc(${leftPct}% - 1px), var(--color-border-subtle) calc(${leftPct}% - 1px), var(--color-border-subtle) ${leftPct}%, transparent ${leftPct}%)`);
        }
    }
    
    // Set a CSS variable for the timeline column background on body
    document.getElementById('waterfallBody').style.setProperty('--timeline-bg', bgImages.join(', ') || 'none');

    pageData.forEach((req, idx) => {
        const rowContainer = document.createElement('div');
        rowContainer.className = 'wf-row-container';

        let sizeStr = req.size > 1024 ? `${(req.size / 1024).toFixed(1)} KB` : `${req.size} B`;
        
        const blocked = Math.max(0, req.timeline?.blocked || 0);
        const dns = Math.max(0, req.timeline?.dns || 0);
        const connect = Math.max(0, req.timeline?.connect || 0);
        const ssl = Math.max(0, req.timeline?.ssl || 0);
        const send = Math.max(0, req.timeline?.send || 0);
        const wait = Math.max(0, req.timeline?.wait || 0);
        const receive = Math.max(0, req.timeline?.receive || 0);

        const startPct = Math.max(0, (req.startTime / timelineScale) * 100);
        const blockedPct = (blocked / timelineScale) * 100;
        const dnsPct = (dns / timelineScale) * 100;
        const connectPct = (connect / timelineScale) * 100;
        const sslPct = (ssl / timelineScale) * 100;
        const sendPct = (send / timelineScale) * 100;
        const waitPct = (wait / timelineScale) * 100;
        const receivePct = (receive / timelineScale) * 100;
        const totalDuration = blocked + dns + connect + ssl + send + wait + receive;
        // Prepare data for tooltip
        const metrics = {
            dns: dns,
            ssl: ssl,
            connect: connect,
            send: send,
            wait: wait,
            receive: receive,
            blocked: blocked,
            total: totalDuration
        };

        let statusColorClass = 'text-success';
        if (req.statusCode >= 300 && req.statusCode < 400) statusColorClass = 'text-info';
        else if (req.statusCode >= 400) statusColorClass = 'text-danger';
        else if (req.error) statusColorClass = 'text-muted';

        let imagePreviewHtml = '';
        let detailsUrlHtml = `<div class="text-center mb-4"><a href="${escapeHTML(req.url)}" target="_blank" class="wf-url-text text-sm underline">${escapeHTML(req.url)}</a></div>`;
        if (req.resourceType === 'Image' || (req.mimeType && req.mimeType.startsWith('image/'))) {
            // Prevent showing preview for invalid urls
            let safeImgUrl = req.url;
            if (safeImgUrl.toLowerCase().startsWith('http://') || safeImgUrl.toLowerCase().startsWith('https://')) {
                detailsUrlHtml = ''; // Remove URL if it's an image
                imagePreviewHtml = `
                    <div class="d-flex justify-center mb-4">
                        <div class="wf-image-thumbnail m-0 wf-image-thumbnail-clickable" data-img-url="${escapeHTML(safeImgUrl)}">
                            <img src="${escapeHTML(safeImgUrl)}" alt="Preview" loading="lazy">
                        </div>
                    </div>
                `;
            }
        }

        rowContainer.innerHTML = `
            <div class="wf-row cursor-pointer wf-row-clickable">
                <div class="wf-col-file">
                    ${getContentTypeIcon(req.resourceType, req.mimeType)}
                    <i class="fa-solid fa-circle ${statusColorClass} mr-2 wf-status-dot"></i>
                    <a href="${escapeHTML(req.url)}" target="_blank" class="wf-url-text" title="${escapeHTML(req.url)}">${escapeHTML(req.url)}</a>
                </div>
                <div class="wf-col-size text-sm text-muted">
                    ${escapeHTML(sizeStr)}
                </div>
                <div class="wf-col-timeline">
                    <div class="wf-timeline-wrap" style="--start: ${startPct}%; --width: ${Math.max(0.5, blockedPct + dnsPct + connectPct + sslPct + sendPct + waitPct + receivePct)}%;">
                        <div class="wf-timeline-bg">
                            <div class="wf-bar wf-bar-blocked" style="--width: ${(blocked / totalDuration) * 100 || 0}%"></div>
                            <div class="wf-bar wf-bar-dns" style="--width: ${(dns / totalDuration) * 100 || 0}%"></div>
                            <div class="wf-bar wf-bar-connect" style="--width: ${(connect / totalDuration) * 100 || 0}%"></div>
                            <div class="wf-bar wf-bar-ssl" style="--width: ${(ssl / totalDuration) * 100 || 0}%"></div>
                            <div class="wf-bar wf-bar-send" style="--width: ${(send / totalDuration) * 100 || 0}%"></div>
                            <div class="wf-bar wf-bar-wait" style="--width: ${(wait / totalDuration) * 100 || 0}%"></div>
                            <div class="wf-bar wf-bar-receive" style="--width: ${(receive / totalDuration) * 100 || 0}%"></div>
                        </div>
                    </div>
                </div>
                <div class="wf-col-action">
                    <button class="wf-btn-expand wf-btn-expand-clickable">
                        <i class="fa-solid fa-chevron-down text-xs"></i>
                    </button>
                </div>
            </div>
            <div class="wf-details">
                ${detailsUrlHtml}
                ${imagePreviewHtml}
                <div class="wf-details-title">Response Headers ${req.error ? `<span class="badge badge-default ml-2 text-xs">ERR</span>` : (req.statusCode >= 400 ? `<span class="badge badge-error ml-2 text-xs">${req.statusCode}</span>` : (req.statusCode >= 300 ? `<span class="badge badge-info ml-2 text-xs">${req.statusCode}</span>` : `<span class="badge badge-success ml-2 text-xs">${req.statusCode}</span>`))}</div>
                <table class="wf-details-table">
                    <tbody>${formatHeaders(req.respHeaders)}</tbody>
                </table>
                <div class="wf-details-title">Request Headers</div>
                <table class="wf-details-table">
                    <tbody>${formatHeaders(req.reqHeaders)}</tbody>
                </table>
            </div>
        `;
        tbody.appendChild(rowContainer);

        // Bind Tooltip events
        const timelineWrap = rowContainer.querySelector('.wf-timeline-wrap');
        if (timelineWrap) {
            timelineWrap.addEventListener('mouseenter', () => window.updateWfTooltipContent(metrics));
            timelineWrap.addEventListener('mousemove', (e) => window.showWfTooltip(e));
            timelineWrap.addEventListener('mouseleave', () => window.hideWfTooltip());
        }

        // Bind click to expand
        const wfRow = rowContainer.querySelector('.wf-row-clickable');
        if (wfRow) {
            wfRow.addEventListener('click', () => {
                rowContainer.classList.toggle('expanded');
            });
        }
        
        // Bind expand button click
        const wfBtn = rowContainer.querySelector('.wf-btn-expand-clickable');
        if (wfBtn) {
            wfBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                rowContainer.classList.toggle('expanded');
            });
        }
        
        // Bind image modal
        const imgThumb = rowContainer.querySelector('.wf-image-thumbnail-clickable');
        if (imgThumb) {
            imgThumb.addEventListener('click', () => {
                const url = imgThumb.getAttribute('data-img-url');
                if (url) window.openImageModal(url);
            });
        }
        
        // Bind URL links (prevent propagation)
        const urlLinks = rowContainer.querySelectorAll('.wf-url-text');
        urlLinks.forEach(link => {
            link.addEventListener('click', (e) => e.stopPropagation());
        });
    });
}

window.openImageModal = function(url) {
    const modal = document.getElementById('imagePreviewModal');
    const img = document.getElementById('wfPreviewImageFull');
    if (modal && img) {
        img.src = url;
        modal.classList.remove('d-none');
    }
};

window.updateWfTooltipContent = function(m) {
    let layer = document.getElementById('wfTooltipLayer');
    if (!layer) {
        layer = document.createElement('div');
        layer.id = 'wfTooltipLayer';
        document.body.appendChild(layer);
    }
    layer.innerHTML = `
        <div class="wf-tooltip-row"><span class="wf-tooltip-color" style="background: #FF9BBE;"></span><span class="wf-tooltip-label">Dns</span><span class="wf-tooltip-val">${m.dns.toFixed(1)} ms</span></div>
        <div class="wf-tooltip-row"><span class="wf-tooltip-color" style="background: #B893D3;"></span><span class="wf-tooltip-label">Ssl</span><span class="wf-tooltip-val">${m.ssl.toFixed(1)} ms</span></div>
        <div class="wf-tooltip-row"><span class="wf-tooltip-color" style="background: #4CB8D4;"></span><span class="wf-tooltip-label">Connect</span><span class="wf-tooltip-val">${m.connect.toFixed(1)} ms</span></div>
        <div class="wf-tooltip-row"><span class="wf-tooltip-color" style="background: #F89E30;"></span><span class="wf-tooltip-label">Send</span><span class="wf-tooltip-val">${m.send.toFixed(1)} ms</span></div>
        <div class="wf-tooltip-row"><span class="wf-tooltip-color" style="background: #F7D238;"></span><span class="wf-tooltip-label font-bold text-text-primary">Wait</span><span class="wf-tooltip-val font-bold text-text-primary">${m.wait.toFixed(1)} ms</span></div>
        <div class="wf-tooltip-row"><span class="wf-tooltip-color" style="background: #7BB835;"></span><span class="wf-tooltip-label">Receive</span><span class="wf-tooltip-val">${m.receive.toFixed(1)} ms</span></div>
        <div class="wf-tooltip-row"><span class="wf-tooltip-color" style="background: #D0D0D0;"></span><span class="wf-tooltip-label">Blocked</span><span class="wf-tooltip-val">${m.blocked.toFixed(1)} ms</span></div>
        <div class="wf-tooltip-divider"></div>
        <div class="wf-tooltip-row"><span class="wf-tooltip-color"></span><span class="wf-tooltip-label font-bold text-text-primary">Total</span><span class="wf-tooltip-val font-bold text-text-primary">${m.total.toFixed(1)} ms</span></div>
    `;
};

window.showWfTooltip = function(event) {
    let layer = document.getElementById('wfTooltipLayer');
    if (!layer) return;

    layer.style.display = 'block';

    // Get layer dimensions (need to display block first)
    const layerWidth = layer.offsetWidth;
    const layerHeight = layer.offsetHeight;

    // Calculate position
    const offset = 12; // distance from cursor
    let leftPos = event.pageX + offset;
    let topPos = event.pageY + offset;

    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    const scrollX = window.scrollX || window.pageXOffset;
    const scrollY = window.scrollY || window.pageYOffset;

    // Clamp right
    if (leftPos + layerWidth > scrollX + viewportWidth - 8) {
        leftPos = event.pageX - layerWidth - offset;
    }

    // Clamp bottom (flip to top if near bottom)
    if (topPos + layerHeight > scrollY + viewportHeight - 8) {
        topPos = event.pageY - layerHeight - offset;
    }

    // Fallback clamp
    if (leftPos < scrollX + 8) leftPos = scrollX + 8;
    if (topPos < scrollY + 8) topPos = scrollY + 8;

    layer.style.left = leftPos + 'px';
    layer.style.top = topPos + 'px';
    layer.style.right = 'auto';
    layer.style.bottom = 'auto';
};

window.hideWfTooltip = function() {
    const layer = document.getElementById('wfTooltipLayer');
    if (layer) {
        layer.style.display = 'none';
    }
};

document.addEventListener('DOMContentLoaded', () => {
    init();
    
    // Bind modal close events
    const modal = document.getElementById('imagePreviewModal');
    const btnClose = document.getElementById('wfBtnCloseImage');
    
    if (btnClose && modal) {
        btnClose.addEventListener('click', () => {
            modal.classList.add('d-none');
        });
        
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.add('d-none');
            }
        });
    }
});
