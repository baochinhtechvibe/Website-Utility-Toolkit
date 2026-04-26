/**
 * client/src/js/tools/bot-simulator/bot-simulator.js
 * Bot Simulator – Indexability Analyzer
 */

import {
    $,
    setDisplay,
    toggleLoading,
    setElementsEnabled,
    escapeHTML,
    createRealtimeURLValidator
} from "../../utils/index.js";
import { API_BASE_URL } from "../../config.js";

const API_ENDPOINT = `${API_BASE_URL}/bot-simulator/analyze`;

function init() {
    // ─── DOM Refs ────────────────────────────────────────────────────
    const form            = $('#botSimulatorForm');
    const urlInput        = $('#botSimUrl');
    const botSelect       = $('#botSelect');
    const urlError        = $('#urlValidationError');
    const btnAnalyze      = $('#btnAnalyze');
    const analyzeIcon     = $('#analyzeIcon');
    const analyzeLoading  = $('#analyzeLoading');
    const errorCard       = $('#errorCard');
    const errorMessage    = $('#errorMessage');
    const resultSection   = $('#resultSection');
    const shareLink       = $('#shareLink');
    const btnCopyLink     = $('#btnCopyLink');
    
    // Verdict Banner
    const verdictBanner     = $('#verdictBanner');
    const verdictIcon       = $('#verdictIcon');
    const verdictLabel      = $('#verdictLabel');
    const verdictConfidence = $('#verdictConfidence');
    const verdictSummary    = $('#verdictSummary');
    const activeBotLabel    = $('#activeBotLabel');

    // Cache Banner
    const cacheNotice    = $('#cacheNotice');
    const btnBypassCache = $('#btnBypassCache');

    // Summary Strip
    const crawlStatus = $('#crawlStatus');
    const indexStatus = $('#indexStatus');
    const httpStatus  = $('#httpStatus');

    // Evidence
    const robotsFetchStatus  = $('#robotsFetchStatus');
    const robotsMatchedGroup = $('#robotsMatchedGroup');
    const robotsMatchedRule  = $('#robotsMatchedRule');
    const robotsDecision     = $('#robotsDecision');

    const metaRobotsVal = $('#metaRobotsVal');
    const xRobotsVal    = $('#xRobotsVal');
    const canonicalVal  = $('#canonicalVal');
    const canonicalSelf = $('#canonicalSelf');
    const indexDetail   = $('#indexDetail');

    const servingFinalUrl    = $('#servingFinalUrl');
    const servingStatus      = $('#servingStatus');
    const servingContentType = $('#servingContentType');
    const servingPayload     = $('#servingPayload');
    const servingRedirects   = $('#servingRedirects');
    const redirectChainWrap  = $('#redirectChainWrap');
    const redirectChainList  = $('#redirectChainList');

    const sitemapContent  = $('#sitemapContent');
    const reasonCodes     = $('#reasonCodes');
    const suggestionList  = $('#suggestionList');
    const compareCard     = $('#compareCard');
    const compareTableBody = $('#compareTableBody');
    const limitationsList = $('#limitationsList');

    let isProcessing = false;

    // ─── State Management ───────────────────────────────────────────
    const updateButtonStates = () => {
        const url = urlInput?.value.trim() || "";
        if (btnAnalyze) {
            btnAnalyze.disabled = url === "" || isProcessing;
        }
    };

    urlInput?.addEventListener('input', () => {
        // Chỉ ẩn errorCard (lỗi logic/lookup). Không đụng vào #urlValidationError
        // vì createRealtimeURLValidator tự quản lý element đó (Rule #26).
        hideError();
        updateButtonStates();
    });

    // ─── Form Submit ─────────────────────────────────────────────────
    form?.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url || isProcessing) return;
        await runAnalyze(url);
    });

    // ─── Main Analyze Flow ───────────────────────────────────────────
    async function runAnalyze(url, forcedBypassCache = false) {
        if (isProcessing) return;
        
        isProcessing = true;
        setLoading(true);
        hideError();
        hideResult();

        // Tự động thêm https:// nếu thiếu (Rule #UX Fix)
        let target = url;
        if (!/^https?:\/\//i.test(target)) {
            target = 'https://' + target;
            if (urlInput) urlInput.value = target; // Cập nhật luôn UI
        }

        const bot          = botSelect?.value || 'googlebot-desktop';
        const ignoreTLS    = $('#ignoreTLSErrors')?.checked;
        const checkSitemap = $('#checkSitemap')?.checked;
        const compareMode  = $('#compareMode')?.checked;

        const payload = {
            url: target,
            bot,
            ignore_tls_errors: ignoreTLS,
            check_sitemap: checkSitemap,
            bypass_cache: forcedBypassCache,
            compare_mode: compareMode,
            compare_bots: compareMode ? [] : undefined,
        };

        try {
            const response = await fetch(API_ENDPOINT, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const result = await response.json();

            if (!result.success) {
                showError(result.message || result.error || 'Phân tích thất bại.');
                return;
            }
            renderResult(result);
        } catch (err) {
            showError('Không thể kết nối tới server. Vui lòng thử lại sau.');
            console.error(err);
        } finally {
            setLoading(false);
            isProcessing = false;
            updateButtonStates();
        }
    }

    function renderResult(response) {
        // Clone dữ liệu để đảm bảo immutability (Rule #51)
        const data = { ...response.data };
        const meta = response.meta ? { ...response.meta } : null;

        // Cache Banner
        if (meta && cacheNotice) {
            setDisplay(cacheNotice, 'flex');
            const timeStr = new Date(meta.fetched_at).toLocaleString('vi-VN');
            const spanEl = cacheNotice.querySelector('span');

            if (meta.cached) {
                spanEl.innerHTML = `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b id="cacheTime">${timeStr}</b>`;
            } else {
                spanEl.innerHTML = `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b id="cacheTime">${timeStr}</b>`;
            }
        } else if (cacheNotice) {
            setDisplay(cacheNotice, 'none');
        }

        // Verdict Banner
        renderVerdictBanner(data.verdict, data.bot_profile);

        // Summary Strip
        renderSummaryStrip(data);

        // Robots.txt
        renderRobots(data.crawl_access);

        // Meta Signals
        renderMeta(data.indexability);

        // Serving
        renderServing(data.serving);

        // Sitemap
        renderSitemap(data.sitemap);

        // Reason Codes & Suggestions
        renderReasonCodes(data.verdict);

        // Compare
        if (data.compare && data.compare.length > 0) {
            renderCompare(data.compare);
            setDisplay(compareCard, 'block');
        } else {
            setDisplay(compareCard, 'none');
        }

        // Limitations
        renderLimitations(data.limitations);

        // Share link
        const shareUrl = new URL(window.location.href);
        shareUrl.searchParams.set('url', data.target);
        shareUrl.searchParams.set('bot', data.bot_profile.key);
        shareLink.value = shareUrl.toString();

        // Sync History / URL Bar
        updateURL(data.target, data.bot_profile.key);

        showResult();
    }

    function updateURL(url, bot) {
        try {
            const params = new URLSearchParams(window.location.search);
            params.set('url', url);
            params.set('bot', bot);
            const newSearch = `?${params.toString()}`;
            const newURL = `${window.location.pathname}${newSearch}`;
            if (window.location.search !== newSearch) {
                window.history.pushState({ url, bot }, '', newURL);
            }
        } catch (err) {
            console.warn("Lỗi cập nhật URL:", err);
        }
    }

    function renderVerdictBanner(verdict, botProfile) {
        verdictBanner.className = 'bs-verdict-banner mb-4';
        const icons = {
            Indexable: 'fa-circle-check',
            Blocked:   'fa-circle-xmark',
            Risky:     'fa-triangle-exclamation',
            Unknown:   'fa-circle-question',
        };
        const verdictKey = verdict.result || 'Unknown';
        verdictBanner.classList.add(`bs-verdict--${verdictKey.toLowerCase()}`);
        verdictIcon.className = `fa-solid ${icons[verdictKey] || 'fa-circle-question'}`;
        verdictLabel.textContent = verdictKey;
        const confMap = { high: 'Độ tin cậy cao', medium: 'Độ tin cậy trung bình', low: 'Độ tin cậy thấp' };
        verdictConfidence.textContent = confMap[verdict.confidence] || verdict.confidence || '';
        verdictSummary.textContent = verdict.summary || '';
        activeBotLabel.textContent = botProfile?.label || '';
    }

    function renderSummaryStrip(data) {
        const crawl = data.crawl_access;
        const index = data.indexability;
        const serving = data.serving;
        const statusLabels = {
            allowed:    'Cho phép',
            blocked:    'Bị chặn',
            timeout:    'Timeout',
            error:      'Lỗi',
            deferred:   'Hoãn (5xx)',
            unreachable:'Không kết nối được',
            unknown_due_to_crawl_block: 'Không rõ (chặn crawl)',
        };
        setStatusCell(crawlStatus, crawl.status, statusLabels[crawl.status] || crawl.status);
        setStatusCell(indexStatus, index.status, statusLabels[index.status] || index.status);
        const code = serving.initial_status_code;
        const statusClass = code >= 500 ? 'risky' : (code >= 400 ? 'blocked' : (code >= 300 ? 'risky' : (code >= 200 ? 'allowed' : 'unknown')));
        httpStatus.textContent = code ? `${code} ${serving.initial_status_text || ''}` : '–';
        httpStatus.className = `bs-summary-cell__value status--${statusClass}`;
    }

    function setStatusCell(el, status, label) {
        el.textContent = label || '–';
        const classSuffix = {
            allowed: 'allowed', blocked: 'blocked', deferred: 'deferred',
            risky: 'risky', timeout: 'risky', error: 'blocked', unreachable: 'blocked',
            unknown_due_to_crawl_block: 'unknown',
        };
        el.className = `bs-summary-cell__value status--${classSuffix[status] || 'unknown'}`;
    }

    function renderRobots(crawl) {
        const fetchStatusMap = {
            '2xx': ['badge-success', 'Tìm thấy (2xx)'],
            '3xx': ['badge-info', 'Redirect (3xx)'],
            '4xx_allow': ['badge-warning', '4xx → Cho phép tất cả'],
            '5xx_block': ['badge-error', '5xx → Hoãn crawl'],
            timeout: ['badge-error', 'Timeout'],
            unreachable: ['badge-error', 'Không kết nối được'],
            none: ['badge-default', 'Không check'],
        };
        const [cls, lbl] = fetchStatusMap[crawl.robots_status] || ['badge-default', crawl.robots_status || '–'];
        robotsFetchStatus.textContent = lbl;
        robotsFetchStatus.className = `badge ${cls}`;
        robotsMatchedGroup.textContent = crawl.matched_group || '–';
        robotsMatchedRule.textContent  = crawl.matched_rule  || '–';
        const decMap = {
            allow: ['badge-success', 'Allow'],
            disallow: ['badge-error', 'Disallow'],
            default_allow: ['badge-info', 'Mặc định: Cho phép'],
            default_disallow: ['badge-warning', 'Mặc định: Chặn'],
        };
        const [dCls, dLbl] = decMap[crawl.decision] || ['badge-default', crawl.decision || '–'];
        robotsDecision.textContent = dLbl;
        robotsDecision.className = `badge ${dCls}`;
    }

    function renderMeta(indexability) {
        metaRobotsVal.textContent = indexability.meta_robots || '(không có)';
        xRobotsVal.textContent    = indexability.x_robots_tag || '(không có)';
        if (indexability.canonical_missing) {
            canonicalVal.textContent = '(thiếu canonical)';
        } else {
            canonicalVal.textContent = indexability.canonical_url || '–';
            canonicalVal.title = indexability.canonical_url || '';
        }
        if (indexability.canonical_missing) {
            canonicalSelf.textContent = '–';
            canonicalSelf.className = 'badge badge-warning';
        } else {
            canonicalSelf.textContent = indexability.canonical_self ? 'Đúng (self)' : 'Khác (không phải self)';
            canonicalSelf.className = indexability.canonical_self ? 'badge badge-success' : 'badge badge-warning';
        }
        const indexMap = {
            allowed: ['badge-success', 'Cho phép index'],
            blocked: ['badge-error', 'Bị chặn index'],
            unknown_due_to_crawl_block: ['badge-warning', 'Không rõ (chặn crawl)'],
        };
        const [iCls, iLbl] = indexMap[indexability.status] || ['badge-default', indexability.status || '–'];
        indexDetail.textContent = iLbl;
        indexDetail.className = `badge ${iCls}`;
    }

    function renderServing(serving) {
        servingFinalUrl.textContent = serving.final_url || '–';
        servingFinalUrl.title = serving.final_url || '';
        const code = serving.initial_status_code;
        const codeCls = code >= 500 ? 'badge-error' : (code >= 400 ? 'badge-error' : (code >= 300 ? 'badge-warning' : (code >= 200 ? 'badge-success' : 'badge-default')));
        servingStatus.textContent = code ? `${code} ${serving.initial_status_text || ''}` : '–';
        servingStatus.className = `badge ${codeCls}`;
        servingContentType.textContent = serving.content_type || '–';
        servingPayload.textContent = serving.payload_bytes > 0 ? formatBytes(serving.payload_bytes) : '–';
        servingRedirects.textContent = String(serving.redirect_count || 0);
        
        const chain = serving.redirect_chain_summary || [];
        if (chain.length > 0) {
            redirectChainList.innerHTML = '';
            chain.forEach(hop => {
                const hop_code_class = hop.status_code >= 400 ? 'badge-error' : (hop.status_code >= 300 ? 'badge-warning' : 'badge-success');
                const div = document.createElement('div');
                div.className = 'bs-redirect-hop';
                div.innerHTML = `
                    <span class="bs-redirect-hop__step">#${hop.step}</span>
                    <span class="badge ${hop_code_class} bs-redirect-hop__code">${hop.status_code} ${escapeHTML(hop.status_text || '')}</span>
                    <span class="bs-redirect-hop__url" title="${escapeHTML(hop.url)}">${escapeHTML(truncateUrl(hop.url, 60))}</span>
                `;
                redirectChainList.appendChild(div);
            });
            setDisplay(redirectChainWrap, 'block');
        } else {
            setDisplay(redirectChainWrap, 'none');
        }
    }

    function renderSitemap(sitemap) {
        if (!sitemap || !sitemap.checked) {
            sitemapContent.innerHTML = '<p class="bs-evidence-value text-center text-muted">Chưa kiểm tra sitemap.</p>';
            return;
        }
        if (!sitemap.found) {
            sitemapContent.innerHTML = `
                <div class="bs-evidence-row">
                    <span class="bs-evidence-label">Trạng thái</span>
                    <span class="badge badge-warning">Không tìm thấy sitemap</span>
                </div>
                <div class="bs-evidence-row">
                    <span class="bs-evidence-label">Discovery</span>
                    <span class="bs-evidence-value">${escapeHTML(sitemap.discovery_path || '–')}</span>
                </div>`;
            return;
        }
        const inSitemapBadge = sitemap.url_in_sitemap ? '<span class="badge badge-success">Có trong sitemap</span>' : '<span class="badge badge-warning">Không có trong sitemap</span>';
        const sitemapUrl = sitemap.sitemap_url || '';
        const safeSitemapUrl = isValidHttpUrl(sitemapUrl) ? escapeHTML(sitemapUrl) : '#';
        const sitemapLink = sitemapUrl ? `<div class="bs-evidence-row"><span class="bs-evidence-label">Sitemap URL</span><a href="${safeSitemapUrl}" target="_blank" rel="noopener noreferrer" class="bs-evidence-value text-truncate-url" title="${escapeHTML(sitemapUrl)}">${escapeHTML(truncateUrl(sitemapUrl, 50))}</a></div>` : '';
        sitemapContent.innerHTML = `<div class="bs-evidence-row"><span class="bs-evidence-label">Tìm thấy qua</span><span class="bs-evidence-value">${escapeHTML(sitemap.discovery_path || '–')}</span></div><div class="bs-evidence-row"><span class="bs-evidence-label">URL trong sitemap</span>${inSitemapBadge}</div><div class="bs-evidence-row"><span class="bs-evidence-label">Files quét</span><span class="bs-evidence-value">${sitemap.files_scanned} / URLs đã kiểm tra: ${sitemap.urls_checked}</span></div>${sitemapLink}`;
    }

    function renderReasonCodes(verdict) {
        const codes = verdict.reason_codes || [];
        const suggestions = verdict.suggestions || [];
        reasonCodes.innerHTML = '';
        if (codes.length === 0) {
            reasonCodes.innerHTML = '<span class="badge badge-default">Không có cờ đặc biệt</span>';
        } else {
            codes.forEach(code => {
                const span = document.createElement('span');
                span.className = `badge badge-sm ${getReasonCodeClass(code)}`;
                span.textContent = code;
                reasonCodes.appendChild(span);
            });
        }
        suggestionList.innerHTML = '';
        if (suggestions.length === 0) {
            const card = document.createElement('div');
            card.className = 'message-card message-card--suggestion';
            card.innerHTML = `<div class="message-card__body"><p class="message-card__message"><i class="fa-solid fa-circle-check mr-1"></i> Không có đề xuất nào – cấu hình đang tốt!</p></div>`;
            suggestionList.appendChild(card);
        } else {
            suggestions.forEach(s => {
                const card = document.createElement('div');
                card.className = 'message-card message-card--info mb-2';
                card.innerHTML = `<div class="message-card__body"><p class="message-card__message"><i class="fa-solid fa-arrow-right mr-1"></i> ${escapeHTML(s)}</p></div>`;
                suggestionList.appendChild(card);
            });
        }
    }

    function getReasonCodeClass(code) {
        if (code.includes('BLOCK') || code.includes('NOINDEX') || code === 'HTTP_404') return 'badge-error';
        if (code.includes('MISSING') || code.includes('MISMATCH') || code.includes('5XX') || code.includes('USER_FETCHER')) return 'badge-warning';
        if (code.includes('CRAWL_BLOCK')) return 'badge-warning';
        return 'badge-default';
    }

    function renderCompare(compareResults) {
        compareTableBody.innerHTML = '';
        compareResults.forEach((r, idx) => {
            const tr = document.createElement('tr');
            const hasDiff = r.diff && r.diff.length > 0 && idx > 0;
            if (hasDiff) tr.classList.add('has-diff');
            const crawlBadge = statusBadge(r.crawl_status, { allowed: 'badge-success', blocked: 'badge-error', deferred: 'badge-warning', error: 'badge-error', unreachable: 'badge-error', timeout: 'badge-warning' });
            const indexBadge = statusBadge(r.index_status, { allowed: 'badge-success', blocked: 'badge-error', unknown_due_to_crawl_block: 'badge-warning' });
            const codeCls = r.status_code >= 500 ? 'badge-error' : r.status_code >= 400 ? 'badge-error' : r.status_code >= 300 ? 'badge-warning' : 'badge-success';
            const httpBadge = r.status_code ? `<span class="badge badge-sm ${codeCls}">${r.status_code}</span>` : '–';
            const diffBadges = (r.diff || []).map(d => `<span class="bs-diff-badge" title="Khác: ${escapeHTML(d)}">${escapeHTML(d)}</span>`).join('');
            tr.innerHTML = `<td><strong>${escapeHTML(r.bot_label || r.bot)}</strong></td><td>${crawlBadge}</td><td>${indexBadge}</td><td>${httpBadge}</td><td>${escapeHTML(r.final_url || '')}</td><td>${escapeHTML(r.title || '')}</td><td>${diffBadges || (idx === 0 ? '<span class="badge badge-sm badge-default">Tham chiếu</span>' : '<span class="badge badge-sm badge-success">Giống</span>')}</td>`;
            if (r.error) {
                tr.innerHTML = `<td><strong>${escapeHTML(r.bot_label || r.bot)}</strong></td><td colspan="6"><span class="badge badge-error">Lỗi: ${escapeHTML(r.error)}</span></td>`;
            }
            compareTableBody.appendChild(tr);
        });
    }

    function statusBadge(status, classMap) {
        const labels = { allowed: 'Allowed', blocked: 'Blocked', deferred: 'Deferred (5xx)', error: 'Error', unreachable: 'Unreachable', timeout: 'Timeout', unknown_due_to_crawl_block: 'Unknown (crawl block)' };
        const cls = classMap[status] || 'badge-default';
        const lbl = labels[status] || status || '–';
        return `<span class="badge badge-sm ${cls}">${escapeHTML(lbl)}</span>`;
    }

    function renderLimitations(limits) {
        limitationsList.innerHTML = '';
        if (!limits || limits.length === 0) return;
        limits.forEach(l => {
            const li = document.createElement('li');
            li.innerHTML = `<div class="bs-limitation-content"><strong>${escapeHTML(l.code)}:</strong> ${escapeHTML(l.message)}</div>`;
            limitationsList.appendChild(li);
        });
    }

    // ─── Helpers ─────────────────────────────────────────────────────
    function isValidHttpUrl(string) {
        try {
            const url = new URL(string);
            return url.protocol === "http:" || url.protocol === "https:";
        } catch (_) {
            return false;
        }
    }

    function setLoading(on) {
        toggleLoading(btnAnalyze, analyzeIcon, analyzeLoading, on);
        setElementsEnabled([urlInput, btnAnalyze], !on);
    }

    function showError(msg) {
        errorMessage.textContent = msg;
        setDisplay(errorCard, 'block');
    }

    function hideError() {
        setDisplay(errorCard, 'none');
    }

    function showResult() {
        setDisplay(resultSection, 'block');
    }

    function hideResult() {
        setDisplay(resultSection, 'none');
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
        return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
    }

    function truncateUrl(url, max) {
        if (!url) return '';
        // Sử dụng array spread để an toàn với ký tự đa byte (Rule #50 tương đương JS)
        const chars = [...url];
        if (chars.length <= max) return url;
        return chars.slice(0, max - 3).join('') + '...';
    }

    // ─── Initial Logic ──────────────────────────────────────────────
    createRealtimeURLValidator(urlInput, urlError, btnAnalyze);

    const handleParams = () => {
        const params = new URLSearchParams(window.location.search);
        const pUrl = params.get('url');
        const pBot = params.get('bot');

        if (pUrl && urlInput) {
            urlInput.value = decodeURIComponent(pUrl);
            urlInput.dispatchEvent(new Event('input')); // Đồng bộ validator (Rule #37)
            if (pBot && botSelect) {
                const opt = botSelect.querySelector(`option[value="${pBot}"]`);
                if (opt) botSelect.value = pBot;
            }
            isProcessing = false;
            updateButtonStates();
            // Gọi trực tiếp thay vì dispatchEvent('submit') để tránh side effect (Safety)
            runAnalyze(decodeURIComponent(pUrl));
        } else {
            urlInput.value = "";
            hideResult();
            hideError();
            updateButtonStates();
        }
    };

    handleParams();

    window.addEventListener("popstate", () => {
        handleParams();
    });

    btnCopyLink?.addEventListener('click', async () => {
        try {
            shareLink.select();
            shareLink.setSelectionRange(0, 99999);
            await navigator.clipboard.writeText(shareLink.value);
            const original = btnCopyLink.innerHTML;
            btnCopyLink.innerHTML = '<i class="fas fa-check"></i> <span>Đã copy!</span>';
            setTimeout(() => { btnCopyLink.innerHTML = original; }, 2000);
        } catch (err) {
            console.error("Copy failed:", err);
        }
    });

    btnBypassCache?.addEventListener('click', () => {
        const url = urlInput.value.trim();
        if (url) runAnalyze(url, true);
    });
}

// Khởi chạy khi DOM sẵn sàng
document.addEventListener('DOMContentLoaded', init);
