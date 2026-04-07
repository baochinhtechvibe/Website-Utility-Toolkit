// =============================================
//  WHOIS LOOKUP - MAIN JAVASCRIPT
// =============================================
import {
    setDisplay,
    showElements,
    toggleLoading,
    escapeHTML,
    createRealtimeDomainValidator,
} from "../../utils/index.js";
import { API_BASE_URL } from "../../config.js";

// =============================================
//  TIMELINE CONSTANTS
// =============================================
const VN_TIMELINE = [
    { days: 0,  label: "Hết hạn",            desc: "Tên miền chính thức hết hạn đăng ký.",                                   type: "expiry" },
    { days: 1,  label: "Đình chỉ",            desc: "Tên miền bị tạm ngưng, DNS không còn hoạt động.",                       type: "warn" },
    { days: 30, label: "Chờ thu hồi",         desc: "Hết thời gian gia hạn muộn, đang chờ quy trình thu hồi từ VNNIC.",      type: "warn" },
    { days: 40, label: "Thu hồi / Xóa",       desc: "VNNIC hoàn tất thu hồi. Tên miền sẵn sàng cho đăng ký mới (~15 ngày).", type: "danger" },
];

const INTL_TIMELINE = [
    { days: 0,  label: "Hết hạn",            desc: "Tên miền chính thức hết hạn đăng ký.",                                          type: "expiry" },
    { days: 30, label: "Grace Period",        desc: "Thời gian gia hạn muộn. DNS thường bị đình chỉ trong giai đoạn này.",           type: "warn" },
    { days: 60, label: "Redemption Period",   desc: "Chủ tên miền có thể chuộc lại với chi phí cao (Redemption Fee).",               type: "warn" },
    { days: 65, label: "Pending Delete",      desc: "Tên miền chuẩn bị xóa hoàn toàn. Sau ~5 ngày bất kỳ ai có thể đăng ký lại.",  type: "danger" },
];

// =============================================
//  INIT
// =============================================
function init() {
    const form           = document.getElementById("whoisForm");
    const domainInput    = document.getElementById("whoisDomain");
    const btnLookup      = document.getElementById("btnWhoisLookup");
    const lookupIcon     = document.getElementById("whoisLookupIcon");
    const lookupLoading  = document.getElementById("whoisLookupLoading");
    const validationError = document.getElementById("whoisValidationError");

    const resultCard     = document.getElementById("whoisResultCard");
    const resultTitle    = document.getElementById("whoisResultTitle");
    const errorCard      = document.getElementById("whoisErrorCard");
    const errorMessage   = document.getElementById("whoisErrorMessage");


    const cacheNotice    = document.getElementById("whoisCacheNotice");
    const cacheText      = document.getElementById("whoisCacheText");
    const btnBypass      = document.getElementById("btnBypassCache");

    const infoList       = document.getElementById("whoisInfoList");
    const rawCard        = document.getElementById("whoisRawCard");
    const rawText        = document.getElementById("whoisRawText");
    const timelineBadge  = document.getElementById("whoisTimelineBadge");
    const timelineList   = document.getElementById("whoisTimelineList");

    const shareCard      = document.getElementById("whoisShareCard");
    const shareLink      = document.getElementById("whoisShareLink");
    const btnCopyLink    = document.getElementById("btnCopyWhoisLink");

    let currentDomain = "";

    // -------- Realtime Validation --------
    createRealtimeDomainValidator(domainInput, validationError, btnLookup);

    // -------- Ẩn error card khi user thay đổi input --------
    domainInput.addEventListener("input", () => {
        if (errorCard && !errorCard.classList.contains("d-none")) {
            errorCard.classList.add("d-none");
        }
    });

    // -------- URL Param: Pre-fill domain --------
    const params = new URLSearchParams(window.location.search);
    const domainParam = params.get("domain");
    if (domainParam) {
        domainInput.value = domainParam;
        domainInput.dispatchEvent(new Event("input"));
        // Trigger lookup after short delay
        setTimeout(() => {
            if (!btnLookup.disabled) {
                performLookup(domainParam, false);
            }
        }, 300);
    }

    // -------- Form Submit --------
    form.addEventListener("submit", (e) => {
        e.preventDefault();
        const domain = domainInput.value.trim();
        if (!domain || btnLookup.disabled) return;
        performLookup(domain, false);
    });

    // -------- Bypass Cache Button --------
    btnBypass.addEventListener("click", () => {
        if (currentDomain) {
            performLookup(currentDomain, true);
        }
    });

    // -------- Copy Link --------
    btnCopyLink.addEventListener("click", () => {
        const val = shareLink.value;
        navigator.clipboard.writeText(val).then(() => {
            const icon = btnCopyLink.querySelector("i");
            const span = btnCopyLink.querySelector("span");
            icon.classList.replace("fa-copy", "fa-check");
            span.textContent = "Đã copy!";
            setTimeout(() => {
                icon.classList.replace("fa-check", "fa-copy");
                span.textContent = "Copy";
            }, 1500);
        });
    });

    // ============================================
    //  CORE: Perform WHOIS Lookup
    // ============================================
    async function performLookup(domain, bypass) {
        currentDomain = domain;

        // Reset UI
        showElements("none", resultCard, errorCard, shareCard, rawCard);
        setDisplay(cacheNotice, "none");

        // Loading state
        toggleLoading(btnLookup, lookupIcon, lookupLoading, true);

        // Update URL
        const newURL = `${window.location.pathname}?domain=${encodeURIComponent(domain)}`;
        if (window.location.search !== `?domain=${encodeURIComponent(domain)}`) {
            window.history.pushState({}, "", newURL);
        }

        try {
            const res = await fetch(
                `${API_BASE_URL}/whois/lookup?domain=${encodeURIComponent(domain)}&bypassCache=${bypass}`
            );
            const json = await res.json();

            toggleLoading(btnLookup, lookupIcon, lookupLoading, false);

            if (!json.success || !json.data) {
                showError(json.message || "Tra cứu WHOIS thất bại. Vui lòng thử lại sau.");
                return;
            }

            displayResult(json.data, json.meta);
        } catch (err) {
            console.error("WHOIS fetch error:", err);
            toggleLoading(btnLookup, lookupIcon, lookupLoading, false);
            showError("Không thể kết nối đến máy chủ. Vui lòng kiểm tra kết nối và thử lại.");
        }
    }

    // ============================================
    //  SHOW ERROR
    // ============================================
    function showError(msg) {
        showElements("none", resultCard, shareCard);
        errorMessage.textContent = msg;
        errorCard.classList.remove("d-none");
        setDisplay(errorCard, "block");
    }

    // ============================================
    //  DISPLAY RESULT
    // ============================================
    function displayResult(data, meta) {


        // Cache Notice
        if (meta && meta.fetched_at) {
            const timeStr = new Date(meta.fetched_at).toLocaleString("vi-VN");
            if (meta.cached) {
                cacheText.innerHTML = `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b>${timeStr}</b>.`;
            } else {
                cacheText.innerHTML = `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b>${timeStr}</b>.`;
            }
            setDisplay(cacheNotice, "flex");
        }

        // Result title
        resultTitle.innerHTML = `<i class="fa-solid fa-circle-check"></i> Thông tin WHOIS: <span class="text-success">"${escapeHTML(data.domain || currentDomain)}"</span>`;

        // Render Info List
        renderInfoList(data, infoList);

        // Raw text (always show if present, including RDAP fallback data)
        if (data.raw_text) {
            rawText.textContent = data.raw_text;
            setDisplay(rawCard, "block");
        } else {
            setDisplay(rawCard, "none");
        }

        // Timeline
        renderTimeline(data, timelineBadge, timelineList);

        // Share link
        const link = `${window.location.origin}${window.location.pathname}?domain=${encodeURIComponent(data.domain || currentDomain)}`;
        shareLink.value = link;

        setDisplay(resultCard, "block");
        setDisplay(shareCard, "block");

        resultCard.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // ============================================
    //  FORMAT: DNSSEC status
    // ============================================
    function formatDNSSEC(dnssecData) {
        if (!dnssecData) return "unsigned";
        if (dnssecData.status === "SECURE") {
            return `<span class="badge badge-success">signedDelegation</span>`;
        }
        if (dnssecData.status === "BOGUS") {
            return `<span class="badge badge-warning">bogus</span>`;
        }
        return "unsigned";
    }

    // ============================================
    //  RENDER: Info List (DL)
    // ============================================
    function renderInfoList(data, container) {
        const fields = [
            { icon: "fa-globe", label: "Tên miền", value: data.domain || "-" },
            { icon: "fa-building", label: "Nhà đăng ký", value: data.registrar || "-" },
            { icon: "fa-user", label: "Chủ sở hữu", value: data.registrant || "-" },
            { icon: "fa-calendar-plus", label: "Ngày đăng ký", value: formatDateTime(data.registered_on) },
            { icon: "fa-calendar-xmark", label: "Ngày hết hạn", value: data.expires_on, isExpiry: true },
            { icon: "fa-server", label: "Name Servers", value: (data.nameservers && data.nameservers.length) ? data.nameservers.map(ns => `<span>${escapeHTML(ns.toLowerCase())}</span>`).join("") : "-" },
            { icon: "fa-toggle-on", label: "Trạng thái", value: (data.status && data.status.length) ? formatStatus(data.status) : "-" },
            { icon: "fa-shield-halved", label: "DNSSEC", value: formatDNSSEC(data.dnssec) },
            { icon: "fa-pen", label: "Cập nhật lần cuối", value: formatDateTime(data.updated_on) },
        ];

        container.innerHTML = fields.map(f => {
            let valueHtml;
            if (f.isExpiry && data.expires_on) {
                const expiryClass = getExpiryClass(data.expires_on);
                valueHtml = `<span class="${expiryClass}">${formatDateTime(data.expires_on)}</span>`;
            } else if (f.label === "Name Servers" || f.label === "Trạng thái" || f.label === "DNSSEC") {
                valueHtml = f.value; // Already escaped/formatted
            } else {
                valueHtml = escapeHTML(f.value || "-");
            }

            return `
                <dt><i class="fa-solid ${f.icon}"></i> ${escapeHTML(f.label)}</dt>
                <dd>${valueHtml}</dd>
            `;
        }).join("");
    }

    // ============================================
    //  FORMAT: Status list to multiline HTML
    // ============================================

    // Map lookup EPP status codes chuẩn → camelCase
    const EPP_STATUS_MAP = {
        "client transfer prohibited": "clientTransferProhibited",
        "client update prohibited": "clientUpdateProhibited",
        "client delete prohibited": "clientDeleteProhibited",
        "client renew prohibited": "clientRenewProhibited",
        "client hold": "clientHold",
        "server transfer prohibited": "serverTransferProhibited",
        "server update prohibited": "serverUpdateProhibited",
        "server delete prohibited": "serverDeleteProhibited",
        "server renew prohibited": "serverRenewProhibited",
        "server hold": "serverHold",
        "inactive": "inactive",
        "pending create": "pendingCreate",
        "pending delete": "pendingDelete",
        "pending renew": "pendingRenew",
        "pending restore": "pendingRestore",
        "pending transfer": "pendingTransfer",
        "pending update": "pendingUpdate",
        "redemption period": "redemptionPeriod",
        "auto renew period": "autoRenewPeriod",
        "transfer period": "transferPeriod",
    };

    function formatStatus(statuses) {
        return statuses.map(s => {
            // Tách phần status code ra khỏi URL (nếu có)
            const urlMatch = s.match(/\s*\(?https?:\/\/[^\s)]+\)?/i);
            let code = urlMatch ? s.slice(0, urlMatch.index).trim() : s.trim();

            // Cố gắng chuẩn hoá sang camelCase bằng map lookup
            const lowerCode = code.toLowerCase();
            if (EPP_STATUS_MAP[lowerCode]) {
                code = EPP_STATUS_MAP[lowerCode];
            }

            // Append ICANN URL nếu chưa có và là status chuẩn
            let icannLink = "";
            if (!s.includes("http") && /prohibited|ok|active|hold|pending|period|inactive/i.test(code)) {
                const icannUrl = `https://icann.org/epp#${code}`;
                icannLink = ` <a href="${icannUrl}" target="_blank" rel="noopener" class="text-muted">[ICANN]</a>`;
            }

            // Phân loại màu
            const lcCode = code.toLowerCase();
            const isOk = ["ok", "active"].includes(lcCode) || lcCode.includes("prohibited");
            const isWarn = lcCode.includes("delete") || lcCode.includes("hold") || lcCode.includes("pending") || lcCode.includes("redemption");
            const colorCls = isOk ? "text-success" : isWarn ? "text-warning" : "text-secondary";

            return `<span class="${colorCls}">${escapeHTML(code)}${icannLink}</span>`;
        }).join("");
    }

    // Removed renderStatus and renderNameservers as they are now integrated into renderInfoList

    // ============================================
    //  RENDER: Domain Lifecycle Timeline
    // ============================================
    function renderTimeline(data, badgeContainer, listContainer) {
        const expiryStr = data.expires_on;

        if (!expiryStr) {
            badgeContainer.innerHTML = "";
            listContainer.innerHTML = `
                <div class="whois__no-expiry">
                    <i class="fa-solid fa-circle-question"></i>
                    <p>Không có thông tin ngày hết hạn.</p>
                    <p>Tên miền này có thể không áp dụng thời hạn (ví dụ: ccTLD đặc biệt).</p>
                </div>
            `;
            return;
        }

        const expiryDate = new Date(expiryStr);
        const now = new Date();
        const diffDays = Math.floor((expiryDate - now) / (1000 * 60 * 60 * 24));
        const isVN = data.is_vn_domain;
        const steps = isVN ? VN_TIMELINE : INTL_TIMELINE;

        // "Còn X ngày" badge
        let daysBadgeHtml = "";
        if (diffDays > 90) {
            daysBadgeHtml = `<div class="whois__days-badge whois__days-badge--safe"><i class="fa-solid fa-circle-check"></i> Còn ${diffDays} ngày</div>`;
        } else if (diffDays > 30) {
            daysBadgeHtml = `<div class="whois__days-badge whois__days-badge--warning"><i class="fa-solid fa-triangle-exclamation"></i> Còn ${diffDays} ngày</div>`;
        } else if (diffDays > 0) {
            daysBadgeHtml = `<div class="whois__days-badge whois__days-badge--danger"><i class="fa-solid fa-fire"></i> Còn ${diffDays} ngày — Gia hạn ngay!</div>`;
        } else {
            const expiredDays = Math.abs(diffDays);
            daysBadgeHtml = `<div class="whois__days-badge whois__days-badge--expired"><i class="fa-solid fa-circle-xmark"></i> Đã hết hạn ${expiredDays} ngày trước</div>`;
        }

        // Build timeline steps
        // Step 0: Ngày đăng ký (nếu có)
        const registeredItems = [];
        if (data.registered_on) {
            registeredItems.push(renderTimelineItem({
                icon: "fa-circle-plus",
                iconClass: "whois__timeline-icon--done",
                labelClass: "whois__timeline-label--done",
                date: formatDateTime(data.registered_on),
                label: "Đăng ký",
                desc: "Tên miền được đăng ký thành công.",
                state: "done",
            }));
        }

        // Step: Active (hiện tại - nếu chưa hết hạn)
        if (diffDays > 0) {
            registeredItems.push(renderTimelineItem({
                icon: "fa-circle-check",
                iconClass: "whois__timeline-icon--current",
                labelClass: "whois__timeline-label--current",
                date: "Hiện tại",
                label: "Đang hoạt động",
                desc: "Tên miền đang hoạt động bình thường.",
                state: "current",
            }));
        }

        // Step: Expiry và các bước tiếp theo
        const lifecycleItems = steps.map((step, idx) => {
            const stepDate = new Date(expiryDate);
            stepDate.setDate(stepDate.getDate() + step.days);
            const isPast = now > stepDate;
            const isCurrent = idx === 0 && diffDays <= 0 && diffDays > -(steps[1]?.days || 999);

            let iconClass, labelClass, icon;

            if (isPast) {
                icon = "fa-check";
                iconClass = "whois__timeline-icon--done";
                labelClass = "whois__timeline-label--done";
            } else if (isCurrent) {
                icon = step.type === "danger" ? "fa-circle-xmark" : "fa-circle-exclamation";
                iconClass = (step.type === "danger") ? "whois__timeline-icon--danger" : "whois__timeline-icon--current";
                labelClass = (step.type === "danger") ? "whois__timeline-label--danger" : "whois__timeline-label--current";
            } else {
                icon = "fa-circle";
                iconClass = "whois__timeline-icon--upcoming";
                labelClass = "whois__timeline-label--upcoming";
            }

            return renderTimelineItem({
                icon,
                iconClass,
                labelClass,
                date: formatDateTime(stepDate.toISOString()),
                label: step.label,
                desc: step.desc,
                state: isPast ? "done" : isCurrent ? "current" : "upcoming",
            });
        });

        badgeContainer.innerHTML = daysBadgeHtml;
        listContainer.innerHTML = registeredItems.join("") + lifecycleItems.join("");
    }

    function renderTimelineItem({ icon, iconClass, labelClass, date, label, desc }) {
        return `
            <div class="whois__timeline-item">
                <div class="whois__timeline-icon ${iconClass}">
                    <i class="fa-solid ${icon}"></i>
                </div>
                <div class="whois__timeline-content">
                    <div class="whois__timeline-date">${escapeHTML(date)}</div>
                    <div class="whois__timeline-label ${labelClass}">${escapeHTML(label)}</div>
                    <div class="whois__timeline-desc">${escapeHTML(desc)}</div>
                </div>
            </div>
        `;
    }

    // ============================================
    //  HELPERS
    // ============================================
    function formatDateTime(str) {
        if (!str) return "-";
        try {
            const d = new Date(str);
            if (isNaN(d.getTime())) return str;
            
            // Format: DD/MM/YYYY HH:mm:ss (GMT+7)
            const options = {
                timeZone: "Asia/Ho_Chi_Minh",
                day: "2-digit",
                month: "2-digit",
                year: "numeric",
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false
            };
            
            return d.toLocaleString("vi-VN", options);
        } catch {
            return str;
        }
    }

    function getExpiryClass(expiryStr) {
        const expiry = new Date(expiryStr);
        const now = new Date();
        const diffDays = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));
        if (diffDays <= 0) return "whois__expiry--danger";
        if (diffDays <= 30) return "whois__expiry--danger";
        if (diffDays <= 90) return "whois__expiry--warning";
        return "whois__expiry--safe";
    }
}

document.addEventListener("DOMContentLoaded", init);
