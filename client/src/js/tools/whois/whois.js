// =============================================
//  WHOIS LOOKUP - MAIN JAVASCRIPT
// =============================================
import {
    setDisplay,
    showElements,
    toggleLoading,
    escapeHTML,
    createRealtimeDomainValidator,
    renderSuccessHeader,
} from "../../utils/index.js";
import { API_BASE_URL } from "../../config.js";

// =============================================
//  TIMELINE CONSTANTS
// =============================================
const VN_TIMELINE = [
    { days: 0,  label: "Hết hạn",            desc: "Tên miền chính thức hết hạn đăng ký.",                                   type: "expiry",  icon: "fa-clock" },
    { days: 1,  label: "Tạm ngưng hoạt động", desc: "Tên miền bị tạm ngưng. Bạn có 25 ngày để gia hạn với giá bình thường.",    type: "danger",  icon: "fa-triangle-exclamation" },
    { days: 26, label: "Chờ thu hồi",         desc: "Tên miền chuyển sang trạng thái chờ thu hồi (Pending Delete). Không thể gia hạn.", type: "muted",   icon: "fa-hourglass-half" },
    { days: 31, label: "Giải phóng",          desc: "VNNIC hoàn tất thu hồi. Tên miền sẵn sàng cho đăng ký mới.",                type: "muted",   icon: "fa-skull-crossbones" },
];

const INTL_TIMELINE = [
    { days: 0,  label: "Hết hạn",            desc: "Tên miền đến ngày hết hạn sử dụng.",                                          type: "expiry",  icon: "fa-clock" },
    { days: 1,  label: "Gia hạn bình thường", desc: "Tên miền bị tạm ngưng. Bạn vẫn có thể gia hạn với giá thông thường.",           type: "danger",  icon: "fa-triangle-exclamation" },
    { days: 41, label: "Giai đoạn Chuộc",     desc: "Tên miền có thể được chuộc lại với chi phí rất cao (Redemption Period).",      type: "muted",   icon: "fa-money-bill-transfer" },
    { days: 71, label: "Chờ xóa",            desc: "Tên miền chuẩn bị xóa hoàn toàn (Pending Delete). Không thể gia hạn/chuộc.",    type: "muted",   icon: "fa-hourglass-end" },
    { days: 76, label: "Giải phóng",         desc: "Tên miền sẵn sàng cho bất kỳ ai đăng ký mới.",                                   type: "muted",   icon: "fa-skull-crossbones" },
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


    const cacheNotice    = document.getElementById("cacheNotice");
    const cacheText      = document.getElementById("cacheText");
    const cacheTime      = document.getElementById("cacheTime");
    const btnBypass      = document.getElementById("btnBypassCache");

    const infoList       = document.getElementById("whoisInfoList");
    const rawCard        = document.getElementById("whoisRawCard");
    const rawText        = document.getElementById("whoisRawText");
    const timelineBadge  = document.getElementById("whoisTimelineBadge");
    const timelineList   = document.getElementById("whoisTimelineList");

    const shareCard      = document.getElementById("whoisShareCard");
    const shareLink      = document.getElementById("whoisShareLink");
    const btnCopyLink    = document.getElementById("btnCopyWhoisLink");

    const availableMsg   = document.getElementById("whoisAvailableMsg");
    const whoisLayout    = document.getElementById("whoisLayout");

    let currentDomain = "";
    let isProcessing = false;
    let currentAbortController = null;

    // -------- Realtime Validation --------
    createRealtimeDomainValidator(domainInput, validationError, btnLookup);

    // -------- Ẩn error/result card khi user thay đổi nhập liệu --------
    domainInput.addEventListener("input", () => {
        setDisplay(errorCard, "none");
        setDisplay(resultCard, "none");
        setDisplay(shareCard, "none");
    });

    // -------- URL Param: Pre-fill domain --------
    const params = new URLSearchParams(window.location.search);
    const domainParam = params.get("domain");
    if (domainParam) {
        domainInput.value = domainParam;
        domainInput.dispatchEvent(new Event("input"));
        // Đợi validation hoàn tất rồi mới gửi request (không dùng setTimeout mù)
        const waitForValidation = () => {
            if (!btnLookup.disabled) {
                performLookup(domainParam, false);
                return;
            }
            // Nếu button chưa enabled → theo dõi thay đổi disabled attribute
            const observer = new MutationObserver(() => {
                if (!btnLookup.disabled) {
                    observer.disconnect();
                    performLookup(domainParam, false);
                }
            });
            observer.observe(btnLookup, { attributes: true, attributeFilter: ["disabled"] });
            // Safety timeout: nếu sau 2s vẫn chưa valid → bỏ qua
            setTimeout(() => observer.disconnect(), 2000);
        };
        waitForValidation();
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
        if (currentAbortController) {
            currentAbortController.abort();
        }
        currentAbortController = new AbortController();
        const signal = currentAbortController.signal;

        currentDomain = domain;
        isProcessing = true;

        // Reset UI
        showElements("none", resultCard, errorCard, shareCard, rawCard);
        setDisplay(cacheNotice, "none");

        // Loading state
        toggleLoading(btnLookup, lookupIcon, lookupLoading, true);

        // Update URL
        const newURL = `${window.location.pathname}?domain=${encodeURIComponent(domain)}`;
        if (window.location.search !== `?domain=${encodeURIComponent(domain)}`) {
            window.history.pushState({ domain }, "", newURL);
        }

        try {
            const res = await fetch(
                `${API_BASE_URL}/whois/lookup?domain=${encodeURIComponent(domain)}&bypassCache=${bypass}`,
                { signal }
            );
            const json = await res.json();

            if (!json.success || !json.data) {
                showError(json.message || "Tra cứu WHOIS thất bại. Vui lòng thử lại sau.");
                return;
            }

            // Kiểm tra tên miền chưa được đăng ký
            const statuses = json.data.status || [];
            const isAvailable = statuses.some(s => s.toLowerCase() === "available");
            if (isAvailable) {
                showAvailable(json.data.domain || domain, json.meta);
                return;
            }

            displayResult(json.data, json.meta);
        } catch (err) {
            if (err.name === 'AbortError') {
                console.log("WHOIS request aborted");
                return; // Thoát âm thầm nếu bị hủy
            }
            console.error("WHOIS fetch error:", err);
            showError("Không thể kết nối đến máy chủ. Vui lòng kiểm tra kết nối và thử lại.");
        } finally {
            isProcessing = false;
            toggleLoading(btnLookup, lookupIcon, lookupLoading, false);
        }
    }

    // ============================================
    //  SHOW ERROR
    // ============================================
    function showError(msg) {
        showElements("none", resultCard, shareCard);
        errorMessage.textContent = msg;
        setDisplay(errorCard, "block");
    }

    // ============================================
    //  SHOW AVAILABLE (Domain not registered)
    // ============================================
    function showAvailable(domain, meta) {
        showElements("none", resultCard, shareCard);

        // Reset title
        renderSuccessHeader(resultTitle, `Kết quả tra cứu: <span class="">"${escapeHTML(domain)}"</span>`);
        
        // Cache Notice
        if (meta && meta.fetched_at) {
            const timeStr = new Date(meta.fetched_at).toLocaleString("vi-VN");
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

        // Ẩn layout chứa 2 cột thông tin đăng ký / vòng đời
        if (whoisLayout) whoisLayout.classList.add("d-none");
        
        // Hiển thị thông báo "chưa đăng ký" kèm nút Mua full-width ở ngoài
        availableMsg.innerHTML = `
            <div class="message-card message-card--info">
                <h4 class="message-card__title">
                    <i class="fa-regular fa-flag"></i>
                    Tên miền chưa được đăng ký
                </h4>
                <p class="message-card__message">
                    Tên miền <strong>${escapeHTML(domain)}</strong> hiện chưa có người sở hữu. Bạn có thể đăng ký ngay để sở hữu tên miền này.
                </p>
                <div class="mt-4">
                    <button id="btnBuyDomain" class="btn btn-action btn-sm">
                        <i class="fa-solid fa-cart-shopping mr-1"></i> Mua tên miền này
                    </button>
                </div>
            </div>
        `;
        setDisplay(availableMsg, "block");
        
        // Gán sự kiện cho nút Mua
        const btnBuy = document.getElementById("btnBuyDomain");
        if (btnBuy) {
            btnBuy.onclick = () => {
                const affUrl = "https://tino.vn/ten-mien?php=2925";
                const cartUrl = `https://tino.vn/cart/domain?sld=${encodeURIComponent(domain)}`;
                
                // Bước 1: Mở tab mới truy cập link Affiliate để set cookie
                const win = window.open(affUrl, "_blank");
                
                // Bước 2: Sau 1 giây, "lái" cái tab đó sang trang giỏ hàng
                if (win) {
                    setTimeout(() => {
                        try {
                            win.location.href = cartUrl;
                        } catch (e) {
                            // Phòng trường hợp trình duyệt chặn script can thiệp tab ngoài domain
                            console.error("Redirect failed:", e);
                        }
                    }, 1000);
                }
            };
        }
        
        // Ẩn các phần không cần thiết
        setDisplay(rawCard, "none");

        setDisplay(resultCard, "block");
        resultCard.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // ============================================
    //  DISPLAY RESULT
    // ============================================
    function displayResult(data, meta) {

        // Ẩn bảng message trống, hiện lại layout 2 cột
        setDisplay(availableMsg, "none");
        if (whoisLayout) whoisLayout.classList.remove("d-none");

        // Cache Notice
        if (meta && meta.fetched_at) {
            const timeStr = new Date(meta.fetched_at).toLocaleString("vi-VN");
            const spanEl = cacheNotice.querySelector("span");
            if (spanEl) {
                if (meta.cached) {
                    spanEl.innerHTML = `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b id="cacheTime">${timeStr}</b>`;
                } else {
                    spanEl.innerHTML = `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b id="cacheTime">${timeStr}</b>`;
                }
            }
            setDisplay(cacheNotice, "flex");
        }

        // Result title
        renderSuccessHeader(resultTitle, `Thông tin WHOIS: <span class="text-success">"${escapeHTML(data.domain || currentDomain)}"</span>`);

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
        let registrantDisplay = data.registrant || "";
        if (!registrantDisplay || registrantDisplay.trim() === "" || registrantDisplay.trim() === "-") {
            registrantDisplay = "Domain Admin";
        }

        const fields = [
            { icon: "fa-globe", label: "Tên miền", value: data.domain || "-" },
            { icon: "fa-building", label: "Nhà đăng ký", value: data.registrar || "-" },
            // Chỉ hiển thị Chủ sở hữu cho tên miền Việt Nam
            ...(data.is_vn_domain ? [{ icon: "fa-user", label: "Chủ sở hữu", value: registrantDisplay }] : []),
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

            // Phân loại màu theo mức độ nghiêm trọng
            const lcCode = code.toLowerCase();
            const isOk = ["ok", "active"].includes(lcCode) || lcCode.includes("prohibited");
            const isDanger = (lcCode.includes("delete") && !lcCode.includes("prohibited")) || lcCode.includes("redemption");
            const isWarn = lcCode.includes("hold") || lcCode.includes("pending") || lcCode.includes("inactive");
            const colorCls = isOk ? "text-success" : isDanger ? "text-error" : isWarn ? "text-warning" : "text-secondary";

            return `<span class="${colorCls}">${escapeHTML(code)}${icannLink}</span>`;
        }).join("");
    }


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

        // "Còn X ngày" badge — dùng badge.css component
        let daysBadgeHtml = "";
        if (diffDays > 90) {
            daysBadgeHtml = `<span class="badge badge-success"><i class="fa-solid fa-circle-check mr-1"></i> Còn ${diffDays} ngày</span>`;
        } else if (diffDays > 30) {
            daysBadgeHtml = `<span class="badge badge-warning"><i class="fa-solid fa-triangle-exclamation mr-1"></i> Còn ${diffDays} ngày</span>`;
        } else if (diffDays > 0) {
            daysBadgeHtml = `<span class="badge badge-error"><i class="fa-solid fa-fire mr-1"></i> Còn ${diffDays} ngày — Gia hạn ngay!</span>`;
        } else {
            const expiredDays = Math.abs(diffDays);
            daysBadgeHtml = `<span class="badge badge-error"><i class="fa-solid fa-circle-xmark mr-1"></i> Đã hết hạn ${expiredDays} ngày trước</span>`;
        }

        // Build timeline steps
        // Step 0: Ngày đăng ký (nếu có)
        const registeredItems = [];
        if (data.registered_on) {
            registeredItems.push(renderTimelineItem({
                icon: "fa-circle-plus",
                iconClass: "whois__timeline-icon--done",
                labelClass: "badge badge-success",
                date: formatDateTime(data.registered_on),
                label: "Đăng ký",
                desc: "Tên miền được đăng ký thành công.",
                state: "done",
            }));
        }

        // Nếu chưa hết hạn → thêm step "Đang hoạt động"
        if (diffDays > 0) {
            registeredItems.push(renderTimelineItem({
                icon: "fa-location-dot",
                iconClass: "whois__timeline-icon--current",
                labelClass: "badge badge-warning",
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

            // Tính isCurrent: step này là step mà "now" đang nằm trong phạm vi
            const nextStep = steps[idx + 1];
            const nextDate = nextStep ? new Date(expiryDate) : null;
            if (nextDate) nextDate.setDate(nextDate.getDate() + nextStep.days);
            const isCurrent = isPast && (!nextDate || now <= nextDate);

            let iconClass, labelClass, icon;

            // Icon mặc định từ step definition
            icon = step.icon || "fa-circle";

            if (isCurrent) {
                // ĐANG Ở giai đoạn này → icon gốc + animation theo type
                if (step.type === "expiry") {
                    iconClass = "whois__timeline-icon--warning";
                    labelClass = "badge badge-warning";
                } else if (step.type === "danger") {
                    iconClass = "whois__timeline-icon--danger";
                    labelClass = "badge badge-error";
                } else {
                    // Muted (chờ thu hồi) — ngày đã qua → dấu tích trầm
                    icon = "fa-check";
                    iconClass = "whois__timeline-icon--upcoming";
                    labelClass = "badge badge-default";
                }
            } else if (isPast) {
                // Đã qua → giữ nguyên màu theo type (như Tino), không pulse
                icon = "fa-check";
                if (step.type === "expiry") {
                    // Hết hạn đã qua → vàng tĩnh
                    iconClass = "whois__timeline-icon--warning-static";
                    labelClass = "badge badge-warning";
                } else if (step.type === "danger") {
                    // Đình chỉ đã qua → đỏ tĩnh
                    iconClass = "whois__timeline-icon--danger-static";
                    labelClass = "badge badge-error";
                } else {
                    // Muted đã qua → xanh (done)
                    iconClass = "whois__timeline-icon--done";
                    labelClass = "badge badge-success";
                }
            } else {
                // Chưa đến → trầm
                iconClass = "whois__timeline-icon--upcoming";
                labelClass = "badge badge-default";
            }

            return renderTimelineItem({
                icon,
                iconClass,
                labelClass,
                date: formatDateTime(stepDate.toISOString()),
                label: step.label,
                desc: step.desc,
                state: isCurrent ? "current" : isPast ? "done" : "upcoming",
            });
        });

        // Chèn marker "Ngày hiện tại" nếu domain đã hết hạn
        let todayItem = "";
        if (diffDays <= 0) {
            const domainAgeDays = data.registered_on
                ? Math.floor((now - new Date(data.registered_on)) / (1000 * 60 * 60 * 24))
                : null;
            const ageDesc = domainAgeDays !== null
                ? `Tên miền được ${Math.floor(domainAgeDays / 365)} tuổi ${domainAgeDays % 365} ngày.`
                : "";
            todayItem = renderTimelineItem({
                icon: "fa-location-dot",
                iconClass: "whois__timeline-icon--current",
                labelClass: "badge badge-warning",
                date: formatDateTime(now.toISOString()),
                label: "Ngày hiện tại",
                desc: ageDesc,
                state: "current",
            });
        }

        // Tìm vị trí chèn marker "Ngày hiện tại" (sau step cuối cùng isPast, trước step đầu upcoming)
        let insertIdx = lifecycleItems.length;
        if (diffDays <= 0) {
            for (let i = 0; i < steps.length; i++) {
                const stepDate = new Date(expiryDate);
                stepDate.setDate(stepDate.getDate() + steps[i].days);
                if (now <= stepDate) {
                    insertIdx = i;
                    break;
                }
            }
        }

        const finalLifecycle = [
            ...lifecycleItems.slice(0, insertIdx),
            todayItem,
            ...lifecycleItems.slice(insertIdx),
        ].filter(Boolean);

        badgeContainer.innerHTML = daysBadgeHtml;
        listContainer.innerHTML = registeredItems.join("") + finalLifecycle.join("");
    }

    function renderTimelineItem({ icon, iconClass, labelClass, date, label, desc }) {
        return `
            <div class="whois__timeline-item">
                <div class="whois__timeline-icon ${iconClass}">
                    <i class="fa-solid ${icon}"></i>
                </div>
                <div class="whois__timeline-content">
                    <div class="whois__timeline-date">${escapeHTML(date)}</div>
                    <div class="whois__timeline-label"><span class="${labelClass}">${escapeHTML(label)}</span></div>
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

    // -------- Popstate: Handling browser navigation --------
    window.addEventListener("popstate", (e) => {
        const params = new URLSearchParams(window.location.search);
        const domain = params.get("domain");
        if (domain) {
            domainInput.value = domain;
            performLookup(domain, false);
        } else {
            domainInput.value = "";
            showElements("none", resultCard, errorCard, shareCard, rawCard);
        }
    });
}

document.addEventListener("DOMContentLoaded", init);
