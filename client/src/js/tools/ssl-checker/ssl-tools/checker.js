// ===================================================
//  SSL TOOLS - SSL CHECKER PAGE
// ===================================================
import {
    toggleLoading,
    setDisplay,
    showElements,
    resetUI,
    setElementsEnabled,
    showError,
    normalizeHostnameInput,
    getWhoisDomain,
    setupCopyButton,
    formatDate,
    createRealtimeDomainValidator,
    escapeHTML
} from "../../../utils/index.js";

import { API_BASE_URL } from "../../../config.js";

// ===================================================
//  CONFIGURATION & CONSTANTS
// ===================================================

const issuerLogoMap = {
    "DigiCert": "digicert.svg",
    "Let's Encrypt": "letsencrypt.svg",
    "ZeroSSL": "zerossl.svg",
    "Sectigo": "sectigo.svg",
    "GlobalSign": "globalsign.svg",
    "Amazon": "amazon.svg",
    "Cloudflare": "cloudflare.svg",
    "GoDaddy": "godaddy.svg",
};

const SSL_EXPIRY_THRESHOLDS = {
    EXPIRED: 0,
    WARNING: 30,
};

const CERT_CHAIN_CONFIG = {
    BASE_PATH: '/client/public/assets/images/tools/ssl/cert_chain/',
    LEVEL_MAP: {
        domain: 'DOMAIN',
        intermediate: 'CA',
        root: 'CA'
    },
    ICONS: {
        DOMAIN: {
            VALID: { src: 'certificate_good_server.png', alt: 'Valid Domain Certificate' },
            EXPIRED: { src: 'certificate_bad_server.png', alt: 'Expired Domain Certificate' }
        },
        CA: {
            VALID: { src: 'certificate_good_chain.png', alt: 'Valid CA Certificate' },
            EXPIRED: { src: 'certificate_bad_chain.png', alt: 'Expired CA Certificate' }
        }
    }
};

const issuerBrandCache = new Map();

const safe = (v, fallback = "N/A") => (v === null || v === undefined || v === "" ? fallback : v);

// ===================================================
//  PURE HELPER FUNCTIONS (No DOM dependency)
// ===================================================

function formatDays(n) {
    if (typeof n !== "number") return "N/A";
    if (n >= 0) return `${n} ngày`;
    return `${Math.abs(n)} ngày trước`;
}

function getBadgeStatus(trust_issues, handshake_error) {
    if (handshake_error) return "critical";
    if (!Array.isArray(trust_issues) || trust_issues.length === 0) return "valid";
    if (trust_issues.some(i => i.level === "critical")) return "critical";
    if (trust_issues.some(i => i.level === "warning")) return "warning";
    return "valid";
}

function getHostnameStatus(hostname_ok, hostname) {
    if (hostname_ok) {
        return {
            message: `Hostname (${escapeHTML(safe(hostname))}) khớp trong chứng chỉ.`,
            iconClass: "ok"
        };
    }
    return {
        message: `Hostname (${escapeHTML(safe(hostname))}) không khớp với bất kỳ tên nào trong chứng chỉ. Trình duyệt sẽ cảnh báo khi truy cập trang web này.`,
        iconClass: "false"
    };
}

function getTSLInfo(tlsVersion) {
    if (typeof tlsVersion !== "string" || !tlsVersion.trim()) return { message: "", iconClass: "unknown" };
    const version = tlsVersion.trim();
    const v = version.toUpperCase();
    let iconClass = "unknown";
    if (v === "TLS 1.3") iconClass = "good";
    else if (v === "TLS 1.2") iconClass = "ok";
    else if (v === "TLS 1.1") iconClass = "weak";
    else if (v === "TLS 1.0") iconClass = "bad";
    else if (v.startsWith("SSL")) iconClass = "insecure";
    return { message: version, iconClass };
}

function getIssuerBrand(cert_chain) {
    const issuer = (cert_chain?.[0]?.issuer || "");
    if (issuerBrandCache.has(issuer)) return issuerBrandCache.get(issuer);
    const lower = issuer.toLowerCase();
    let result = "";
    if (lower.includes("digicert")) result = "DigiCert";
    else if (lower.includes("let's encrypt") || lower.includes("lets encrypt")) result = "Let's Encrypt";
    else if (lower.includes("sectigo") || lower.includes("comodoca") || lower.includes("comodo")) result = "Sectigo";
    else if (lower.includes("globalsign")) result = "GlobalSign";
    else if (lower.includes("geotrust")) result = "GeoTrust";
    else if (lower.includes("entrust")) result = "Entrust";
    else if (lower.includes("zerossl")) result = "ZeroSSL";
    issuerBrandCache.set(issuer, result);
    return result;
}

function getIssuerLogoPath(issuerBrand) {
    if (issuerBrand && issuerLogoMap[issuerBrand]) {
        return `/client/public/assets/images/tools/ssl/ca/${issuerLogoMap[issuerBrand]}`;
    }
    return "";
}

function getExpiryInfo(valid, days_left) {
    const isValid = Boolean(valid);
    const days = Number(days_left);
    const isDaysValid = Number.isFinite(days);
    let status = "ok";
    if (!isValid || !isDaysValid || days <= SSL_EXPIRY_THRESHOLDS.EXPIRED) {
        status = "expired";
    } else if (days < SSL_EXPIRY_THRESHOLDS.WARNING) {
        status = "warning";
    }
    const config = {
        ok: { iconClass: "ok", valueClass: "text-success", label: "Chứng chỉ sẽ hết hạn sau" },
        warning: { iconClass: "warning", valueClass: "text-warning", label: "Chứng chỉ sẽ hết hạn sau" },
        expired: { iconClass: "critical", valueClass: "text-error", label: "Chứng chỉ đã hết hạn" },
    };
    const cfg = config[status];
    return {
        status,
        html: `${cfg.label} <strong class="${cfg.valueClass}">${formatDays(days)}</strong>.`,
        iconClass: cfg.iconClass,
        visible: isValid && isDaysValid && days > 0,
    };
}

function getTrustState(data) {
    const { hostname_ok, trusted, trust_issues, handshake_error } = data;
    return { 
        hostname_ok, 
        trusted, 
        hasIssue: Array.isArray(trust_issues) && trust_issues.length > 0,
        handshake_error: !!handshake_error
    };
}

function detectCase(state) {
    const { hostname_ok, trusted, hasIssue, handshake_error } = state;
    if (handshake_error) return "HANDSHAKE_FAILED";
    if (hostname_ok && trusted && !hasIssue) return "PERFECT";
    if (hostname_ok && trusted && hasIssue) return "MINOR_ISSUE";
    if (hostname_ok && !trusted) return "UNTRUSTED";
    if (!hostname_ok && !trusted) return "BROKEN";
    if (!hostname_ok && trusted) return hasIssue ? "WEIRD_WITH_ISSUE" : "WEIRD";
    return "UNKNOWN";
}

function renderTrustIssues(trust_issues) {
    if (!Array.isArray(trust_issues)) return "";
    return trust_issues.map(issue => {
        const isWarning = issue.level === "warning";
        const iconClass = isWarning ? "ssl-checker__icon--trusted-issue--warning" : "ssl-checker__icon--trusted-issue";
        const textClass = isWarning ? "text-warning" : "text-error";
        let extra = issue.code === "cert_expired" ? `<a href="https://tino.vn/chung-chi-bao-mat-ssl?php=2925" target="_blank" class="btn btn-sm btn-outline ml-2 py-0">Gia hạn</a>` : "";
        return `<tr><td class="ssl-checker__icon ${iconClass}">&nbsp;</td><td><strong class="${textClass}">${escapeHTML(issue.message || "")}${extra}</strong></td></tr>`;
    }).join("");
}

function getCertIconData(level, notAfterStr) {
    if (!level || !notAfterStr) return null;
    const levelKey = level.toLowerCase();
    const expireTime = new Date(notAfterStr).getTime();
    if (Number.isNaN(expireTime)) return null;
    const statusKey = Date.now() < expireTime ? 'VALID' : 'EXPIRED';
    const configGroup = CERT_CHAIN_CONFIG.LEVEL_MAP[levelKey];
    if (!configGroup) return null;
    const iconData = CERT_CHAIN_CONFIG.ICONS[configGroup][statusKey];
    return { src: CERT_CHAIN_CONFIG.BASE_PATH + iconData.src, alt: iconData.alt };
}

function renderCertCard(c) {
    if (!c) return "";
    const { level = "", common_name: cn = "", issuer = "", sans = [], organization = [], country = [], locality = [], province = [], not_before: nbf = null, not_after: naf = null, serial_hex: sxh = "", signature_algo: sga = "", public_key_algorithm: pka = null, public_key_bits: pkb = null, fingerprint_sha256: fp256 = null } = c;

    const sanList = (sans || []).filter(v => v).map(v => v.trim());
    const orgList = (organization || []).filter(v => v).map(v => v.trim());
    const location = [locality, province, country].flat().filter(v => typeof v === "string" && v.trim()).map(v => v.trim()).join(", ");
    const nafTime = new Date(naf).getTime();
    const now = Date.now();
    let nafStatus = "valid";
    if (now > nafTime) {
        nafStatus = "expired";
    } else if (nafTime - now < 30 * 24 * 60 * 60 * 1000) {
        nafStatus = "warning";
    }

    const pubKeyDisplay = pka ? `${escapeHTML(pka)}${pkb ? ` (${pkb}-bit)` : ""}` : null;
    const dataIcon = getCertIconData(level, naf);

    return `
        <div class="ssl-checker__cert-card d-flex gap-2">
            <div class="ssl-checker__cert-img-wrapper">
                ${dataIcon ? `<img src="${dataIcon.src}" alt="${dataIcon.alt}" loading="lazy" class="ssl-checker__cert-img" />` : ""}
            </div>
            <div class="ssl-checker__cert-content ${level.toLowerCase()} shadow-sm rounded-md d-flex flex-col gap-1">
                <div class="ssl-checker__cert-level"><h4 class="ssl-checker__cert-level-${level.toLowerCase()}">${level.charAt(0).toUpperCase()}${level.slice(1)} Certificate</h4></div>
                <div class="ssl-checker__cert-info ssl-checker__cert-common-name"><strong class="ssl-checker__cert-label">Common Name:</strong> <span class="ssl-checker__cert-value">${escapeHTML(safe(cn))}</span></div>
                ${sanList.length > 0 ? `<div class="ssl-checker__cert-info"><strong class="ssl-checker__cert-label">SANs:</strong> <span class="ssl-checker__cert-value">${sanList.map(s => escapeHTML(s)).join(", ")}</span></div>` : ""}
                ${orgList.length > 0 ? `<div class="ssl-checker__cert-info"><strong class="ssl-checker__cert-label">Organization:</strong> <span class="ssl-checker__cert-value">${orgList.map(o => escapeHTML(o)).join(", ")}</span></div>` : ""}
                ${location.length > 0 ? `<div class="ssl-checker__cert-info"><strong class="ssl-checker__cert-label">Location:</strong> <span class="ssl-checker__cert-value">${escapeHTML(location)}</span></div>` : ""}
                <div class="ssl-checker__cert-info"><strong class="ssl-checker__cert-label">Valid:</strong> <div class="ssl-checker__cert-value"><span>From ${escapeHTML(formatDate(nbf))}</span> <span>to <span class="ssl-checker__cert-date-not-after ${nafStatus} font-bold">${escapeHTML(formatDate(naf))}</span></span></div></div>
                ${pubKeyDisplay ? `<div class="ssl-checker__cert-info"><strong class="ssl-checker__cert-label">Public Key:</strong> <span class="ssl-checker__cert-value">${pubKeyDisplay}</span></div>` : ""}
                <div class="ssl-checker__cert-info"><strong class="ssl-checker__cert-label">Serial Number:</strong> <span class="ssl-checker__cert-value">${escapeHTML(sxh)}</span></div>
                <div class="ssl-checker__cert-info"><strong class="ssl-checker__cert-label">Signature Algorithm:</strong> <span class="ssl-checker__cert-value">${escapeHTML(sga)}</span></div>
                ${fp256 ? `<div class="ssl-checker__cert-info"><strong class="ssl-checker__cert-label">SHA-256:</strong> <span class="ssl-checker__cert-value font-mono break-all">${escapeHTML(fp256)}</span></div>` : ""}
                <div class="ssl-checker__cert-info ssl-checker__cert-issuer"><strong class="ssl-checker__cert-label">Issuer:</strong> <span class="ssl-checker__cert-value">${escapeHTML(issuer)}</span></div>
            </div>
        </div>`;
}

// ===================================================
//  MODULE EXPORT INIT
// ===================================================

export function init() {
    const formChecker = document.getElementById("formChecker");
    if (!formChecker) return;

    const inputChecker = document.getElementById("inputChecker");
    const btnSubmitChecker = document.getElementById("btnSubmitChecker");
    const iconCheckerArrow = document.getElementById("iconCheckerArrow");
    const iconCheckerLoading = document.getElementById("iconCheckerLoading");
    const domainValidationError = document.getElementById("domainValidationError");

    const toolResultChecker = document.getElementById("toolResultChecker");
    const resultDomainName = document.getElementById("resultDomainName");
    const resultCheckerHeader = document.getElementById("resultCheckerHeader");
    const btnWhoisChecker = document.getElementById("btnWhoisChecker");
    const resultCheckerContent = document.getElementById("resultCheckerContent");

    const toolError = document.getElementById("toolErrorChecker");
    const toolErrorMessage = document.getElementById("toolErrorMessage");
    const toolShareLink = document.getElementById("toolShareLink");
    const shareLinkChecker = document.getElementById("shareLinkChecker");
    const btnCopyLinkChecker = document.getElementById("btnCopyLinkChecker");
    const cacheNotice = document.getElementById("cacheNotice");
    const btnBypassCache = document.getElementById("btnBypassCache");

    let isProcessing = false;
    let isBypassCache = false;

    // --- Local UI Helpers ---

    function renderFatalError(msg) {
        btnWhoisChecker.onclick = null;
        showError(toolError, toolErrorMessage, msg, [toolResultChecker, toolShareLink]);
    }

    function renderExpiryRow(expiry) {
        if (!expiry.visible) return "";
        return `<tr><td class="ssl-checker__icon ssl-checker__icon--expiryDay-${expiry.iconClass}">&nbsp;</td><td><span class="ssl-checker__message">${expiry.html}</span></td></tr>`;
    }

    function renderCaseContent(caseType, data) {
        const { hostname, hostname_ok, valid, days_left, trusted, trust_issues, handshake_error } = data;
        const hostStatus = getHostnameStatus(hostname_ok, hostname);
        const trustStatus = getTrustedStatus(trusted);
        const expr = getExpiryInfo(valid, days_left);
        const issues = renderTrustIssues(trust_issues);

        // Tránh lặp lại thông báo hết hạn nếu đã có trong trust_issues
        const hasExpiryIssue = (trust_issues || []).some(i =>
            i.code === "cert_expired" || i.code === "expiring_soon"
        );

        const rows = [];

        if (caseType === "HANDSHAKE_FAILED") {
            if (handshake_error) {
                rows.push(`<tr><td class="ssl-checker__icon ssl-checker__icon--trusted-issue">&nbsp;</td><td><strong class="text-error">${escapeHTML(handshake_error)}</strong></td></tr>`);
            }
            return rows.join("");
        }

        const addTrustRow = () => {
            if (trustStatus.message) {
                rows.push(`<tr><td class="ssl-checker__icon ssl-checker__icon--trusted-${trustStatus.iconClass}">&nbsp;</td><td><strong class="ssl-checker__message">${trustStatus.message}</strong></td></tr>`);
            }
        };

        const addExpiryRow = () => {
            if (expr.visible && !hasExpiryIssue) {
                rows.push(renderExpiryRow(expr));
            }
        };

        const addHostRow = () => {
            if (hostStatus.message) {
                rows.push(`<tr><td class="ssl-checker__icon ssl-checker__icon--hostname${hostStatus.iconClass}">&nbsp;</td><td><strong class="ssl-checker__message">${hostStatus.message}</strong></td></tr>`);
            }
        };

        const addIssues = () => {
            if (issues) rows.push(issues);
        };

        switch (caseType) {
            case "PERFECT": 
                addTrustRow(); addExpiryRow(); addHostRow(); 
                break;
            case "MINOR_ISSUE": 
                addTrustRow(); addExpiryRow(); addHostRow(); addIssues(); 
                break;
            case "UNTRUSTED": 
                addExpiryRow(); addHostRow(); addIssues(); 
                break;
            case "BROKEN": 
                addExpiryRow(); addIssues(); 
                break;
            case "WEIRD":
            case "WEIRD_WITH_ISSUE": 
                addTrustRow(); addExpiryRow(); addHostRow(); addIssues(); 
                break;
            default: 
                rows.push(`<tr><td>Không xác định trạng thái SSL.</td></tr>`);
        }

        return rows.join("");
    }

    function getTrustedStatus(trusted) {
        return trusted ? { message: "Chứng chỉ được tin cậy bởi hầu hết trình duyệt.", iconClass: "ok" } : { message: "", iconClass: "false" };
    }

    function renderSSLResultUI(data) {
        const { hostname, ip, server_type, tls_version, cert_chain, cipher_suite, trust_issues, handshake_error } = data;
        const trstState = getTrustState(data);
        const cType = detectCase(trstState);
        const badge = getBadgeStatus(trust_issues, handshake_error);
        const tls = getTSLInfo(tls_version);
        const brnd = getIssuerBrand(cert_chain);
        const logo = getIssuerLogoPath(brnd);
        const leaf = cert_chain?.[0] || {};
        const pk = leaf.public_key_algorithm ? `${escapeHTML(leaf.public_key_algorithm)} (${leaf.public_key_bits}-bit)` : null;

        const chainHTML = (cert_chain || []).map((c, i) => {
            let card = renderCertCard(c);
            let arrow = (i < cert_chain.length - 1) ? `<div class="ssl-checker__cert-arrow"><img src="/client/public/assets/images/tools/ssl/cert_chain/arrow_down.png" loading="lazy"></div>` : "";
            return card + arrow;
        }).join("");

        const badgeIcons = {
            "valid": '<i class="fa-solid fa-circle-check"></i>',
            "warning": '<i class="fa-solid fa-triangle-exclamation"></i>',
            "critical": '<i class="fa-solid fa-circle-xmark"></i>'
        };
        const badgeIcon = badgeIcons[badge.toLowerCase()] || "";

        const tableRows = [];

        // Resolve IP Row
        if (hostname !== ip && ip) {
            tableRows.push(`<tr><td class="ssl-checker__icon ssl-checker__icon--resolve">&nbsp;</td><td><span>Tên miền <strong class="text-primary">${escapeHTML(hostname)}</strong> phân giải thành IP <strong class="text-primary">${escapeHTML(ip)}</strong>.</span></td></tr>`);
        }

        // Server Type Row
        if (server_type && server_type !== "Unknown") {
            tableRows.push(`<tr><td class="ssl-checker__icon ssl-checker__icon--server">&nbsp;</td><td><span>Server Type: <strong class="text-primary">${escapeHTML(server_type)}</strong>.</span></td></tr>`);
        }

        // Issuer Row
        if (brnd) {
            tableRows.push(`<tr><td class="ssl-checker__icon ssl-checker__icon--issuer">&nbsp;</td><td class="d-flex items-center"><span>Nhà cung cấp chứng chỉ: <strong class="font-bold">${brnd}</strong></span> ${logo ? `<img src="${logo}" width="48" height="48" class="ml-2">` : ""}</td></tr>`);
        }

        // TLS Row
        if (tls.message) {
            tableRows.push(`<tr><td class="ssl-checker__icon ssl-checker__icon--tls ${tls.iconClass}">&nbsp;</td><td><span>TLS: <strong>${tls.message}</strong> (${tls.iconClass.toUpperCase()})</span></td></tr>`);
        }

        // Cipher Row
        if (cipher_suite) {
            tableRows.push(`<tr><td class="ssl-checker__icon ssl-checker__icon--tls ok">&nbsp;</td><td><span>Cipher: <strong class="font-mono">${escapeHTML(cipher_suite)}</strong></span></td></tr>`);
        }

        // Public Key Row
        if (pk) {
            tableRows.push(`<tr><td class="ssl-checker__icon ssl-checker__icon--server">&nbsp;</td><td><span>Public Key: <strong>${pk}</strong></span></td></tr>`);
        }

        // Case Specific Rows (Trust, Expiry, Hostname, Issues, Handshake Error)
        tableRows.push(renderCaseContent(cType, data));

        resultCheckerContent.innerHTML = `
            <div class="ssl-checker__overview d-flex flex-row gap-2 items-center">
                <span class="ssl-checker__icon ssl-checker__icon--result"></span>
                <h3 class="ssl-checker__overview-title">Kết quả tổng quan:</h3>
                <span class="ssl-checker__badge ssl-checker__badge--${badge.toLowerCase()} rounded-sm">${badgeIcon}${badge.toUpperCase()}</span>
            </div>
            <table class="ssl-checker__table">
                <tbody>
                    ${tableRows.join("")}
                </tbody>
            </table>
            ${chainHTML ? `<div class="cert-chain d-flex flex-col items-center gap-2 mt-4">${chainHTML}</div>` : ""}
        `;
    }

    function displayResults(data) {
        // Chỉ hiện lỗi fatal nếu thực sự không có data hoặc có flag success=false 
        // VÀ đồng thời không có thông tin IP (nghĩa là fail ngay từ bước resolve)
        if (!data || (data.success === false && !data.ip && !data.hostname)) {
            renderFatalError(data?.message || data?.error || "Hệ thống đang bận, vui lòng thử lại sau.");
            return;
        }

        setDisplay(toolResultChecker, "block");
        resultDomainName.textContent = data.hostname;
        setDisplay(resultCheckerHeader, "flex");
        getWhoisDomain(btnWhoisChecker, data.hostname);
        showElements("block", resultCheckerContent, toolShareLink);

        const url = new URL(window.location.href);
        url.searchParams.set("hostname", data.hostname);
        shareLinkChecker.value = url.toString();

        if (cacheNotice && data.meta?.fetched_at) {
            const spanEl = cacheNotice.querySelector("span");
            const timeStr = new Date(data.meta.fetched_at).toLocaleString('vi-VN');
            spanEl.innerHTML = data.meta.cached
                ? `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b id="cacheTime">${timeStr}</b>`
                : `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b id="cacheTime">${timeStr}</b>`;
            setDisplay(cacheNotice, "flex");
        }

        renderSSLResultUI(data);
    }

    // --- Controller ---

    async function handleCheckRequest(hostname) {
        if (isProcessing) return;
        isProcessing = true;
        setElementsEnabled([inputChecker, btnSubmitChecker], false);
        resetUI([toolResultChecker, toolShareLink, toolError, cacheNotice]);
        toggleLoading(btnSubmitChecker, iconCheckerArrow, iconCheckerLoading, true);

        try {
            const resp = await fetch(`${API_BASE_URL}/ssl/check`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain: hostname, bypass_cache: isBypassCache }),
            });
            const rawData = await resp.json();
            const res = rawData?.data || rawData;
            if (rawData?.meta) res.meta = rawData.meta;
            displayResults(res);

            const url = new URL(window.location.href);
            url.searchParams.set("hostname", hostname);
            if (window.location.search !== url.search) {
                window.history.pushState({}, "", url.toString());
            }
        } catch (err) {
            showError(toolError, toolErrorMessage, "Mạng không ổn định hoặc lỗi kết nối.", [toolShareLink, toolResultChecker]);
        } finally {
            isProcessing = false;
            isBypassCache = false;
            toggleLoading(btnSubmitChecker, iconCheckerArrow, iconCheckerLoading, false);
            setElementsEnabled([inputChecker, btnSubmitChecker], true);
        }
    }

    formChecker.addEventListener("submit", (e) => {
        e.preventDefault();
        const hostname = normalizeHostnameInput(inputChecker.value.trim());
        if (hostname) {
            inputChecker.value = hostname;
            inputChecker.dispatchEvent(new Event('input'));
            handleCheckRequest(hostname);
        }
    });

    btnBypassCache?.addEventListener("click", () => {
        isBypassCache = true;
        formChecker.dispatchEvent(new Event("submit"));
    });

    inputChecker.addEventListener("input", () => {
        resetUI([toolError, toolResultChecker, toolShareLink, cacheNotice]);
    });

    // Handle initial params & back button
    const queryParams = new URLSearchParams(window.location.search);
    const initialHost = queryParams.get("hostname");
    if (initialHost) {
        inputChecker.value = initialHost;
        setTimeout(() => formChecker.dispatchEvent(new Event("submit")), 300);
    }

    window.addEventListener("popstate", () => {
        const host = new URLSearchParams(window.location.search).get("hostname");
        if (host) {
            inputChecker.value = host;
            formChecker.dispatchEvent(new Event("submit"));
        } else {
            inputChecker.value = "";
            resetUI([toolError, toolResultChecker, toolShareLink]);
        }
    });

    createRealtimeDomainValidator(inputChecker, domainValidationError, btnSubmitChecker);
    setupCopyButton(shareLinkChecker, btnCopyLinkChecker);
    inputChecker.focus();
}

document.addEventListener("DOMContentLoaded", init);
