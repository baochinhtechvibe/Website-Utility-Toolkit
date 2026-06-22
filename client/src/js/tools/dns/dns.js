// =================================//
//  DNS LOOKUP - MAIN JAVASCRIPT
//==================================//
import {
    /* dom.js */
    setDisplay,
    showElements,
    toggleLoading,
    showError,
    hide,
    setElementsEnabled,

    /* network.js */
    isIP,
    isIPv6,
    getPTRQueryName,
    normalizeRecordType,
    normalizeHostnameInput,

    /* format.js */
    truncateByWords,
    stripLegalSuffix,
    formatTTL,
    formatExpirationDate,
    escapeHTML,

    /* geo.js */
    getCountryCode,
    getCountryFlag,

    /* org.js */
    shouldKeepFullName,

    /* url.js */
    getIPInfoLink,
    getWhoisDomain,

    /* validation.js */
    createRealtimeDomainValidator,
    isValidHostname
} from "../../utils/index.js";
import { API_BASE_URL } from "../../config.js";

function init() {
    // =================================//
    //  CONFIG & GLOBAL STATE
    //==================================//
    // DOM Elements
    const form = document.getElementById("dnsLookupForm");
    const hostnameInput = document.getElementById("domain"); // changed from hostname to domain due to html ID
    const recordTypeSelect = document.getElementById("record-type");
    const btnResolve = document.getElementById("btnResolve");

    const resultsSection = document.getElementById("resultCard");
    const errorSection = document.getElementById("errorCard");
    const errorMessage = document.getElementById("errorMessage");
    // CACHE ELEMENTS
    const cacheNotice = document.getElementById("cacheNotice");
    const cacheTime = document.getElementById("cacheTime");
    const btnBypassCache = document.getElementById("btnBypassCache");
    // END CACHE
    const tableWrapper = document.getElementById("tableWrapper");
    const resultsTableHead = document.getElementById("resultsTableHead");
    const resultsTableBody = document.getElementById("resultsTableBody");
    const tableWrapperSRV = document.getElementById("tableWrapperSRV");
    const resultsTableHeadSRV = document.getElementById("resultsTableHeadSRV");
    const resultsTableBodySRV = document.getElementById("resultsTableBodySRV");
    const resultDNSSECSection = document.getElementById("resultDNSSECSection");
    const dnssecDetailTitleDNSKEY = document.getElementById("dnssecDetailTitleDNSKEY");
    const tableWrapperDNSKEY = document.getElementById("tableWrapperDNSKEY");
    const resultsTableHeadDNSKEY = document.getElementById("resultsTableHeadDNSKEY");
    const resultsTableBodyDNSKEY = document.getElementById("resultsTableBodyDNSKEY");
    const dnssecDetailTitleDS = document.getElementById("dnssecDetailTitleDS");

    const tableWrapperDS = document.getElementById("tableWrapperDS");
    const resultsTableHeadDS = document.getElementById("resultsTableHeadDS");
    const resultsTableBodyDS = document.getElementById("resultsTableBodyDS");
    const dnssecDetailTitleRRSIG = document.getElementById("dnssecDetailTitleRRSIG");
    const tableWrapperRRSIG = document.getElementById("tableWrapperRRSIG");
    const resultsTableHeadRRSIG = document.getElementById("resultsTableHeadRRSIG");
    const resultsTableBodyRRSIG = document.getElementById("resultsTableBodyRRSIG");
    const resultsTitle = document.getElementById("resultsTitle");
    const shareLinkSection = document.getElementById("shareCard");
    const shareLink = document.getElementById("shareLink");
    const btnCopyLink = document.getElementById("btnCopyLink");
    const btnWhois = document.getElementById("whoisBtn");
    const traceRootCheckbox = document.getElementById("traceRoot");
    const traceRootContainer = document.getElementById("traceRootContainer");
    const traceLogBox = document.getElementById("traceLogBox");

    // Task 11: Removed hardcoded BLACKLIST_PROVIDERS.
    // Now dynamically loaded from backend via BLACKLIST_INIT event.




    // Global flags / state

    let blacklistEventSource = null;
    let blacklistTimeout = null; // Task 4: SSE safety timeout
    let isBypassCache = false;

    // Shared element refs (Task 6: Cleanup)
    const dLookupIcon = document.getElementById("dnsLookupIcon");
    const dLookupLoading = document.getElementById("dnsLookupLoading");

    // =================================//
    //  LOW-LEVEL UTILS
    //==================================//

    // -------- Removed getDNSServerName -------
    // ======== ISP / ORG normalization ========
    function getISPDisplay(record) {
        const source = record.org || record.isp;
        if (!source) return "-";

        // Xử lý chuỗi từ Team Cymru: "SHORTNAME - Long Name" -> lấy SHORTNAME
        if (source.includes(" - ")) {
            return source.split(" - ")[0].trim();
        }

        // 1️⃣ Nếu tên chứa keyword giữ nguyên (NIC / registry)
        if (shouldKeepFullName(source)) {
            return source;
        }

        // 2️⃣ Kiểm tra có ngoặc trong tên không
        let target = source;
        const match = source.match(/\(([^)]+)\)/);
        if (match && match[1]) {
            target = match[1];
        }

        // 3️⃣ Bình thường → strip suffix
        const normalized = stripLegalSuffix(target);
        return normalized
            .split(" ")
            .map(w => w.charAt(0).toUpperCase() + w.slice(1))
            .join(" ");
    }

    // ======== DNS / Protocol helpers ========
    /**
     * Get type badge HTML
     */
    function getTypeBadge(type) {
        const safeType = escapeHTML(type);
        const safeTypeClass = String(type).toLowerCase().replace(/[^a-z0-9_-]/g, "");
        return `<span class="type-badge type-${safeTypeClass || "unknown"}">${safeType}</span>`;
    }

    /**
     * Get DNSKEY flag type (ZSK or KSK)
     */
    function getDNSKEYFlagType(flags) {
        if (flags === 256) return { type: "ZSK", name: "Zone Signing Key", class: "zsk" };
        if (flags === 257) return { type: "KSK", name: "Key Signing Key", class: "ksk" };
        return { type: "Unknown", name: `Flags: ${flags}`, class: "unknown" };
    }

    /**
     * Get algorithm name from algorithm number
     */
    function getAlgorithmName(algorithmId) {
        const algorithms = {
            1: "RSA/MD5",
            3: "DSA/SHA1",
            5: "RSA/SHA-1",
            6: "DSA-NSEC3-SHA1",
            7: "RSASHA1-NSEC3-SHA1",
            8: "RSA/SHA-256",
            10: "RSA/SHA-512",
            12: "GOST R 34.10-2001",
            13: "ECDSA Curve P-256 with SHA-256",
            14: "ECDSA Curve P-384 with SHA-384",
            15: "Ed25519",
            16: "Ed448"
        };
        return algorithms[algorithmId] || `Unknown (${algorithmId})`;
    }

    /**
     * Get digest type name
     */
    function getDigestTypeName(digestType) {
        const types = {
            1: "SHA-1",
            2: "SHA-256",
            3: "GOST R 34.11-94",
            4: "SHA-384"
        };
        return types[digestType] || `Unknown (${digestType})`;
    }

    function getDNSSECStatusClass(status) {
        switch (status) {
            case "SECURE":
                return "status-secure";
            case "INSECURE":
                return "status-insecure";
            case "BOGUS":
                return "status-bogus";
            default:
                return "status-unknown";
        }
    }

    function getDNSSECStatusLabel(status) {
        return status === "SECURE" ? "SECURE CHAIN" : (status || "UNKNOWN");
    }

    // ======== URL / Share helpers ========
    /**
     * Generate share link
     */
    function generateShareLink(hostname, type) {
        const baseUrl = window.location.origin + window.location.pathname;
        let url = `${baseUrl}?host=${encodeURIComponent(hostname)}&type=${type}`;
        if (traceRootCheckbox && traceRootCheckbox.checked) {
            url += '&traceroot=true';
        }
        return url;
    }

    /**
     * Đổi link URL
     */

    function updateURL(host, type) {
        const params = new URLSearchParams({
            host,
            type
        });
        if (traceRootCheckbox && traceRootCheckbox.checked) {
            params.append('traceroot', 'true');
        }

        const newSearch = `?${params.toString()}`;
        const newURL = `${window.location.pathname}${newSearch}`;
        if (window.location.search !== newSearch) {
            window.history.replaceState({}, '', newURL);
        }
    }

    // =================================//
    //  API / DATA ACCESS LAYER
    //==================================//
    /**
     * Perform DNS lookup
     */
    async function performDNSLookup(hostname, type, bypassCache = false, traceRoot = false) {
        showElements("none", resultsSection, shareLinkSection, errorSection);
        if (traceLogBox) setDisplay(traceLogBox, "none");
        if (cacheNotice) cacheNotice.classList.add("d-none");
        try {
            const response = await fetch(`${API_BASE_URL}/dns/lookup`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    hostname,
                    type,
                    bypassCache,
                    traceRoot,
                }),
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || "DNS lookup failed");
            }

            return data;
        } catch (error) {
            console.error("DNS Lookup Error:", error);
            throw error;
        }
    }

    async function resolveIPv4(hostname) {
        const res = await performDNSLookup(hostname, "A", false);
        const records = res.data.records || [];
        const a = records.find(r => r.type === "A");
        return a ? a.address : null;
    }

    // =================================//
    //  BLACKLIST DOMAIN LOGIC
    //==================================//
    function cleanupBlacklistStream() {
        if (blacklistTimeout) {
            clearTimeout(blacklistTimeout);
            blacklistTimeout = null;
        }
        if (blacklistEventSource) {
            blacklistEventSource.close();
            blacklistEventSource = null;
        }
    }

    function performBlacklistStream(ip) {
        return new Promise((resolve, reject) => {
            setDisplay(errorSection, "none");
            resultsTableBody.innerHTML = "";

            const rowMap = {};

            // Header
            resultsTableHead.innerHTML = `
            <tr>
                <th class= "results-table__cell results-table__cell--rbl-provider">RBL PROVIDER</th>
                <th class= "results-table__cell results-table__cell--rbl-type">CATEGORY</th>
                <th class= "results-table__cell results-table__cell--rbl-level">LEVEL</th>
                <th class= "results-table__cell results-table__cell--rbl-status">STATUS</th>
                <th class= "results-table__cell results-table__cell--rbl-response-time">RESPONSE TIME</th>
            </tr>
        `;

            // Gắn class riêng để áp dụng layout cột chuyên biệt cho Blacklist
            resultsTableBody.parentElement.classList.add('results-table--blacklist');

            // Title ban đầu
            resultsTitle.innerHTML = `
            <i class="fas fa-shield-alt"></i>
            Blacklist Check: ${escapeHTML(ip)}
            <span class="ml-2 badge badge-default">Connecting...</span>
        `;

            // ✅ 2. SSE STREAM
            cleanupBlacklistStream();

        blacklistEventSource = new EventSource(
            `${API_BASE_URL}/dns/blacklist-stream/${encodeURIComponent(ip)}`
        );

        blacklistEventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);

            // Bỏ qua heartbeat keep-alive từ backend
            if (data.type === "HEARTBEAT") return;

            // Task 11: Dynamic Skeleton rendering from Backend list
            if (data.type === "BLACKLIST_INIT") {
                resultsTableBody.innerHTML = "";
                (data.providers || []).forEach(rbl => {
                    const tr = document.createElement("tr");
                    tr.dataset.provider = rbl.host;
                    tr.innerHTML = `
                    <td class= "results-table__cell results-table__cell--rbl-provider" data-label="PROVIDER" title="${escapeHTML(rbl.name || rbl.host)}">${escapeHTML(rbl.host)}</td>
                    <td class= "results-table__cell results-table__cell--rbl-type" data-label="CATEGORY"><span class="type-badge type-blacklist">${escapeHTML(rbl.category || "RBL")}</span></td>
                    <td class= "results-table__cell results-table__cell--rbl-level" data-label="LEVEL"><span class="level-badge level-${escapeHTML(rbl.level.toLowerCase())}">${escapeHTML(rbl.level)}</span></td>
                    <td class="results-table__cell results-table__cell--rbl-status status-cell" data-label="STATUS">
                        <i class="fas fa-spinner fa-spin"></i>
                        <span>Đang kiểm tra...</span>
                    </td>
                    <td class="results-table__cell results-table__cell--rbl-response-time response-time-cell" data-label="RESPONSE TIME">-</td>
                `;
                    rowMap[rbl.host] = tr;
                    resultsTableBody.appendChild(tr);
                });

                // Update title with total count (0/Total)
                resultsTitle.innerHTML = `
                <i class="fas fa-shield-alt"></i>
                Blacklist Check: ${escapeHTML(data.ip)}
                <span class="ml-2 badge badge-default">0/${data.total} blacklist</span>
            `;

                // Start safety timeout (Task 4)
                if (blacklistTimeout) clearTimeout(blacklistTimeout);
                blacklistTimeout = setTimeout(() => {
                    if (blacklistEventSource) {
                        console.warn("SSE Timeout: Closing connection after 60s");
                        blacklistEventSource.close();
                        blacklistEventSource = null;
                        
                        // Đánh dấu các mục chưa xong là TIMEOUT
                        const pendingCells = resultsTableBody.querySelectorAll(".status-cell");
                        pendingCells.forEach(cell => {
                            if (cell.textContent.includes("Đang kiểm tra")) {
                                cell.innerHTML = renderBlacklistStatus("TIMEOUT");
                            }
                        });
                        
                        // Cập nhật title thành trạng thái hoàn tất (partial) do timeout
                        resultsTitle.innerHTML = `
                        <i class="fas fa-shield-alt"></i>
                        Blacklist Check:
                        <div class="results__section-title-rbl-realtime">
                            ${escapeHTML(data.ip || ip)}
                            <span class="ml-1 badge badge-warning">Gián đoạn (Quá 60s)</span>
                        </div>
                    `;
                        resolve(); // Báo hoàn thành cho luồng chính
                    }
                }, 60000); // 60s is plenty for parallel RBL checks

                return;
            }

            if (data.type === "BLACKLIST_SUMMARY") {
                if (blacklistTimeout) {
                    clearTimeout(blacklistTimeout);
                    blacklistTimeout = null;
                }
                resultsTitle.innerHTML = `
            <i class="fas fa-shield-alt"></i>
            Blacklist Check:
            <div class="results__section-title-rbl-realtime">
                ${escapeHTML(data.ip)}
                <span class="ml-1 badge ${data.listed > 0 ? "badge-error" : "badge-success"}">
                    ${data.listed}/${data.total} blacklist
                </span>
            </div>
        `;
                // Đóng stream sau khi hoàn thành phòng EventSource auto-reconnect
                if (blacklistEventSource) {
                    blacklistEventSource.close();
                    blacklistEventSource = null;
                }

                resolve(); // Báo hoàn thành cho luồng chính
                return;
            }

            if (data.type === "BLACKLIST") {
                const row = rowMap[data.provider];
                if (!row) return;

                const statusCell = row.querySelector(".status-cell");
                statusCell.innerHTML = renderBlacklistStatus(data.status);
                row.querySelector(".response-time-cell").textContent = formatResponseTime(data.responseTimeMs);
            }
        };

        blacklistEventSource.onerror = () => {
            if (blacklistTimeout) {
                clearTimeout(blacklistTimeout);
                blacklistTimeout = null;
            }

            // Kiểm tra xem đã nhận được data nào chưa
            const hasReceivedData = resultsTableBody && resultsTableBody.querySelectorAll("tr").length > 0;

            if (blacklistEventSource) {
                blacklistEventSource.close();
                blacklistEventSource = null;
            }

            if (hasReceivedData) {
                // Đã có data trên bảng → giữ nguyên, chỉ đánh dấu các mục chưa xong là TIMEOUT
                const pendingCells = resultsTableBody.querySelectorAll(".status-cell");
                pendingCells.forEach(cell => {
                    if (cell.textContent.includes("Đang kiểm tra")) {
                        cell.innerHTML = renderBlacklistStatus("TIMEOUT");
                    }
                });
                // Cập nhật title thành trạng thái hoàn tất (partial)
                resultsTitle.innerHTML = `
                <i class="fas fa-shield-alt"></i>
                Blacklist Check:
                <div class="results__section-title-rbl-realtime">
                    ${escapeHTML(ip)}
                    <span class="ml-1 badge badge-warning">Kết nối bị gián đoạn</span>
                </div>
            `;
                resolve();
            } else {
                // Chưa có data gì → lỗi kết nối thực sự
                const msg = (ip === "127.0.0.1" || ip === "localhost")
                    ? "Địa chỉ IP Local/Loopback không thể kiểm tra Blacklist. Vui lòng dùng IP Public."
                    : "Không thể kết nối với dịch vụ kiểm tra Blacklist hoặc IP không hợp lệ.";

                // Ở đây chúng ta gọi reject để throw lỗi ra ngoài, catch block bên ngoài sẽ hiển thị lỗi
                reject(new Error(msg));
            }
        };
    });
}

    function formatResponseTime(responseTimeMs) {
        return Number.isFinite(responseTimeMs) ? `${responseTimeMs} ms` : "-";
    }

    function renderBlacklistStatus(status) {
        switch (status) {
            case "OK":
                return `
                <i class="fa-solid fa-circle-check icon-ok mr-1"></i>
                <span class="status status--ok">
                    OK
                </span>
            `;

            case "LISTED":
                return `
                <i class="fa-solid fa-circle-xmark icon-listed mr-1"></i>
                <span class="status status--listed">
                    BỊ LIỆT KÊ
                </span>
            `;

            case "TIMEOUT":
                return `
                <i class="fa-solid fa-circle-exclamation icon-timeout mr-1"></i>
                <span class="status status--timeout">
                    TIMEOUT
                </span>
            `;

            case "ERROR":
                return `
                <i class="fa-solid fa-circle-exclamation icon-timeout mr-1"></i>
                <span class="status status--timeout">
                    LỖI
                </span>
            `;

            case "CHECKING":
                return `
              <span class="status status--checking">
                <i class="fa-solid fa-spinner fa-spin mr-1"></i> Đang kiểm tra...
              </span>
            `;

            default:
                return `<span>-</span>`;
        }
    }

    // =================================================//
    //  UI STATE CONTROL (LOADING / ERROR / FEEDBACK)
    // =================================================//
    function resetUI() {
        showElements(
            "none",
            resultsTitle,
            btnWhois,
            errorSection,
            tableWrapper,
            tableWrapperSRV,
            resultDNSSECSection,
            shareLinkSection
        );

        // Ẩn bảng lỗi validation bằng đúng cơ chế d-none (để validator realtime vẫn hoạt động đúng)
        const validationError = document.getElementById('domainValidationError');
        if (validationError) validationError.classList.add('d-none');
        hostnameInput.classList.remove('is-invalid');

        if (cacheNotice) setDisplay(cacheNotice, "none"); // Reset cache text
        setDisplay(resultsSection, "none"); // Hide main card

        tableWrapper.classList.remove("table-wrapper--blacklist");

        // Xoá class layout Blacklist để không ảnh hưởng các bảng DNS thông thường
        resultsTableBody.parentElement.classList.remove('results-table--blacklist');
    }


    function removeDNone(el) {
        if (!el) return;
        el.classList.remove("d-none");
    }

    function showCopyFeedback(icon, type) {
        const messages = {
            "public-key": "Public key copied",
            "digest": "Digest copied",
            "default": "Copied to clipboard"
        };

        const message = messages[type] || messages.default;

        // Đổi icon
        icon.classList.remove("fa-copy");
        icon.classList.add("fa-check", "copied");


        setTimeout(() => {
            icon.classList.remove("fa-check", "copied");
            icon.classList.add("fa-copy");
        }, 1500);
    }



    // =================================//
    //  UI RENDERING – ATOMIC
    //==================================//
    /**
     * Create table row - with safety checks
     */
    function createTableRow(record, domain) {
        const row = document.createElement("tr");

        // ✅ SAFETY CHECK: Skip if record.type is undefined or not a string
        if (!record || !record.type || typeof record.type !== 'string') {
            console.warn("Invalid record type:", record);
            return row; // Return empty row
        }

        let answer = "";
        let ispOrg = "";

        switch (record.type) {
            case "A":
                // Flag và IP nằm trong cột ANSWER
                const countryA = record.country || "";
                const countryCodeA = record.countryCode || getCountryCode(countryA);
                const flagA = countryCodeA ? getCountryFlag(countryCodeA) : "";

                answer = `
                <div class="answer-cell d-flex flex-row items-center gap-1">
                    <span>${escapeHTML(record.address)}</span>
                    ${flagA}
                </div>
            `;

                // ISP/ORG có link
                if (record.isp || record.org) {
                    const fullText = escapeHTML(record.org || record.isp || "-");
                    const displayText = escapeHTML(getISPDisplay(record));
                    ispOrg = `
                    <a href="${getIPInfoLink(record.address)}"
                       target="_blank"
                       title="${fullText}"
                       class="isp-link d-inline-flex items-center gap-1 btn btn-success">
                        <span class="isp-link__text">${displayText}</span>
                        <i class="fas fa-external-link-alt isp-link__icon"></i>
                    </a>
                `;
                }
                break;

            case "AAAA":
                const countryAAAA = record.country || "";
                const countryCodeAAAA = record.countryCode || getCountryCode(countryAAAA);
                const flagAAAA = countryCodeAAAA ? getCountryFlag(countryCodeAAAA) : "";

                answer = `
                <div class="answer-cell d-flex flex-row items-center gap-1">
                    <span>${escapeHTML(record.address)}</span>
                    ${flagAAAA}
                </div>
            `;

                if (record.isp || record.org) {
                    const fullText = escapeHTML(record.org || record.isp || "-");
                    const displayText = escapeHTML(getISPDisplay(record));
                    ispOrg = `
                    <a href="${getIPInfoLink(record.address)}"
                        target="_blank"
                        title="${fullText}"
                        class="isp-link d-inline-flex items-center gap-1 btn btn-success">
                        <span class="isp-link__text">${displayText}</span>
                        <i class="fas fa-external-link-alt isp-link__icon"></i>
                    </a>
                `;
                }
                break;

            case "NS":
                answer = escapeHTML(record.nameserver);
                break;

            case "MX":
                answer = `${escapeHTML(record.exchange)} (Priority: ${escapeHTML(record.priority)})`;
                break;

            case "CNAME":
                answer = escapeHTML(record.value);
                break;

            case "TXT":
                answer = escapeHTML(record.value);
                break;

            case "PTR":
                const countryPTR = record.country || "";
                const countryCodePTR = record.countryCode || getCountryCode(countryPTR);
                const flagPTR = countryCodePTR ? getCountryFlag(countryCodePTR) : "";

                answer = `
                <div class="answer-cell d-inline-flex items-center gap-1">
                    <span>${escapeHTML(record.value)}</span>
                    ${flagPTR}
                </div>
            `;

                if ((record.isp || record.org) && domain) {
                    const displayText = escapeHTML(getISPDisplay(record));
                    ispOrg = `
                    <a href="${getIPInfoLink(domain)}"
                        target="_blank"
                        class="isp-link d-inline-flex items-center gap-1 btn btn-success">
                        <span class="isp-link__text">${displayText}</span>
                        <i class="fas fa-external-link-alt isp-link__icon"></i>
                    </a>
                `;
                }
                break;

            case "DNSSEC":
                answer = `<span class="status-badge ${record.enabled ? "status-active" : "status-inactive"}">${escapeHTML(record.status)}</span>`;
                break;

            default:
                answer = escapeHTML(JSON.stringify(record));
        }

        const isIPInput = isIP(domain) || isIPv6(domain);

        // Ưu tiên hiển thị record.domain nếu có (cho CNAME case)
        let domainDisplay = domain;
        if (record.domain) {
            domainDisplay = record.domain;
        } else if (record.type === "PTR" || isIPInput) {
            domainDisplay = getPTRQueryName(domain);
        }

        const isTxt = record.type === "TXT" ? " wrap-text" : "";

        row.innerHTML = `
        <td class="results-table__cell results-table__cell--domain" data-label="DOMAIN">
            <span class="results-table__value results-table__value--domain">${escapeHTML(domainDisplay)}</span>
        </td>
        <td class="results-table__cell results-table__cell--type" data-label="TYPE">
            ${getTypeBadge(record.type)}
        </td>
        <td class="results-table__cell results-table__cell--ttl" data-label="TTL">${formatTTL(record.ttl)}</td>
        <td class="results-table__cell results-table__cell--answer${isTxt}" data-label="ANSWER">
            <span class="results-table__value results-table__value--answer">
                ${answer}
            </span>
        </td>
        <td class="results-table__cell results-table__cell--isp" data-label="ISP / ORG">
            ${ispOrg || "-"}
        </td>
    `;

        return row;
    }

    // =================================//
    //  UI RENDERING – PAGE
    //==================================//
    /**
     * Create table row for SRV records
     */
    function createTableSRVRow(record, domain) {
        const tr = document.createElement("tr");

        const targetHTML = escapeHTML(record.target || "-");
        const portHTML = escapeHTML(record.port || "0");
        const priorityHTML = escapeHTML(record.priority || "0");
        const weightHTML = escapeHTML(record.weight || "0");
        const ttlHTML = escapeHTML(record.ttl ? String(record.ttl) : "-");

        tr.innerHTML = `
        <td class="results-table__cell results-table__cell--domain" data-label="DOMAIN">
            <span class="results-table__value results-table__value--domain">${escapeHTML(domain)}</span>
        </td>
        <td class="results-table__cell results-table__cell--target" data-label="TARGET">
            <span class="results-table__value">${targetHTML}</span>
        </td>
        <td class="results-table__cell results-table__cell--port" data-label="PORT">
            <span class="results-table__value">${portHTML}</span>
        </td>
        <td class="results-table__cell results-table__cell--priority" data-label="PRIORITY">
            <span class="results-table__value">${priorityHTML}</span>
        </td>
        <td class="results-table__cell results-table__cell--weight" data-label="WEIGHT">
            <span class="results-table__value">${weightHTML}</span>
        </td>
        <td class="results-table__cell results-table__cell--ttl" data-label="TTL">
            <span class="results-table__value">${ttlHTML}</span>
        </td>
        `;
        return tr;
    }

    /**
     * Display results in table
     */
    function displayResults(data) {
        // 🔴 CHẶN LỖI PTR / INVALID / NOT FOUND
        if (!data || data.success === false) {
            // Nếu là lỗi nhưng có Trace Logs (nhật ký hành trình) thì vẫn phải hiện kết quả lên để xem logs
            const hasTraceLogs = data.data && data.data.traceLogs && data.data.traceLogs.length > 0;

            if (hasTraceLogs) {
                setDisplay(resultsSection, "block");
                showElements("block", resultsTitle);
                // Ẩn share card khi lỗi
                showError(errorSection, errorMessage, data?.message || "Không tìm thấy bản ghi DNS!", [shareLinkSection]);
                // Vẫn tiếp tục chạy xuống dưới để render nốt cái Trace Logs
            } else {
                showError(errorSection, errorMessage, data?.message || "Không tìm thấy bản ghi DNS cho truy vấn này!", [
                    shareLinkSection, resultsSection
                ]);
                return;
            }
        } else {
            // Nếu thành công, ẩn bảng lỗi cũ đi và hiện share card
            setDisplay(errorSection, "none");
            setDisplay(shareLinkSection, "block");
        }

        // LUÔN show section khi có kết quả thành công (hoặc lỗi có trace)
        setDisplay(resultsSection, "block");
        showElements("block", resultsTitle);

        const { query, records, nameservers } = data.data;
        const hostname = query.hostname;
        const type = query.type;
        if (cacheNotice && data.meta) {
            setDisplay(cacheNotice, "flex");
            const timeStr = new Date(data.meta.fetched_at).toLocaleString('vi-VN');
            const spanEl = cacheNotice.querySelector("span");
            if (data.meta.cached) {
                spanEl.innerHTML = `<i class="fa-solid fa-clock"></i> Kết quả này được xuất từ bộ nhớ tạm phục hồi lúc <b id="cacheTime">${timeStr}</b>`;
            } else {
                spanEl.innerHTML = `<i class="fa-solid fa-bolt"></i> Kết quả tra cứu mới nhất lúc <b id="cacheTime">${timeStr}</b>`;
            }
        } else if (cacheNotice) {
            setDisplay(cacheNotice, "none");
        }

        // TRACE LOGS
        if (traceLogBox && data.data && data.data.traceLogs && data.data.traceLogs.length > 0) {
            let traceHtml = `<div class="trace-log__title">
            <i class="fa-solid fa-route"></i> DNS Trace từ Root Server:
        </div>`;

            data.data.traceLogs.forEach(step => {
                const hasEnrichment = !!step.enrichment;
                const safeMsg = escapeHTML(step.message);
                const boldedMessage = safeMsg.replace(/(\.\.\.took \d+ ms)/g, '<b>$1</b>');

                if (hasEnrichment) {
                    const en = step.enrichment;
                    const nodeTypeClass = `node-type--${en.nodeType.toLowerCase()}`;

                    traceHtml += `
                    <div class="trace-log__item trace-log__item--expandable">
                        <div class="trace-log__header">
                            <i class="fa-solid fa-chevron-right trace-log__chevron"></i>
                            <div class="trace-log__content">${boldedMessage}</div>
                        </div>
                        <div class="trace-log__detail">
                            <div class="trace-log__detail-card">
                                <div class="detail-info__item">
                                    <span class="detail-info__label">Phân quyền</span>
                                    <span class="detail-info__value">
                                        <span class="node-type-badge ${nodeTypeClass}">${en.nodeType}</span>
                                    </span>
                                </div>
                                <div class="detail-info__item">
                                    <span class="detail-info__label">Tổ chức vận hành</span>
                                    <span class="detail-info__value">${escapeHTML(en.organization || "-")}</span>
                                </div>
                                ${en.location ? `
                                <div class="detail-info__item">
                                    <span class="detail-info__label">Vị trí</span>
                                    <span class="detail-info__value">
                                        ${en.countryCode ? `<span class="fi fi-${en.countryCode.toLowerCase()}"></span>` : ""}
                                        ${escapeHTML(en.location)}
                                    </span>
                                </div>` : ""}

                            </div>
                        </div>
                    </div>`;
                } else {
                    traceHtml += `
                    <div class="trace-log__item">
                        <div class="trace-log__header">
                            <i class="fa-solid fa-circle-info trace-log__chevron text-info"></i>
                            <div class="trace-log__content">${boldedMessage}</div>
                        </div>
                    </div>`;
                }
            });

            traceLogBox.innerHTML = traceHtml;
            setDisplay(traceLogBox, "block");

            // Gắn sự kiện toggle
            const expandableItems = traceLogBox.querySelectorAll(".trace-log__item--expandable");
            expandableItems.forEach(item => {
                item.addEventListener("click", () => {
                    item.classList.toggle("is-expanded");
                });
            });
        }

        hostnameInput.value = hostname;

        const actualRecords = records || [];

        // Determine display name
        const isIPInput = isIP(hostname) || isIPv6(hostname);
        const isSubdomainFlag = query.isSubdomain || false;
        const displayName = type === "PTR" || (type === "ALL" && isIPInput)
            ? getPTRQueryName(hostname)
            : hostname;

        // Update title
        if (type === "ALL") {
            resultsTitle.innerHTML = `
            <i class="fas fa-check-circle"></i>
            ALL lookup – "${escapeHTML(displayName)}"
        `;
        } else {
            resultsTitle.innerHTML = `
            <i class="fas fa-check-circle"></i>
            ${type} lookup – "${escapeHTML(displayName)}"
        `;
        }

        // Show WHOIS button
        if (
            !isIPInput &&
            !isSubdomainFlag &&
            type !== "PTR" &&
            type !== "BLACKLIST"
        ) {
            getWhoisDomain(btnWhois, hostname);
        } else {
            if (btnWhois) hide(btnWhois);
        }

        // Generate share link
        const link = generateShareLink(hostname, type);
        shareLink.value = link;
        shareLink.title = link;

        // Handle DNSSEC separately
        if (type === "DNSSEC") {
            resultsTableHead.innerHTML = `
            <tr>
                <th class = "results-table__cell results-table__cell--domain">DOMAIN</th>
                <th class = "results-table__cell results-table__cell--type-dnssec">TYPE</th>
                <th class = "results-table__cell results-table__cell--status-dnssec">STATUS</th>
                <th class = "results-table__cell results-table__cell--details">DETAIL</th>
            </tr>
        `;

            resultsTableBody.innerHTML = `
            <tr>
                <td class = "results-table__cell results-table__cell--domain" data-label="DOMAIN"><span class="results-table__value results-table__value--domain">${escapeHTML(hostname)}</span></td>
                <td class = "results-table__cell results-table__cell--type-dnssec" data-label="TYPE">${getTypeBadge("DNSSEC")}</td>
                <td class = "results-table__cell results-table__cell--status-dnssec" data-label="STATUS">
                    <span class="status-badge ${getDNSSECStatusClass(data.data.dnssec.status)}">
                        ${getDNSSECStatusLabel(data.data.dnssec.status)}
                    </span>
                </td>
                <td class = "results-table__cell results-table__cell--details" data-label="DETAIL">${escapeHTML(data.data.dnssec.message || "-")}</td>
            </tr>
        `;

            showElements("block", tableWrapper, shareLinkSection);
            resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
            if (data.data.dnssec.enabled) {
                displayDNSSECResults(data);
            }
            return;
        }

        // Set table headers based on type
        if (type === "SRV") {
            resultsTableHeadSRV.innerHTML = `
            <tr>
                <th class="results-table__cell results-table__cell--domain">DOMAIN</th>
                <th class="results-table__cell results-table__cell--target">TARGET</th>
                <th class="results-table__cell results-table__cell--port">PORT</th>
                <th class="results-table__cell results-table__cell--priority">PRIORITY</th>
                <th class="results-table__cell results-table__cell--weight">WEIGHT</th>
                <th class="results-table__cell results-table__cell--ttl">TTL</th>
            </tr>
        `;
        } else if (type === "PTR" || (type === "ALL" && isIPInput)) {
            resultsTableHead.innerHTML = `
            <tr>
                <th class="results-table__cell results-table__cell--ip">IP</th>
                <th class="results-table__cell results-table__cell--type">TYPE</th>
                <th class="results-table__cell results-table__cell--ttl">TTL</th>
                <th class="results-table__cell results-table__cell--answer">ANSWER</th>
                <th class="results-table__cell results-table__cell--isp">ISP / ORG</th>
            </tr>
        `;
        } else {
            resultsTableHead.innerHTML = `
            <tr>
                <th class="results-table__cell results-table__cell--domain">DOMAIN</th>
                <th class="results-table__cell results-table__cell--type">TYPE</th>
                <th class="results-table__cell results-table__cell--ttl">TTL</th>
                <th class="results-table__cell results-table__cell--answer">ANSWER</th>
                <th class="results-table__cell results-table__cell--isp">ISP / ORG</th>
            </tr>
        `;
        }

        // Clear previous results
        resultsTableBody.innerHTML = "";
        resultsTableBodySRV.innerHTML = "";

        // Check if we have actual records OR trace logs
        const hasRecords = actualRecords && actualRecords.length > 0;
        const hasTraceLogs = data.data && data.data.traceLogs && data.data.traceLogs.length > 0;

        if (!hasRecords && !hasTraceLogs) {
            // Thực sự không có gì để hiện
            showError(errorSection, errorMessage, data?.message || `Không tìm thấy bản ghi ${type} cho hostname này!`, [
                resultsSection, shareLinkSection
            ]);
        } else {
            // Có kết quả thực tế hoặc có Trace Logs
            setDisplay(resultsSection, "block");

            if (hasRecords) {
                if (type === "SRV") {
                    setDisplay(tableWrapperSRV, "block");
                } else {
                    setDisplay(tableWrapper, "block");
                }
                setDisplay(errorSection, "none"); // Có records thì ẩn lỗi đi (thành công)
                setDisplay(shareLinkSection, "block"); // Hiện share card khi thành công
            } else {
                // Trường hợp chỉ có Trace Logs nhưng không có Records (ví dụ lỗi NXDOMAIN khi trace)
                setDisplay(tableWrapper, "none");
                setDisplay(tableWrapperSRV, "none");
                setDisplay(shareLinkSection, "none"); // Ẩn share card khi lỗi

                // 🚨 QUAN TRỌNG: Nếu là lỗi (success=false) thì phải hiện message-card--error lên
                if (data.success === false) {
                    showError(errorSection, errorMessage, data?.message || "Không tìm thấy bản ghi DNS!", []);
                }
            }

            showElements("block", resultsTitle);
        }

        // Add nameservers as NS records (for ALL type, show them)
        if (nameservers && nameservers.length > 0 &&
            type !== "DNSSEC" &&
            type !== "PTR" &&
            type !== "BLACKLIST" &&
            type !== "NS") {
            nameservers.forEach((ns) => {
                const nsRecord = {
                    type: "NS",
                    nameserver: ns.nameserver || ns,
                    ttl: ns.ttl || null,
                    domain: ns.domain || hostname,
                };
                const row = createTableRow(nsRecord, hostname);
                if (row && row.children.length > 0) {
                    resultsTableBody.appendChild(row);
                }
            });
        }

        // Populate table with actual records
        actualRecords.forEach((record) => {
            // Skip invalid records
            if (!record || !record.type || typeof record.type !== 'string') {
                console.warn("Skipping invalid record:", record);
                return;
            }

            if (type === "SRV") {
                const row = createTableSRVRow(record, hostname);
                if (row && row.children.length > 0) {
                    resultsTableBodySRV.appendChild(row);
                }
            } else {
                const row = createTableRow(record, hostname);
                if (row && row.children.length > 0) {
                    resultsTableBody.appendChild(row);
                }
            }
        });

        // 6. Scroll to results or error
        if (data.success === false) {
            errorSection.scrollIntoView({ behavior: "smooth", block: "center" });
        } else {
            resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
        }
    }

    async function handleBlacklistSubmit(hostname) {
        // setResolveButtonLoading(true);

        let ip = hostname;

        if (!isIP(hostname)) {
            ip = await resolveIPv4(hostname);
            if (!ip) {
                throw new Error("Không tìm thấy bản ghi A để kiểm tra blacklist!");
            }
        }

        removeDNone(resultsTitle);
        const cleanHostname = normalizeHostnameInput(hostname);
        hostnameInput.value = cleanHostname;
        shareLink.value = generateShareLink(cleanHostname, "BLACKLIST");
        shareLink.title = shareLink.value;
        showElements("block", shareLinkSection, resultsSection, tableWrapper);
        tableWrapper.classList.add("table-wrapper--blacklist"); // Sử dụng class thay vì inline style (Rule J-07)

        await performBlacklistStream(ip);
    }

    /**
     * Display DNSSEC results
     */
    function displayDNSSECResults(data) {
        const { query, dnssec } = data.data;
        const hostname = query.hostname;
        const isIPInput = isIP(hostname) || isIPv6(hostname);
        const isSubdomainFlag = query.isSubdomain || false;
        const dnssecRecords = Array.isArray(dnssec?.records) ? dnssec.records : [];

        const recordsByType = {
            DNSKEY: [],
            DS: [],
            RRSIG: []
        };

        dnssecRecords.forEach(record => {
            if (recordsByType[record.type]) {
                recordsByType[record.type].push(record);
            }
        });

        // ===== UI chung =====
        if (!isIPInput && !isSubdomainFlag) {
            getWhoisDomain(btnWhois, hostname);
        } else {
            setDisplay(btnWhois, "none");
        }
        setDisplay(resultDNSSECSection, "block");

        resultsTitle.innerHTML = `
        <i class="fas fa-shield-alt"></i>
        DNSSEC lookup – "${escapeHTML(hostname)}"
    `;

        shareLink.value = generateShareLink(hostname, "DNSSEC");
        shareLink.title = shareLink.value;

        // ===== Reset tất cả bảng =====
        showElements("block", shareLinkSection, tableWrapper);
        showElements("none", tableWrapperDNSKEY, tableWrapperDS, tableWrapperRRSIG);

        resultsTableBodyDNSKEY.innerHTML = "";
        resultsTableBodyDS.innerHTML = "";
        resultsTableBodyRRSIG.innerHTML = "";

        if (dnssecRecords.length === 0) {
            return;
        }

        // ===== Group records =====
        const dnskeyRecords = dnssecRecords.filter(r => r.type === "DNSKEY");
        const dsRecords = dnssecRecords.filter(r => r.type === "DS");
        const rrsigRecords = dnssecRecords.filter(r => r.type === "RRSIG");

        // =========================
        // DNSKEY TABLE
        // =========================
        if (dnskeyRecords.length > 0) {
            dnssecDetailTitleDNSKEY.innerHTML = `
        <i class="fas fa-key"></i>
        DNSKEY Records (${recordsByType.DNSKEY.length})
        `
            document.getElementById('resultsTableHeadDNSKEY').innerHTML = `
            <tr class="results-table__row--head">
                <th class="results-table__cell">KEY ROLE</th>
                <th class="results-table__cell">ALGORITHM</th>
                <th class="results-table__cell">KEY TAG</th>
                <th class="results-table__cell">PROTOCOL</th>
                <th class="results-table__cell">PUBLIC KEY</th>
            </tr>
        `;
            setDisplay(tableWrapperDNSKEY, "block");

            dnskeyRecords.forEach(record => {
                const role = getDNSKEYFlagType(record.flags); // KSK / ZSK

                const tr = document.createElement("tr");
                tr.innerHTML = `
                <td class="results-table__cell" data-label="KEY ROLE">
                    <span class="key-role-badge key-role-${escapeHTML(role.class)}">
                        ${escapeHTML(role.type)}
                    </span>
                </td>
                <td class="results-table__cell" data-label="ALGORITHM">
                    ${escapeHTML(getAlgorithmName(record.algorithm))}
                </td>
                <td class="results-table__cell results-table__cell--mono" data-label="KEY TAG">
                    ${escapeHTML(String(record.keyTag))}
                </td>
                <td class="results-table__cell results-table__cell--mono" data-label="PROTOCOL">
                    ${escapeHTML(String(record.protocol))}
                </td>
                <td class="results-table__cell results-table__cell--mono" data-label="PUBLIC KEY">
                    <code>
                        ${escapeHTML(record.publicKey)}
                    </code>
                    <i class="fa-solid fa-copy copy-dnssec"
                        title="Copy public key"
                        data-copy-type="public-key"
                        data-copy-value="${escapeHTML(record.publicKey)}">
                    </i>
                </td>
            `;
                resultsTableBodyDNSKEY.appendChild(tr);
            });
        }

        // =========================
        // DS TABLE
        // =========================
        if (dsRecords.length > 0) {
            dnssecDetailTitleDS.innerHTML = `
        <i class="fas fa-link"></i>
        DS Records (${recordsByType.DS.length})
        `
            document.getElementById('resultsTableHeadDS').innerHTML = `
            <tr class="results-table__row--head">
                <th class="results-table__cell">KEY TAG</th>
                <th class="results-table__cell">ALGORITHM</th>
                <th class="results-table__cell">DIGEST TYPE</th>
                <th class="results-table__cell">DIGEST</th>
            </tr>
        `;
            setDisplay(tableWrapperDS, "block");

            dsRecords.forEach(record => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                <td class="results-table__cell results-table__cell--mono" data-label="KEY TAG">
                    ${escapeHTML(String(record.keyTag))}
                </td>
                <td class="results-table__cell" data-label="ALGORITHM">
                    ${escapeHTML(getAlgorithmName(record.algorithm))}
                </td>
                <td class="results-table__cell" data-label="DIGEST TYPE">
                    ${escapeHTML(getDigestTypeName(record.digestType))}
                </td>
                <td class="results-table__cell results-table__cell--mono" data-label="DIGEST">
                    <code>
                        ${escapeHTML(record.digest)}
                    </code>
                    <i class="fa-solid fa-copy copy-dnssec"
                        title="Copy digest"
                        data-copy-type="digest"
                        data-copy-value="${escapeHTML(record.digest)}">
                    </i>
                </td>
            `;
                resultsTableBodyDS.appendChild(tr);
            });
        }

        // =========================
        // RRSIG TABLE
        // =========================
        if (rrsigRecords.length > 0) {
            dnssecDetailTitleRRSIG.innerHTML = `
        <i class="fas fa-signature"></i>
        RRSIG Records (${recordsByType.RRSIG.length})
        `
            document.getElementById('resultsTableHeadRRSIG').innerHTML = `
            <tr class="results-table__row--head">
                <th class="results-table__cell">TYPE COVERED</th>
                <th class="results-table__cell">ALGORITHM</th>
                <th class="results-table__cell">KEY TAG</th>
                <th class="results-table__cell">SIGNER NAME</th>
                <th class="results-table__cell">EXPIRATION</th>
            </tr>
        `;
            setDisplay(tableWrapperRRSIG, "block");

            rrsigRecords.forEach(record => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                <td class="results-table__cell" data-label="TYPE COVERED">
                    ${escapeHTML(record.typeCovered)}
                </td>
                <td class="results-table__cell" data-label="ALGORITHM">
                    ${escapeHTML(getAlgorithmName(record.algorithm))}
                </td>
                <td class="results-table__cell results-table__cell--mono" data-label="KEY TAG">
                    ${escapeHTML(String(record.keyTag))}
                </td>
                <td class="results-table__cell results-table__cell--mono" data-label="SIGNER'S NAME">
                    ${escapeHTML(record.signerName)}
                </td>
                <td class="results-table__cell" data-label="EXPIRATION">
                    ${formatExpirationDate(record.expiration)}
                </td>
            `;
                resultsTableBodyRRSIG.appendChild(tr);
            });
        }

        resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    // =================================//
    //  URL / STATE SYNC
    //==================================//
    /**
     * Handle URL parameters (auto-fill form)
     */
    function handleURLParams() {
        const urlParams = new URLSearchParams(window.location.search);
        const host = urlParams.get("host");
        const type = urlParams.get("type");
        const traceroot = urlParams.get("traceroot");

        if (host) {
            hostnameInput.value = host;
        }

        const matchedOption = type && [...recordTypeSelect.options].find(o => o.value === type);
        if (matchedOption) {
            recordTypeSelect.value = type;
        }

        // Cập nhật lại hiển thị của Trace Root checkbox dựa trên Type vừa set từ URL
        updateTraceVisibility();
        updateInputPlaceholder();

        if (traceroot === "true" && traceRootCheckbox) {
            traceRootCheckbox.checked = true;
        }
        updateTraceVisibility();

        // Auto submit if all params present
        if (host && type) {
            setTimeout(() => {
                form.dispatchEvent(new Event("submit"));
            }, 500);
        }
    }

    // =================================//
    //  APP LIFECYCLE
    //==================================//
    // Hook realtime domain validator (dùng chung từ utils/validation.js)
    createRealtimeDomainValidator(
        hostnameInput,
        document.getElementById('domainValidationError'),
        btnResolve
    );
    updateTraceVisibility();
    updateInputPlaceholder();
    handleURLParams();
    hostnameInput.focus();

    // Listen to history changes to re-sync
    window.addEventListener("popstate", () => {
        const urlParams = new URLSearchParams(window.location.search);
        const host = urlParams.get("host");
        const type = urlParams.get("type");
        const traceroot = urlParams.get("traceroot");

        if (host) {
            hostnameInput.value = host;
            if (type && recordTypeSelect.querySelector(`option[value="${type}"]`)) {
                recordTypeSelect.value = type;
            }
            updateTraceVisibility();
            if (traceroot === "true" && traceRootCheckbox) {
                traceRootCheckbox.checked = true;
            } else if (traceRootCheckbox) {
                traceRootCheckbox.checked = false;
            }
            updateTraceVisibility();
            form.dispatchEvent(new Event("submit"));
        } else {
            hostnameInput.value = "";
            resetUI();
        }
    });



    // =================================//
    //  EVENT BINDINGS
    //==================================//

    /**
     * Form / Input
     */
    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const rawHostname = hostnameInput.value.trim();
        const hostname = normalizeHostnameInput(rawHostname);
        hostnameInput.value = hostname;

        // 💡 Mẹo: Phát sự kiện 'input' để thằng validator realtime nó biết mà check lại giá trị mới (ví dụ 8.8.8 -> 8.8.0.8)
        hostnameInput.dispatchEvent(new Event('input'));

        // 🛑 CHẶN SỚM: Nếu hostname không hợp lệ thì dừng ngay, chưa làm gì đến UI cả
        if (!hostname || !isValidHostname(hostname)) return;

        // Sau khi đã hợp lệ mới bắt đầu xử lý UI và gửi request
        cleanupBlacklistStream();
        setElementsEnabled([hostnameInput, recordTypeSelect], false);
        resetUI();

        let type = normalizeRecordType(hostname, recordTypeSelect.value);
        updateURL(hostname, type);

        // 🔄 Use module-level cached refs for toggleLoading
        toggleLoading(btnResolve, dLookupIcon, dLookupLoading, true);

        try {
            if (type === "BLACKLIST") {
                await handleBlacklistSubmit(hostname);
                return;
            }

            const traceRoot = traceRootCheckbox ? traceRootCheckbox.checked : false;
            const result = await performDNSLookup(hostname, type, isBypassCache, traceRoot);
            isBypassCache = false; // Reset to false after use
            displayResults(result);
        } catch (error) {
            const msg = error?.message || "Không thể tra cứu DNS. Vui lòng thử lại.";
            showError(errorSection, errorMessage, msg, [shareLinkSection, resultsSection]);
        } finally {
            toggleLoading(btnResolve, dLookupIcon, dLookupLoading, false);
            setElementsEnabled([hostnameInput, recordTypeSelect], true);
        }
    });

    btnBypassCache?.addEventListener("click", () => {
        isBypassCache = true;

        // Khôi phục giá trị đang hiển thị trên URL để tránh refresh nhầm record vừa select mà chưa submit
        const urlParams = new URLSearchParams(window.location.search);
        const host = urlParams.get("host");
        const type = urlParams.get("type");

        if (host) hostnameInput.value = host;
        if (type) recordTypeSelect.value = type;

        form.dispatchEvent(new Event("submit"));
    });

    /**
     * Handle Enter key in hostname input
     */
    hostnameInput.addEventListener("keypress", (e) => {
        if (e.key === "Enter") {
            form.dispatchEvent(new Event("submit"));
        }
    });

    /**
     * Handle Input changes to reset UI automatically
     */
    hostnameInput.addEventListener("input", () => {
        // Ẩn kết quả cũ hoặc lỗi cũ ngay khi người dùng bắt đầu gõ mới
        // dùng setDisplay trực tiếp vì showElements() set inline style, không toggle class d-none
        setDisplay(errorSection, "none");
        setDisplay(resultsSection, "none");
        setDisplay(shareLinkSection, "none");
        updateTraceVisibility();
    });

    recordTypeSelect.addEventListener("change", () => {
        updateTraceVisibility();
        updateInputPlaceholder();
        // Ẩn kết quả cũ hoặc lỗi cũ ngay khi người dùng thay đổi loại bản ghi
        setDisplay(errorSection, "none");
        setDisplay(resultsSection, "none");
        setDisplay(shareLinkSection, "none");
    });

    /**
     * Update placeholder based on selected record type
     */
    function updateInputPlaceholder() {
        if (!recordTypeSelect || !hostnameInput) return;
        const type = recordTypeSelect.value;

        if (type === "SRV") {
            hostnameInput.placeholder = "Ví dụ: _sip._tcp.example.com";
        } else if (type === "PTR") {
            hostnameInput.placeholder = "Ví dụ: 8.8.8.8 hoặc example.com";
        } else {
            hostnameInput.placeholder = "Ví dụ: google.com";
        }
    }

    /**
     * Update Trace Root checkbox visibility based on record type
     */
    function updateTraceVisibility() {
        if (!recordTypeSelect || !traceRootContainer || !traceRootCheckbox) return;

        const type = recordTypeSelect.value;
        const hideTraceTypes = ["PTR", "DNSSEC", "BLACKLIST", "SRV"];
        const normalizedHost = normalizeHostnameInput(hostnameInput?.value || "");
        const isIPInput = normalizedHost && (isIP(normalizedHost) || isIPv6(normalizedHost));

        if (hideTraceTypes.includes(type) || isIPInput) {
            setDisplay(traceRootContainer, "none");
            traceRootCheckbox.checked = false;
        } else {
            setDisplay(traceRootContainer, "block");
        }
    }

    /**
    
     * Button
     */
    btnCopyLink.addEventListener("click", async () => {
        try {
            // Chọn input (không bắt buộc, nhưng UX tốt)
            shareLink.select();
            shareLink.setSelectionRange(0, 99999); // cho mobile

            // Copy vào clipboard
            await navigator.clipboard.writeText(shareLink.value);

            // Update button text tạm thời
            btnCopyLink.innerHTML = `
            <i class="fa-solid fa-check"></i>
            <span>Đã copy!</span>
        `;

            setTimeout(() => {
                btnCopyLink.innerHTML = `
                <i class="fas fa-copy"></i>
                <span>Copy</span>`;
            }, 3000);
        } catch (err) {
            console.error("Copy failed:", err);
        }
    });

    /**
     * Document-level
     */
    document.addEventListener("click", function (e) {
        const icon = e.target.closest(".copy-dnssec");
        if (!icon) return;

        const value = icon.dataset.copyValue;
        const type = icon.dataset.copyType || "value";

        navigator.clipboard.writeText(value).then(() => {
            showCopyFeedback(icon, type);
        }).catch(() => {
        });
    });

} // end init()

document.addEventListener("DOMContentLoaded", init);
