/* =======================================================
    CERT DECODER TOOL
   ======================================================= */
import {
    showError,
    setDisplay,
    setElementsEnabled,
    toggleLoading,
    escapeHTML
} from "../../../utils/index.js";

const formCertDecoder = document.getElementById("formCertDecoder");
const inputCert = document.getElementById("inputCert");
const btnCertDecoder = document.getElementById("btnCertDecoder");
const iconCertDecoder = document.getElementById("iconCertDecoder");
const iconCertLoading = document.getElementById("iconCertLoading");

const resultCardCert = document.getElementById("resultCardCert");
const resultBodyCert = document.getElementById("resultBodyCert");

const errorCardCert = document.getElementById("errorCardCert");
const errorMsgCert = document.getElementById("errorMsgCert");

// Inline Error Card
const certValidationError = document.getElementById("certValidationError");

// Config API (Hỗ trợ cả môi trường Dev bằng Live Server lẫn Production)
const API_BASE_URL = (window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost")
    ? "http://localhost:3101/api"
    : "/api";

const CERT_STORAGE_KEY = "web_utility_kit_cert_decoder_input";

/* ================================
    HELPER FUNCTIONS
=================================== */

/**
 * Chuẩn hóa dữ liệu CERT người dùng nhập
 */
function normalizeCertInput(input) {
    if (input == null || typeof input !== "string") return "";
    if (input.trim() === "") return "";

    const MAX_CERT_SIZE = 100 * 1024;
    if (input.length > MAX_CERT_SIZE) {
        throw new Error("Certificate vượt quá kích thước cho phép (100KB).");
    }

    input = input.trim()
        .replace(/\r\n/g, "\n")
        .replace(/\r/g, "\n");

    const PEM_REGEX = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
    const matches = [...input.matchAll(PEM_REGEX)];

    if (matches.length === 0) {
        if (!input.includes("-----BEGIN")) {
            throw new Error("Certificate không hợp lệ: Thiếu thẻ mở (Ví dụ: -----BEGIN CERTIFICATE-----).");
        }
        if (input.includes("PRIVATE KEY")) {
            throw new Error("Dữ liệu không hợp lệ: Đây là Private Key, không phải Certificate.");
        }
        if (input.includes("CERTIFICATE REQUEST")) {
            throw new Error("Dữ liệu không hợp lệ: Đây là Certificate Signing Request (CSR), không phải Certificate.");
        }
        if (!input.includes("-----END")) {
            throw new Error("Certificate không hợp lệ: Thiếu thẻ đóng (Ví dụ: -----END CERTIFICATE-----).");
        }
        throw new Error("Certificate không hợp lệ: Cấu trúc PEM sai định dạng hoặc bị hỏng.");
    }

    if (matches.length > 1) {
        throw new Error("Hệ thống chỉ hỗ trợ giải mã 1 Certificate mỗi lần nhập.");
    }

    const rawBase64 = matches[0][1];
    const base64Content = rawBase64.replace(/\s+/g, "");

    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64Content)) {
        throw new Error("Certificate không hợp lệ: Nội dung mã hóa bị lỗi hoặc chứa ký tự lạ không thuộc chuẩn Base64.");
    }

    if (base64Content.length % 4 !== 0) {
        throw new Error("Certificate không hợp lệ: Dữ liệu mã hóa của Certificate bị thiếu ký tự hoặc bị cắt xén.");
    }

    if (base64Content.length < 200) {
        throw new Error("Certificate không hợp lệ: Nội dung quá ngắn, có thể chứng chỉ đã bị cắt xén hoặc copy thiếu.");
    }

    const lines = [];
    for (let i = 0; i < base64Content.length; i += 64) {
        lines.push(base64Content.slice(i, i + 64));
    }

    return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----`;
}

/* =================================
    PERFORM CERT DECODER FUNCTIONS
==================================== */

const mFetch = async (url, options) => {
    try {
        const response = await fetch(url, {
            ...options,
            signal: options?.signal
        });
        
        let data = {};
        try {
            data = await response.json();
        } catch (e) {
            console.warn("Không thể parse JSON từ API:", e);
        }

        if (!response.ok) {
            return {
                success: false,
                code: response.status,
                error: data?.error || data?.message || "Lỗi máy chủ (" + response.status + ")",
            };
        }

        if (data && data.data !== undefined) return data.data;
        return data;

    } catch (err) {
        if (err.name === "AbortError") {
            return {
                success: false,
                error: "Yêu cầu đã bị hủy do timeout hoặc người dùng dừng."
            };
        }
        return {
            success: false,
            error: "Không thể kết nối đến máy chủ. Vui lòng kiểm tra mạng."
        };
    }
};

const performCertDecoder = async (certData) => {
    const url = `${API_BASE_URL}/ssl/cer/decode`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s timeout

    const body = { cert: certData };

    try {
        const result = await mFetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(body),
            signal: controller.signal
        });

        clearTimeout(timeoutId);
        return result;
    } catch (err) {
        clearTimeout(timeoutId);
        // Fallback catch (dù mFetch đã handle)
        return {
            success: false,
            error: err.message
        };
    }
};

/* ==========================
    UI RENDERING
   ========================== */


function safe(val) {
    if (val === undefined || val === null || val === "" || val === " ") return "N/A";
    return escapeHTML(val);
}

function safeArr(arr) {
    if (!Array.isArray(arr) || arr.length === 0) return "N/A";
    const joined = arr.filter(v => v).join(", ");
    return escapeHTML(joined);
}

function formatVNDate(isoString) {
    if (!isoString) return "N/A";
    const d = new Date(isoString);
    if (isNaN(d.getTime())) return escapeHTML(isoString); // fallback nếu parse lỗi
    
    const pad = (n) => n.toString().padStart(2, '0');
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`;
}

function renderCERTResult(data) {
    if (!data) return;

    const {
        common_name,
        organization,
        organizational_unit,
        country,
        state,
        locality,
        issuer_common_name,
        issuer_organization,
        valid_from,
        valid_to,
        sans,
        key_size,
        algorithm,
        signature_algorithm,
        serial_hex,
        serial_dec
    } = data;

    const addressArr = [safeArr(locality), safeArr(state), safeArr(country)].filter(v => v !== "N/A");
    const addressStr = addressArr.length > 0 ? addressArr.join(", ") : "N/A";

    const rawSerial = serial_hex || "";
    const serialClean = rawSerial.replace(/:/g, "").toLowerCase();
    const serialFormatted = rawSerial.toLowerCase();

    const html = `
        <div class="ssl-checker__result-row">
            <div class="ssl-checker__result-label">
                <i class="fa-solid fa-circle-check text-success mr-2"></i>
                Common Name:
            </div>
            <div class="ssl-checker__result-value font-bold">${safe(common_name)}</div>
        </div>

        <div class="ssl-checker__result-row">
            <div class="ssl-checker__result-label">
                <i class="fa-solid fa-circle-check text-success mr-2"></i>
                Subject Alternative Names (SANs):
            </div>
            <div class="ssl-checker__result-value">${safeArr(sans)}</div>
        </div>

        <div class="ssl-checker__result-row">
            <div class="ssl-checker__result-label">
                <i class="fa-solid fa-circle-check text-success mr-2"></i>
                Organization:
            </div>
            <div class="ssl-checker__result-value">${safeArr(organization)}</div>
        </div>

        <div class="ssl-checker__result-row">
            <div class="ssl-checker__result-label">
                <i class="fa-solid fa-circle-check text-success mr-2"></i>
                Organizational Unit:
            </div>
            <div class="ssl-checker__result-value">${safeArr(organizational_unit)}</div>
        </div>

        <div class="ssl-checker__result-row">
            <div class="ssl-checker__result-label">
                <i class="fa-solid fa-circle-check text-success mr-2"></i>
                Address:
            </div>
            <div class="ssl-checker__result-value">${addressStr}</div>
        </div>

        <div class="ssl-checker__result-row">
            <div class="ssl-checker__result-label">
                <i class="fa-solid fa-circle-check text-success mr-2"></i>
                Issuer:
            </div>
            <div class="ssl-checker__result-value">${safe(issuer_common_name)} (${safeArr(issuer_organization)})</div>
        </div>

        <div class="ssl-checker__result-row">
            <div class="ssl-checker__result-label">
                <i class="fa-solid fa-circle-check text-success mr-2"></i>
                Valid From:
            </div>
            <div class="ssl-checker__result-value">${formatVNDate(valid_from)}</div>
        </div>

        <div class="ssl-checker__result-row">
            <div class="ssl-checker__result-label">
                <i class="fa-solid fa-circle-check text-success mr-2"></i>
                Valid To:
            </div>
            <div class="ssl-checker__result-value">${formatVNDate(valid_to)}</div>
        </div>

        <div class="ssl-checker__result-row">
            <div class="ssl-checker__result-label">
                <i class="fa-solid fa-circle-check text-success mr-2"></i>
                Key Size:
            </div>
            <div class="ssl-checker__result-value">${key_size ? `${escapeHTML(key_size)} bits` : "N/A"}</div>
        </div>

        <div class="ssl-checker__result-row">
            <div class="ssl-checker__result-label">
                <i class="fa-solid fa-circle-check text-success mr-2"></i>
                Algorithm:
            </div>
            <div class="ssl-checker__result-value font-bold">${safe(algorithm)}</div>
        </div>
        
        <div class="ssl-checker__result-row">
            <div class="ssl-checker__result-label">
                <i class="fa-solid fa-circle-check text-success mr-2"></i>
                Signature Algorithm:
            </div>
            <div class="ssl-checker__result-value">${safe(signature_algorithm)}</div>
        </div>
        
        <div class="ssl-checker__result-row">
            <div class="ssl-checker__result-label">
                <i class="fa-solid fa-circle-check text-success mr-2"></i>
                Serial Number:
            </div>
            <div class="ssl-checker__result-value" title="${safe(serialFormatted)}">${safe(serialClean) || "N/A"}</div>
        </div>
    `;

    resultBodyCert.innerHTML = html;
}


function displayResults(data) {
    if (!data || data.error) {
        setDisplay(resultCardCert, "none");
        let msg = data?.error || "Gặp lỗi khi giải mã Certificate!";
        // Highlight logic
        msg = msg.replace(/(Certificate không thể parse được)/, "<b>$1</b>");
        msg = msg.replace(/(signature verification failed)/, "<b>$1</b>");

        showError(errorCardCert, errorMsgCert, msg);
        return;
    }

    setDisplay(errorCardCert, "none");
    setDisplay(resultCardCert, "block");

    renderCERTResult(data);
}

/* ==========================
    EVENT LISTENERS
   ========================== */

inputCert.addEventListener("input", function (e) {
    const val = e.target.value;
    sessionStorage.setItem(CERT_STORAGE_KEY, val);

    // Ẩn error (server) hoặc kết quả cũ
    setDisplay(errorCardCert, "none");
    setDisplay(resultCardCert, "none");

    if (!val || val.trim() === "") {
        setDisplay(certValidationError, "none");
        inputCert.classList.remove("is-invalid");
        setElementsEnabled([btnCertDecoder], false);
        return;
    }

    try {
        normalizeCertInput(val);

        // Hợp lệ -> Ẩn cảnh báo
        setDisplay(certValidationError, "none");
        inputCert.classList.remove("is-invalid");
        setElementsEnabled([btnCertDecoder], true);
    } catch (err) {
        // Có lỗi format -> Hiện cảnh báo real-time
        setDisplay(certValidationError, "block");
        certValidationError.querySelector('.error-card__message').textContent = err.message;
        inputCert.classList.add("is-invalid");
        setElementsEnabled([btnCertDecoder], false);
    }
});

btnCertDecoder.addEventListener("click", async () => {
    let rawCert = inputCert.value;
    let certClean = "";

    try {
        certClean = normalizeCertInput(rawCert);
    } catch (err) {
        setDisplay(resultCardCert, "none");
        showError(errorCardCert, errorMsgCert, err.message);
        return;
    }

    toggleLoading(btnCertDecoder, iconCertDecoder, iconCertLoading, true);
    setElementsEnabled([btnCertDecoder, inputCert], false);

    const data = await performCertDecoder(certClean);

    displayResults(data);

    toggleLoading(btnCertDecoder, iconCertDecoder, iconCertLoading, false);
    setElementsEnabled([btnCertDecoder, inputCert], true);
});

/* Khởi tạo trạng thái ban đầu */
function initCertDecoderApp() {
    const savedCERT = sessionStorage.getItem(CERT_STORAGE_KEY);
    if (savedCERT) {
        inputCert.value = savedCERT;
    }

    if (inputCert.value.trim() !== "") {
        inputCert.dispatchEvent(new Event("input"));
    } else {
        setElementsEnabled([btnCertDecoder], false);
    }
}

document.addEventListener("DOMContentLoaded", initCertDecoderApp);
