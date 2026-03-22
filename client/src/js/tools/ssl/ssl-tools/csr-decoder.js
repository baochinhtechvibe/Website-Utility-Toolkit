// ===================================================
//  SSL TOOLS - CSR DECODER PAGE
// ===================================================
import {
    /* dom.js */
    toggleLoading,
    setDisplay,
    renderSuccessHeader,
    showElements,
    resetUI,
    setElementsEnabled,
    showError,

    /* network.js */
    normalizeHostnameInput,

    /* url.js */
    getWhoisDomain,
    setupCopyButton,

    /* format.js */
    formatDate,
    escapeHTML
} from "../../../utils/index.js";

// ===================================================
//  CONFIGURATION
// ===================================================
/*
 * Cấu hình tự động URL API cho cả Dev lẫn Production
 */
const API_BASE_URL = (window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost")
    ? "http://localhost:3101/api"
    : "/api";

/*
 * CSR Decoder Elements
 */
const formCsr = document.getElementById("formCsrDecoder");
const inputCsr = document.getElementById("inputCsr");
const btnCsrDecoder = document.getElementById("btnCsrDecoder");
const iconCsrDecoder = document.getElementById("iconCsrDecoder");
const iconCsrLoading = document.getElementById("iconCsrLoading");
const toolResult = document.getElementById("resultCardCsr");
const sslResultTitle = document.querySelector("#resultCardCsr .result-card__title");
const resultsContent = document.getElementById("resultBodyCsr");
const toolError = document.getElementById("errorCardCsr");
const toolErrorTitle = document.querySelector("#errorCardCsr .error-card__title");
const toolErrorMessage = document.getElementById("errorMsgCsr");

const CSR_STORAGE_KEY = "web_utility_kit_csr_decoder_input";

/* ================================
    HELPER FUNCTIONS
=================================== */


/**
 * Chuẩn hóa dữ liệu CSR người dùng nhập
 */
function normalizeCSRInput(input) {
    if (input == null || typeof input !== "string") return "";
    if (input.trim() === "") return "";

    const MAX_CSR_SIZE = 100 * 1024;
    if (input.length > MAX_CSR_SIZE) {
        throw new Error("CSR vượt quá kích thước cho phép (100KB).");
    }

    input = input.trim()
        .replace(/\r\n/g, "\n")
        .replace(/\r/g, "\n");

    const PEM_REGEX = /-----BEGIN ((?:NEW )?CERTIFICATE REQUEST)-----([\s\S]*?)-----END \1-----/g;
    const matches = [...input.matchAll(PEM_REGEX)];

    if (matches.length === 0) {
        if (!input.includes("-----BEGIN")) {
            throw new Error("CSR không hợp lệ: Thiếu thẻ mở (Ví dụ: -----BEGIN CERTIFICATE REQUEST-----).");
        }
        if (input.includes("PRIVATE KEY")) {
            throw new Error("Dữ liệu không hợp lệ: Đây là Private Key, không phải CSR.");
        }
        if (input.includes("BEGIN CERTIFICATE") && !input.includes("REQUEST")) {
            throw new Error("Dữ liệu không hợp lệ: Đây là Chứng chỉ (Certificate), không phải hệ thống CSR.");
        }
        if (!input.includes("-----END")) {
            throw new Error("CSR không hợp lệ: Thiếu thẻ đóng (Ví dụ: -----END CERTIFICATE REQUEST-----).");
        }
        throw new Error("CSR không hợp lệ: Cấu trúc PEM sai định dạng hoặc bị hỏng.");
    }

    if (matches.length > 1) {
        throw new Error("Hệ thống chỉ hỗ trợ giải mã 1 CSR mỗi lần nhập.");
    }

    const match = matches[0];
    const type = match[1];
    const rawBase64 = match[2];

    const base64Content = rawBase64.replace(/\s+/g, "");

    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64Content)) {
        throw new Error("CSR không hợp lệ: Nội dung mã hóa bị lỗi hoặc chứa ký tự lạ không thuộc chuẩn Base64.");
    }

    if (base64Content.length % 4 !== 0) {
        throw new Error("CSR không hợp lệ: Dữ liệu mã hóa của CSR bị thiếu ký tự hoặc bị cắt xén.");
    }

    if (base64Content.length < 150) {
        throw new Error("CSR không hợp lệ: Nội dung quá ngắn, có thể đoạn mã CSR đã bị cắt xén hoặc copy thiếu.");
    }

    const lines = [];
    for (let i = 0; i < base64Content.length; i += 64) {
        lines.push(base64Content.slice(i, i + 64));
    }

    return `-----BEGIN ${type}-----\n${lines.join("\n")}\n-----END ${type}-----`;
}

/* =================================
    PERFORM CSR DECODER FUNCTIONS
================================== */
/**
 * Gửi CSR lên server để decode
 */
async function performCSRDecoder(csr) {
    if (typeof csr !== "string" || csr.trim() === "") {
        return { success: false, error: "CSR không hợp lệ", code: 400 };
    }

    const url = `${API_BASE_URL}/ssl/csr/decode`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    try {
        const response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            body: JSON.stringify({ csr }),
            signal: controller.signal,
        });

        let data = {};
        try {
            data = await response.json();
        } catch {
            data = {};
        }

        if (!response.ok) {
            return {
                success: false,
                code: response.status,
                error: data?.error || "Server error",
            };
        }

        // Cần unwrap 'data' để các hàm render dễ dàng lấy biến
        if (data && data.data !== undefined) return data.data;
        return data;

    } catch (err) {
        if (err.name === "AbortError") {
            return { success: false, error: "Request timeout", code: 408 };
        }
        console.error("CSR decode network error:", err);
        return { success: false, error: "Không thể kết nối server", code: 0 };
    } finally {
        clearTimeout(timeoutId);
    }
}

/* =================================
    UI RENDER FUNCTIONS
================================== */
/**
 * Hiển thị kết quả giải mã CSR
 */
function displayResults(data) {
    if (!data || data.error) {
        showError(
            toolError,
            toolErrorMessage,
            data?.error || "Giải mã CSR thất bại, vui lòng thử lại sau",
            [toolResult]
        );
        return;
    }

    setDisplay(toolResult, "block");
    setDisplay(toolError, "none");
    renderSuccessHeader(sslResultTitle, "Kết quả giải mã CSR");
    renderCSRResult(data);
}

function renderCSRResult(data) {
    if (!data) return;
    const {
        common_name,
        organization,
        organizational_unit,
        country,
        state,
        locality,
        sans,
        key_size,
        algorithm,
    } = data;

    const safeArr = (arr) => (Array.isArray(arr) && arr.length > 0 ? escapeHTML(arr.join(", ")) : "N/A");
    const safeStr = (str) => (str ? escapeHTML(str) : "N/A");

    resultsContent.innerHTML = `
        <div class="ssl-checker__result-group">
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label">
                    <i class="fa-solid fa-circle-check text-success mr-2"></i>
                    Common Name:
                </div>
                <div class="ssl-checker__result-value font-bold text-primary">${safeStr(common_name)}</div>
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
                    Locality:
                </div>
                <div class="ssl-checker__result-value">${safeArr(locality)}</div>
            </div>

            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label">
                    <i class="fa-solid fa-circle-check text-success mr-2"></i>
                    State / Province:
                </div>
                <div class="ssl-checker__result-value">${safeArr(state)}</div>
            </div>

            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label">
                    <i class="fa-solid fa-circle-check text-success mr-2"></i>
                    Country:
                </div>
                <div class="ssl-checker__result-value">${safeArr(country)}</div>
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
                <div class="ssl-checker__result-value uppercase text-sm font-semibold">${safeStr(algorithm)}</div>
            </div>
        </div>
    `;
}

/* =================================
    EVENT BINDINGS
================================== */
if (formCsr) {
    formCsr.addEventListener("submit", async (e) => {
        e.preventDefault();
        setElementsEnabled([inputCsr, btnCsrDecoder], false);
        resetUI([toolResult, toolError]);
        toggleLoading(btnCsrDecoder, iconCsrDecoder, iconCsrLoading, true);

        try {
            const csr = normalizeCSRInput(inputCsr.value);
            const result = await performCSRDecoder(csr);
            displayResults(result);
        } catch (error) {
            const msg = error?.message || "Không thể giải mã CSR. Vui lòng thử lại.";
            showError(toolError, toolErrorMessage, msg, [toolResult]);
        } finally {
            toggleLoading(btnCsrDecoder, iconCsrDecoder, iconCsrLoading, false);
            setElementsEnabled([inputCsr, btnCsrDecoder], true);
        }
    });
}

function initApp() {
    const savedCSR = sessionStorage.getItem(CSR_STORAGE_KEY);
    if (savedCSR) {
        inputCsr.value = savedCSR;
    }

    inputCsr.addEventListener("input", () => {
        sessionStorage.setItem(CSR_STORAGE_KEY, inputCsr.value);

        // Ẩn bảng kết quả hoặc lỗi cũ nếu đang hiển thị
        if (!toolError.classList.contains("d-none")) {
            setDisplay(toolError, "none");
        }
        if (!toolResult.classList.contains("d-none")) {
            setDisplay(toolResult, "none");
        }

        // Validate realtime
        const val = inputCsr.value.trim();
        const csrValidationError = document.getElementById("csrValidationError");
        const csrValidationMsg = document.querySelector("#csrValidationError .error-card__message");

        if (!val) {
            inputCsr.classList.remove('is-invalid');
            if (csrValidationError) csrValidationError.classList.add('d-none');
            btnCsrDecoder.disabled = true;
            return;
        }

        try {
            normalizeCSRInput(val);
            // Hợp lệ
            inputCsr.classList.remove('is-invalid');
            if (csrValidationError) csrValidationError.classList.add('d-none');
            btnCsrDecoder.disabled = false;
        } catch (err) {
            // Không hợp lệ
            inputCsr.classList.add('is-invalid');
            if (csrValidationError) {
                csrValidationError.classList.remove('d-none');
                if (csrValidationMsg) csrValidationMsg.textContent = err.message;
            }
            btnCsrDecoder.disabled = true;
        }
    });

    // Chạy sự kiện input lần đầu để cập nhật trạng thái UI tương ứng nội dung được nạp từ localStorage
    if (inputCsr.value) {
        inputCsr.dispatchEvent(new Event('input'));
    }

    console.log("🚀 CSR Decoder Tool Initialized");
}

document.addEventListener("DOMContentLoaded", initApp);