import {
    toggleLoading,
    setDisplay,
    renderSuccessHeader,
    resetUI,
    setElementsEnabled,
    showError,
    hide,
    $
} from "../../../utils/dom.js";
import { escapeHTML } from "../../../utils/format.js";
import { API_BASE_URL } from "../../../config.js";
import { initFileUploadToggle } from "../../../utils/file-upload.js";

/**
 * SSL CSR Decoder Module
 * Hardened & Refactored version
 */
function init() {
    const form = document.getElementById("formCsrDecoder");
    if (!form) return;

    // --- Init File Upload Toggle ---
    initFileUploadToggle(
        "csrInputMode", 
        "csrPasteZone", 
        "csrUploadZone", 
        "uploadCsrDropzone", 
        "inputCsrFile", 
        "inputCsr"
    );

    // --- UI Elements ---
    const inputCsr = document.getElementById("inputCsr");
    const btnDecoder = document.getElementById("btnCsrDecoder");
    const iconDecoder = document.getElementById("iconCsrDecoder");
    const iconLoading = document.getElementById("iconCsrLoading");
    const toolResult = document.getElementById("resultCardCsr");
    const resultTitle = $("#resultCardCsr .result-card__title");
    const resultsBody = document.getElementById("resultBodyCsr");
    const toolError = document.getElementById("errorCardCsr");
    const toolErrorMsg = document.getElementById("errorMsgCsr");

    const inputValidationError = document.getElementById("csrValidationError");
    const inputValidationMsg = $("#csrValidationError .message-card__message");

    // --- Helper Functions ---

    /**
     * Clean and validate PEM structure locally before sending to server
     */
    function normalizeCSRInput(input) {
        if (!input || typeof input !== "string") return "";
        const val = input.trim();
        if (!val) return "";

        const MAX_SIZE = 100 * 1024;
        if (val.length > MAX_SIZE) throw new Error("CSR vượt quá kích thước cho phép (100KB).");

        const normalized = val.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
        const PEM_REGEX = /-----BEGIN ((?:NEW )?CERTIFICATE REQUEST)-----([\s\S]*?)-----END \1-----/g;
        const matches = [...normalized.matchAll(PEM_REGEX)];

        if (matches.length === 0) {
            if (!normalized.includes("-----BEGIN")) throw new Error("CSR không hợp lệ: Thiếu thẻ mở (BEGIN).");
            if (normalized.includes("PRIVATE KEY")) throw new Error("Đây là Private Key, không phải CSR.");
            if (normalized.includes("BEGIN CERTIFICATE") && !normalized.includes("REQUEST")) throw new Error("Đây là Chứng chỉ (Certificate), không phải CSR.");
            if (!normalized.includes("-----END")) throw new Error("CSR không hợp lệ: Thiếu thẻ đóng (END).");
            throw new Error("CSR không hợp lệ: Sai định dạng PEM.");
        }

        if (matches.length > 1) throw new Error("Chỉ hỗ trợ giải mã 1 CSR mỗi lần.");

        const match = matches[0];
        const content = match[2].replace(/\s+/g, "");
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(content)) throw new Error("CSR chứa ký tự lạ không thuộc chuẩn Base64.");
        if (content.length % 4 !== 0) throw new Error("Dữ liệu CSR bị cắt xén hoặc thiếu ký tự.");

        return `-----BEGIN ${match[1]}-----\n${content.match(/.{1,64}/g).join("\n")}\n-----END ${match[1]}-----`;
    }

    function renderCSRDetailRow(label, value, icon, isBold = false, isCode = false) {
        const displayValue = Array.isArray(value) ? value.join(", ") : (value || "N/A");
        const iconClass = icon || "fa-solid fa-circle-check";
        return `
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label">
                    <i class="${iconClass} text-success mr-2"></i>
                    ${label}:
                </div>
                <div class="ssl-checker__result-value ${isBold ? 'font-bold text-primary' : ''} ${isCode ? 'font-mono text-secondary' : ''}">
                    ${escapeHTML(displayValue)}
                </div>
            </div>
        `;
    }

    function clearUIState() {
        if (toolResult) hide(toolResult);
        if (toolError) hide(toolError);
    }

    // --- Core Logic ---

    inputCsr.addEventListener("input", () => {
        clearUIState();
        const val = inputCsr.value.trim();
        const dropzone = document.getElementById("uploadCsrDropzone");
        const isUploadMode = document.querySelector('input[name="csrInputMode"]:checked')?.value === 'upload';
        
        if (!val) {
            inputCsr.classList.remove('is-invalid');
            if (inputValidationError) hide(inputValidationError);
            btnDecoder.disabled = true;
            if (isUploadMode && dropzone) {
                dropzone.classList.remove('ssl-file-upload--valid', 'ssl-file-upload--invalid');
            }
            return;
        }

        try {
            normalizeCSRInput(val);
            inputCsr.classList.remove('is-invalid');
            if (inputValidationError) hide(inputValidationError);
            btnDecoder.disabled = false;

            if (isUploadMode && dropzone) {
                dropzone.classList.add('ssl-file-upload--valid');
                dropzone.classList.remove('ssl-file-upload--invalid');
            }
        } catch (err) {
            inputCsr.classList.add('is-invalid');
            if (inputValidationError) {
                inputValidationError.classList.remove('d-none');
                if (inputValidationMsg) inputValidationMsg.textContent = err.message;
            }
            btnDecoder.disabled = true;

            if (isUploadMode && dropzone) {
                dropzone.classList.add('ssl-file-upload--invalid');
                dropzone.classList.remove('ssl-file-upload--valid');
            }
        }
    });

    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        
        let csr;
        try {
            csr = normalizeCSRInput(inputCsr.value);
        } catch (err) {
            showError(toolError, toolErrorMsg, err.message, [toolResult]);
            return;
        }

        toggleLoading(btnDecoder, iconDecoder, iconLoading, true);
        setElementsEnabled([inputCsr, btnDecoder], false);
        clearUIState();

        try {
            const response = await fetch(`${API_BASE_URL}/ssl/csr/decode`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ csr })
            });

            const result = await response.json();
            if (!response.ok || !result.success) {
                throw new Error(result.message || "Giải mã CSR thất bại.");
            }

            const data = result.data;
            renderSuccessHeader(resultTitle, "Kết quả giải mã CSR", "fa-qrcode");
            
            resultsBody.innerHTML = `
                <div class="ssl-checker__result-group">
                    ${renderCSRDetailRow("Common Name", data.common_name, "fa-solid fa-file-signature", true)}
                    ${renderCSRDetailRow("SANs", data.sans, "fa-solid fa-list-check")}
                    ${renderCSRDetailRow("Organization", data.organization, "fa-solid fa-building")}
                    ${renderCSRDetailRow("Unit", data.organizational_unit, "fa-solid fa-sitemap")}
                    ${renderCSRDetailRow("Locality", data.locality, "fa-solid fa-city")}
                    ${renderCSRDetailRow("State / Province", data.state, "fa-solid fa-map-location")}
                    ${renderCSRDetailRow("Country", data.country, "fa-solid fa-earth-asia")}
                    ${renderCSRDetailRow("Algorithm", data.algorithm, "fa-solid fa-shield-halved", false, true)}
                    ${renderCSRDetailRow("Key Size", data.key_size ? `${data.key_size} bits` : "N/A", "fa-solid fa-key", false, true)}
                </div>
            `;

            setDisplay(toolResult, "block");
            toolResult.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        } catch (error) {
            console.error("Decode Error:", error);
            showError(toolError, toolErrorMsg, error.message, [toolResult]);
        } finally {
            toggleLoading(btnDecoder, iconDecoder, iconLoading, false);
            setElementsEnabled([inputCsr, btnDecoder], true);
        }
    });

    // Initial check if there's content (e.g. from browser autofill)
    if (inputCsr.value) {
        inputCsr.dispatchEvent(new Event('input'));
    }
}

document.addEventListener("DOMContentLoaded", init);
