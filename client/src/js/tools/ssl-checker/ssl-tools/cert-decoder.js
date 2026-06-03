import {
    showError,
    setDisplay,
    setElementsEnabled,
    toggleLoading,
    escapeHTML
} from "../../../utils/index.js";
import { API_BASE_URL } from "../../../config.js";
import { initFileUploadToggle } from "../../../utils/file-upload.js";

const CERT_STORAGE_KEY = "web_utility_kit_cert_decoder_input";

/**
 * SSL Certificate Decoder Module
 * Refactored to modular init() pattern
 */
export function init() {
    const formCertDecoder = document.getElementById("formCertDecoder");
    if (!formCertDecoder) return;

    // --- Init File Upload Toggle ---
    initFileUploadToggle(
        "certInputMode",
        "certPasteZone",
        "certUploadZone",
        "uploadCertDropzone",
        "inputCertFile",
        "inputCert"
    );

    const inputCert = document.getElementById("inputCert");
    const btnCertDecoder = document.getElementById("btnCertDecoder");
    const iconCertDecoder = document.getElementById("iconCertDecoder");
    const iconCertLoading = document.getElementById("iconCertLoading");

    const resultCardCert = document.getElementById("resultCardCert");
    const resultBodyCert = document.getElementById("resultBodyCert");

    const errorCardCert = document.getElementById("errorCardCert");
    const errorMsgCert = document.getElementById("errorMsgCert");

    const certValidationError = document.getElementById("certValidationError");

    // ─── Input Normalization ───────────────────────────────────────────────
    function normalizeCertInput(input) {
        if (input == null || typeof input !== "string") return "";
        const val = input.trim();
        if (val === "") return "";

        const MAX_CERT_SIZE = 100 * 1024; // 100KB
        if (val.length > MAX_CERT_SIZE) {
            throw new Error("Certificate quá lớn (tối đa 100KB).");
        }

        const normalized = val.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
        const PEM_REGEX = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;
        const matches = [...normalized.matchAll(PEM_REGEX)];

        if (matches.length === 0) {
            if (!normalized.includes("-----BEGIN")) throw new Error("Thiếu thẻ mở BEGIN CERTIFICATE.");
            if (normalized.includes("PRIVATE KEY")) throw new Error("Đây là Private Key, không phải Certificate.");
            if (!normalized.includes("-----END")) throw new Error("Thiếu thẻ đóng END CERTIFICATE.");
            throw new Error("Định dạng Certificate không hợp lệ.");
        }

        if (matches.length > 1) {
            throw new Error("Sử dụng tab 'Chain' hoặc chỉ nhập 1 Certificate.");
        }

        const base64Content = matches[0][1].replace(/\s+/g, "");
        if (!/^[A-Za-z0-9+/]+={0,2}$/.test(base64Content)) {
            throw new Error("Chứng chỉ chứa ký tự Base64 không hợp lệ.");
        }
        
        // Re-construct clean PEM
        const lines = base64Content.match(/.{1,64}/g).join("\n");
        return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
    }

    // ─── Rendering Helpers ────────────────────────────────────────────────
    function safe(val) {
        if (val === undefined || val === null || val === "" || val === " ") return "N/A";
        return escapeHTML(val);
    }

    function safeArr(arr) {
        if (!Array.isArray(arr) || arr.length === 0) return "N/A";
        return escapeHTML(arr.filter(v => v).join(", "));
    }

    function formatVNDate(isoString) {
        if (!isoString) return "N/A";
        const d = new Date(isoString);
        if (isNaN(d.getTime())) return escapeHTML(isoString);
        
        const pad = (n) => n.toString().padStart(2, '0');
        return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`;
    }

    function renderCERTResult(data) {
        if (!data) return;

        const {
            common_name, organization, organizational_unit, country, state, locality,
            issuer_common_name, issuer_organization, valid_from, valid_to, sans,
            key_size, algorithm, signature_algorithm, serial_hex, serial_dec
        } = data;


        const getExpiryStatus = (validTo) => {
            const expiry = new Date(validTo);
            const now = new Date();
            const diffTime = expiry - now;
            const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

            if (diffDays < 0) {
                return {
                    textClass: "text-error",
                    icon: "fa-solid fa-circle-xmark"
                };
            } else if (diffDays <= 30) {
                return {
                    textClass: "text-warning",
                    icon: "fa-solid fa-triangle-exclamation"
                };
            } else {
                return {
                    textClass: "text-success",
                    icon: "fa-solid fa-calendar-check"
                };
            }
        };

        const expiryStatus = getExpiryStatus(valid_to);

        resultBodyCert.innerHTML = `
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="fa-solid fa-file-signature text-success mr-2"></i> Common Name:</div>
                <div class="ssl-checker__result-value font-bold text-primary">${safe(common_name)}</div>
            </div>
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="fa-solid fa-list-check text-success mr-2"></i> Alternative Names (SANs):</div>
                <div class="ssl-checker__result-value">${safeArr(sans)}</div>
            </div>
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="fa-solid fa-building text-success mr-2"></i> Organization:</div>
                <div class="ssl-checker__result-value">${safe(organization)}</div>
            </div>
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="fa-solid fa-sitemap text-success mr-2"></i> Organization Unit:</div>
                <div class="ssl-checker__result-value">${safe(organizational_unit)}</div>
            </div>
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="fa-solid fa-map-pin text-success mr-2"></i> Locality:</div>
                <div class="ssl-checker__result-value">${safe(locality)}</div>
            </div>
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="fa-solid fa-map text-success mr-2"></i> State:</div>
                <div class="ssl-checker__result-value">${safe(state)}</div>
            </div>
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="fa-solid fa-globe text-success mr-2"></i> Country:</div>
                <div class="ssl-checker__result-value">${safe(country)}</div>
            </div>
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="fa-solid fa-stamp text-success mr-2"></i> Issuer:</div>
                <div class="ssl-checker__result-value font-bold">${safe(issuer_common_name)} ${issuer_organization ? `(${safe(issuer_organization)})` : ""}</div>
            </div>
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="fa-solid fa-calendar-day text-success mr-2"></i> Valid From:</div>
                <div class="ssl-checker__result-value">${formatVNDate(valid_from)}</div>
            </div>
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="${expiryStatus.icon} ${expiryStatus.textClass} mr-2"></i> Valid To (Expiry):</div>
                <div class="ssl-checker__result-value font-bold ${expiryStatus.textClass}">${formatVNDate(valid_to)}</div>
            </div>
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="fa-solid fa-shield-halved text-success mr-2"></i> Algorithm & Key Size:</div>
                <div class="ssl-checker__result-value">${safe(algorithm)} ${key_size ? `(${key_size} bits)` : ""}</div>
            </div>
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="fa-solid fa-fingerprint text-success mr-2"></i> Signature Algorithm:</div>
                <div class="ssl-checker__result-value">${safe(signature_algorithm)}</div>
            </div>
            <div class="ssl-checker__result-row">
                <div class="ssl-checker__result-label"><i class="fa-solid fa-barcode text-success mr-2"></i> Serial Number:</div>
                <div class="ssl-checker__result-value">
                    <div class="font-mono break-all text-secondary pb-1">${escapeHTML(serial_hex)}</div>
                </div>
            </div>
        `;
        
        setDisplay(resultCardCert, "block");
        resultCardCert.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    // ─── Actions ────────────────────────────────────────────────────────────

    async function handleDecode() {
        const raw = inputCert.value;
        let clean = "";
        try {
            clean = normalizeCertInput(raw);
        } catch (err) {
            showError(errorCardCert, errorMsgCert, err.message, [resultCardCert]);
            return;
        }

        toggleLoading(btnCertDecoder, iconCertDecoder, iconCertLoading, true);
        setElementsEnabled([btnCertDecoder, inputCert], false);
        setDisplay(errorCardCert, "none");
        setDisplay(resultCardCert, "none");

        try {
            const resp = await fetch(`${API_BASE_URL}/ssl/cer/decode`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cert: clean }),
            });
            const res = await resp.json();

            if (!resp.ok || !res.success) {
                showError(errorCardCert, errorMsgCert, res.message || "Lỗi máy chủ.", [resultCardCert]);
            } else {
                renderCERTResult(res.data);
            }
        } catch (err) {
            showError(errorCardCert, errorMsgCert, "Không thể kết nối đến máy chủ.", [resultCardCert]);
        } finally {
            toggleLoading(btnCertDecoder, iconCertDecoder, iconCertLoading, false);
            setElementsEnabled([btnCertDecoder, inputCert], true);
        }
    }

    // ─── Event Listeners ────────────────────────────────────────────────────
    inputCert.addEventListener("input", function() {
        const val = this.value;
        const dropzone = document.getElementById("uploadCertDropzone");
        const isUploadMode = document.querySelector('input[name="certInputMode"]:checked')?.value === 'upload';
        
        sessionStorage.setItem(CERT_STORAGE_KEY, val);
        setDisplay(errorCardCert, "none");
        setDisplay(resultCardCert, "none");

        if (!val.trim()) {
            setDisplay(certValidationError, "none");
            inputCert.classList.remove("is-invalid");
            btnCertDecoder.disabled = true;
            if (isUploadMode && dropzone) {
                dropzone.classList.remove('ssl-file-upload--valid', 'ssl-file-upload--invalid');
            }
            return;
        }

        try {
            normalizeCertInput(val);
            setDisplay(certValidationError, "none");
            inputCert.classList.remove("is-invalid");
            btnCertDecoder.disabled = false;

            if (isUploadMode && dropzone) {
                dropzone.classList.add('ssl-file-upload--valid');
                dropzone.classList.remove('ssl-file-upload--invalid');
            }
        } catch (err) {
            setDisplay(certValidationError, "block");
            const msgEl = certValidationError.querySelector('.message-card__message');
            if (msgEl) msgEl.textContent = err.message;
            inputCert.classList.add("is-invalid");
            btnCertDecoder.disabled = true;

            if (isUploadMode && dropzone) {
                dropzone.classList.add('ssl-file-upload--invalid');
                dropzone.classList.remove('ssl-file-upload--valid');
            }
        }
    });

    btnCertDecoder.addEventListener("click", handleDecode);

    // Initial State
    const saved = sessionStorage.getItem(CERT_STORAGE_KEY);
    if (saved) {
        inputCert.value = saved;
        inputCert.dispatchEvent(new Event("input"));
    } else {
        btnCertDecoder.disabled = true;
    }
}

document.addEventListener("DOMContentLoaded", init);
