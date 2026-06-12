import {
    toggleLoading,
    setDisplay,
    setElementsEnabled,
    showError,
} from "../../../utils/index.js";
import { escapeHTML } from "../../../utils/format.js";
import { API_BASE_URL } from "../../../config.js";
import { initFileUploadToggle, resetFileUpload } from "../../../utils/file-upload.js";

/**
 * SSL Key Matcher Module
 * Refactored to modular init() pattern
 */
export function init() {
    // --- AbortController state ---
    let currentAbortController = null;

    const form = document.getElementById("formKeyMatcher");
    if (!form) return;

    // --- Init File Upload Toggles for 2 Boxes ---
    initFileUploadToggle(
        "matcher1Mode",
        "matcher1PasteZone",
        "matcher1UploadZone",
        "uploadMatcher1Dropzone",
        "inputMatcher1File",
        "matcherBox1"
    );

    initFileUploadToggle(
        "matcher2Mode",
        "matcher2PasteZone",
        "matcher2UploadZone",
        "uploadMatcher2Dropzone",
        "inputMatcher2File",
        "matcherBox2"
    );

    const radioCertKey = document.querySelector('input[name="matcherMode"][value="cert_key"]');
    const radioCsrCert = document.querySelector('input[name="matcherMode"][value="csr_cert"]');

    const lblBox1 = document.getElementById("lblMatcherBox1");
    const lblBox2 = document.getElementById("lblMatcherBox2");
    const box1 = document.getElementById("matcherBox1");
    const box2 = document.getElementById("matcherBox2");
    const btnSubmit = document.getElementById("btnKeyMatcher");
    const iconNormal = document.getElementById("iconMatcher");
    const iconLoading = document.getElementById("iconMatcherLoading");

    // Card lỗi inline của từng ô input
    const errBox1 = document.getElementById("matcher1ValidationError");
    const errMsg1 = errBox1 ? errBox1.querySelector(".message-card__message") : null;
    const errBox2 = document.getElementById("matcher2ValidationError");
    const errMsg2 = errBox2 ? errBox2.querySelector(".message-card__message") : null;

    // Card kết quả khớp/không khớp
    const resultCard = document.getElementById("resultCardMatcher");
    const resultTitle = document.querySelector("#resultCardMatcher .result-card__title");
    const resultBody = document.getElementById("resultBodyMatcher");

    // Card lỗi chung
    const errorCard = document.getElementById("errorCardMatcher");
    const errorMsg = document.getElementById("errorMsgMatcher");

    // ─── Validate định dạng PEM (real-time, chỉ kiểm tra cú pháp) ────────────
    function validatePEM(input, expectedType) {
        if (!input) return null;
        const val = input.trim();
        if (!val) return null;

        let regex;
        let typeName;
        let displayType = expectedType;

        switch (expectedType) {
            case "CERTIFICATE":
                regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
                typeName = "Certificate (CRT)";
                break;
            case "CSR":
                regex = /-----BEGIN ((?:NEW )?CERTIFICATE REQUEST)-----[\s\S]*?-----END \1-----/g;
                typeName = "Certificate Signing Request (CSR)";
                displayType = "CERTIFICATE REQUEST";
                break;
            case "KEY":
                regex = /-----BEGIN ((?:RSA |EC )?PRIVATE KEY)-----[\s\S]*?-----END \1-----/g;
                typeName = "Private Key";
                displayType = "PRIVATE KEY";
                break;
        }

        const matches = [...val.matchAll(regex)];

        if (matches.length === 0) {
            if (!val.includes("-----BEGIN")) return `Thiếu dòng mở đầu (-----BEGIN ${displayType}-----)`;
            if (!val.includes("-----END"))   return `Thiếu dòng kết thúc (-----END ${displayType}-----)`;
            return `Định dạng ${typeName} không hợp lệ.`;
        }

        if (matches.length > 1) {
            return `Chỉ nhập 1 khối ${typeName} mỗi lần.`;
        }

        if (val.trim() !== matches[0][0].trim()) {
            return `Có ký tự thừa bên ngoài khối PEM — vui lòng xóa chúng.`;
        }

        const rawLines = val.split("\n").map(l => l.replace("\r", "").trimEnd());
        let insideBlock = false;
        for (let i = 0; i < rawLines.length; i++) {
            const line = rawLines[i];
            if (line.startsWith("-----BEGIN")) { insideBlock = true; continue; }
            if (line.startsWith("-----END"))   { insideBlock = false; continue; }
            if (insideBlock && line.length > 64) {
                return `Dòng ${i + 1} có ${line.length} ký tự (tối đa 64 mỗi dòng).`;
            }
        }

        const b64 = matches[0][0]
            .replace(/-----BEGIN[^-]*-----/, "")
            .replace(/-----END[^-]*-----/, "")
            .replace(/\s+/g, "");

        if (!/^[A-Za-z0-9+/]+=*$/.test(b64)) {
            return `Nội dung Base64 trong ${typeName} chứa ký tự không hợp lệ.`;
        }

        const minLength = expectedType === "CERTIFICATE" ? 800 : expectedType === "CSR" ? 200 : 100;
        if (b64.replace(/=/g, "").length < minLength) {
            return `Nội dung ${typeName} quá ngắn — có thể bị copy thiếu.`;
        }

        return null;
    }

    // ─── Cập nhật nhãn và xóa state khi đổi mode ─────────────────────────────
    function updateLabels() {
        if (currentAbortController) {
            currentAbortController.abort();
        }

        if (!lblBox1 || !lblBox2) return;

        box1.value = "";
        box2.value = "";

        // Reset File Upload areas
        resetFileUpload("uploadMatcher1Dropzone", "Kéo thả tệp hoặc click chọn");
        resetFileUpload("uploadMatcher2Dropzone", "Kéo thả tệp hoặc click chọn");

        setDisplay(resultCard, "none");
        setDisplay(errorCard, "none");
        setDisplay(errBox1, "none");
        setDisplay(errBox2, "none");
        box1.classList.remove("is-invalid");
        box2.classList.remove("is-invalid");

        if (radioCertKey && radioCertKey.checked) {
            lblBox1.textContent = "Private Key (KEY)";
            lblBox2.textContent = "Certificate (CRT)";
            box1.placeholder = "-----BEGIN RSA PRIVATE KEY----- ...";
            box2.placeholder = "-----BEGIN CERTIFICATE----- ...";
        } else if (radioCsrCert && radioCsrCert.checked) {
            lblBox1.textContent = "Certificate Signing Request (CSR)";
            lblBox2.textContent = "Certificate (CRT)";
            box1.placeholder = "-----BEGIN CERTIFICATE REQUEST----- ...";
            box2.placeholder = "-----BEGIN CERTIFICATE----- ...";
        }

        if (btnSubmit) btnSubmit.disabled = true;
    }

    // ─── Kiểm tra định dạng real-time ────────────────────────────────────────
    function checkValidations() {
        setDisplay(resultCard, "none");
        setDisplay(errorCard, "none");

        const checkedMode = document.querySelector('input[name="matcherMode"]:checked');
        if (!checkedMode) return;

        const mode = checkedMode.value;
        const type1 = mode === "cert_key" ? "KEY" : "CSR";
        const type2 = "CERTIFICATE";

        const val1 = box1.value;
        const val2 = box2.value;

        // Dropzones and Modes
        const dropzone1 = document.getElementById("uploadMatcher1Dropzone");
        const dropzone2 = document.getElementById("uploadMatcher2Dropzone");
        const isUpload1 = document.querySelector('input[name="matcher1Mode"]:checked')?.value === 'upload';
        const isUpload2 = document.querySelector('input[name="matcher2Mode"]:checked')?.value === 'upload';

        if (!val1.trim()) {
            box1.classList.remove("is-invalid");
            if (errBox1) setDisplay(errBox1, "none");
            if (isUpload1 && dropzone1) {
                dropzone1.classList.remove('ssl-file-upload--valid', 'ssl-file-upload--invalid');
            }
        }
        if (!val2.trim()) {
            box2.classList.remove("is-invalid");
            if (errBox2) setDisplay(errBox2, "none");
            if (isUpload2 && dropzone2) {
                dropzone2.classList.remove('ssl-file-upload--valid', 'ssl-file-upload--invalid');
            }
        }

        const error1 = validatePEM(val1, type1);
        const error2 = validatePEM(val2, type2);

        if (error1) {
            box1.classList.add("is-invalid");
            if (errBox1) setDisplay(errBox1, "block");
            if (errMsg1) errMsg1.textContent = error1;
            if (isUpload1 && dropzone1) {
                dropzone1.classList.add('ssl-file-upload--invalid');
                dropzone1.classList.remove('ssl-file-upload--valid');
            }
        } else if (val1.trim()) {
            box1.classList.remove("is-invalid");
            if (errBox1) setDisplay(errBox1, "none");
            if (isUpload1 && dropzone1) {
                dropzone1.classList.add('ssl-file-upload--valid');
                dropzone1.classList.remove('ssl-file-upload--invalid');
            }
        }

        if (error2) {
            box2.classList.add("is-invalid");
            if (errBox2) setDisplay(errBox2, "block");
            if (errMsg2) errMsg2.textContent = error2;
            if (isUpload2 && dropzone2) {
                dropzone2.classList.add('ssl-file-upload--invalid');
                dropzone2.classList.remove('ssl-file-upload--valid');
            }
        } else if (val2.trim()) {
            box2.classList.remove("is-invalid");
            if (errBox2) setDisplay(errBox2, "none");
            if (isUpload2 && dropzone2) {
                dropzone2.classList.add('ssl-file-upload--valid');
                dropzone2.classList.remove('ssl-file-upload--invalid');
            }
        }

        btnSubmit.disabled = !!(error1 || error2 || !val1.trim() || !val2.trim());
    }

    // ─── Render kết quả khớp / không khớp vào #resultCardMatcher ─────────────
    /**
     * Render match results using standardized CSS classes
     */
    function renderResult(data) {
        setDisplay(resultCard, "block");

        const isMatched = data.matched;
        const colorClass = isMatched ? "success" : "error";
        const iconClass = isMatched ? "fa-circle-check" : "fa-circle-xmark";

        // Clean header with semantic classes
        resultTitle.innerHTML = `
            <div class="matcher-result__status-box">
                <div class="matcher-result__icon text-${colorClass}">
                    <i class="fa-solid ${iconClass}"></i>
                </div>
                <div class="matcher-result__title text-${colorClass}">${escapeHTML(data.status)}</div>
                <p class="matcher-result__message">${escapeHTML(data.message)}</p>
            </div>
        `;

        const checkedMode = document.querySelector('input[name="matcherMode"]:checked');
        const currentMode = checkedMode ? checkedMode.value : "";
        const label1 = currentMode === "csr_cert" ? "CSR Hash (SHA-256)" : "Private Key Hash (SHA-256)";
        const label2 = "Certificate Hash (SHA-256)";

        if (isMatched) {
            resultBody.innerHTML = `
                <div class="matcher-result__details">
                    <div class="matcher-result__key-info">
                        <i class="fa-solid fa-circle-check text-success"></i>
                        <span class="font-semibold text-secondary">Loại khóa:</span>
                        <span class="font-bold text-primary">${escapeHTML(data.key_type)} / ${escapeHTML(String(data.key_size))} bits</span>
                    </div>
                    <div class="matcher-result__hashes-box">
                        <div class="matcher-result__hash-row matcher-result__hash-row--bordered">
                            <span class="matcher-result__hash-label">${escapeHTML(label1)}:</span>
                            <span class="matcher-result__hash-value">${escapeHTML(data.hash1)}</span>
                        </div>
                        <div class="matcher-result__hash-row">
                            <span class="matcher-result__hash-label">${escapeHTML(label2)}:</span>
                            <span class="matcher-result__hash-value">${escapeHTML(data.hash2)}</span>
                        </div>
                    </div>
                </div>
            `;
        } else {
            resultBody.innerHTML = `
                <div class="matcher-result__details">
                    <div class="matcher-result__hashes-box">
                        <div class="matcher-result__hash-row matcher-result__hash-row--bordered">
                            <span class="matcher-result__hash-label text-error">${escapeHTML(label1)}:</span>
                            <span class="matcher-result__hash-value text-error">${escapeHTML(data.hash1 || "—")}</span>
                        </div>
                        <div class="matcher-result__hash-row">
                            <span class="matcher-result__hash-label text-error">${escapeHTML(label2)}:</span>
                            <span class="matcher-result__hash-value text-error">${escapeHTML(data.hash2 || "—")}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const checkedMode = document.querySelector('input[name="matcherMode"]:checked');
        if (!checkedMode) return;
        const mode = checkedMode.value;
        const input1 = box1.value.trim();
        const input2 = box2.value.trim();

        // Abort request cũ nếu đang chạy
        if (currentAbortController) currentAbortController.abort();
        const controller = new AbortController();
        currentAbortController = controller;

        const modeControls = [
            ...document.querySelectorAll('input[name="matcherMode"], input[name="matcher1Mode"], input[name="matcher2Mode"]')
        ];

        setDisplay(resultCard, "none");
        setDisplay(errorCard, "none");
        setElementsEnabled([box1, box2, btnSubmit, ...modeControls], false);
        toggleLoading(btnSubmit, iconNormal, iconLoading, true);

        let hasInputErrors = false;

        try {
            const response = await fetch(`${API_BASE_URL}/ssl/key-matcher/match`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ type: mode, input1, input2 }),
                signal: controller.signal,
            });

            let rawData;
            try {
                rawData = await response.json();
            } catch (_) {
                throw new Error(`Lỗi từ máy chủ: ${response.status} ${response.statusText}`);
            }

            if (!response.ok) {
                throw new Error(rawData.message || rawData.error || "Lỗi hệ thống không xác định.");
            }

            if (currentAbortController !== controller) return;

            // Unwrap: backend trả { success, data: { matched, input_errors, ... } }
            const result = rawData.data || rawData;

            if (result.input_errors) {
                hasInputErrors = true;
                if (result.input_errors?.input1) {
                    box1.classList.add("is-invalid");
                    if (errBox1) setDisplay(errBox1, "block");
                    if (errMsg1) errMsg1.textContent = result.input_errors.input1;
                }
                if (result.input_errors?.input2) {
                    box2.classList.add("is-invalid");
                    if (errBox2) setDisplay(errBox2, "block");
                    if (errMsg2) errMsg2.textContent = result.input_errors.input2;
                }
            } else {
                renderResult(result);
            }

        } catch (err) {
            if (err.name === 'AbortError') return;
            if (currentAbortController !== controller) return;
            showError(errorCard, errorMsg, err.message || "Không thể kết nối đến máy chủ. Vui lòng thử lại.", [resultCard]);
        } finally {
            if (currentAbortController === controller) {
                currentAbortController = null;
                toggleLoading(btnSubmit, iconNormal, iconLoading, false);
                setElementsEnabled([box1, box2, btnSubmit, ...modeControls], true);
                if (hasInputErrors) btnSubmit.disabled = true;
            }
        }
    });

    if (radioCertKey && radioCsrCert) {
        radioCertKey.addEventListener("change", updateLabels);
        radioCsrCert.addEventListener("change", updateLabels);
    }
    box1.addEventListener("input", checkValidations);
    box2.addEventListener("input", checkValidations);

    updateLabels();
}

document.addEventListener("DOMContentLoaded", init);
