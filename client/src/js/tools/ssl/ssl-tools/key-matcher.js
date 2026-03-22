import {
    toggleLoading,
    setDisplay,
    resetUI,
    setElementsEnabled,
    showError,
    escapeHTML,
} from "../../../utils/index.js";

const API_BASE_URL = (window.location.hostname === "127.0.0.1" || window.location.hostname === "localhost")
    ? "http://localhost:3101/api"
    : "/api";

function initKeyMatcherUI() {
    const form = document.getElementById("formKeyMatcher");
    const radioCertKey = document.querySelector('input[name="matcherMode"][value="cert_key"]');
    const radioCsrCert = document.querySelector('input[name="matcherMode"][value="csr_cert"]');

    const lblBox1 = document.getElementById("lblMatcherBox1");
    const lblBox2 = document.getElementById("lblMatcherBox2");
    const box1 = document.getElementById("matcherBox1");
    const box2 = document.getElementById("matcherBox2");
    const btnSubmit = document.getElementById("btnKeyMatcher");
    const iconNormal = document.getElementById("iconMatcher");
    const iconLoading = document.getElementById("iconMatcherLoading");

    // Card lỗi inline của từng ô input (lỗi ĐỊNH DẠNG real-time)
    const errBox1 = document.getElementById("matcher1ValidationError");
    const errMsg1 = errBox1 ? errBox1.querySelector(".error-card__message") : null;
    const errBox2 = document.getElementById("matcher2ValidationError");
    const errMsg2 = errBox2 ? errBox2.querySelector(".error-card__message") : null;

    // Card kết quả khớp/không khớp
    const resultCard = document.getElementById("resultCardMatcher");
    const resultTitle = document.querySelector("#resultCardMatcher .result-card__title");
    const resultBody = document.getElementById("resultBodyMatcher");

    // Card lỗi chung (parse error từ backend + network error)
    const errorCard = document.getElementById("errorCardMatcher");
    const errorMsg = document.getElementById("errorMsgMatcher");

    // ─── Validate định dạng PEM (real-time, chỉ kiểm tra cú pháp) ────────────
    function validatePEM(input, expectedType) {
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

        // Kiểm tra dữ liệu thừa bên ngoài khối PEM (normalize trước khi so sánh)
        if (val.trim() !== matches[0][0].trim()) {
            return `Có ký tự thừa bên ngoài khối PEM — vui lòng xóa chúng.`;
        }

        // Quét từng dòng raw: mọi dòng bên trong block phải <= 64 ký tự
        const rawLines = val.split("\n").map(l => l.replace("\r", "").trimEnd());
        let insideBlock = false;
        for (let i = 0; i < rawLines.length; i++) {
            const line = rawLines[i];
            if (line.startsWith("-----BEGIN")) { insideBlock = true; continue; }
            if (line.startsWith("-----END"))   { insideBlock = false; continue; }
            if (insideBlock && line.length > 64) {
                return `Dòng ${i + 1} có ${line.length} ký tự (tối đa 64 mỗi dòng) — có ký tự bị chèn thêm.`;
            }
        }

        // Kiểm tra Base64 hợp lệ
        const b64 = matches[0][0]
            .replace(/-----BEGIN[^-]*-----/, "")
            .replace(/-----END[^-]*-----/, "")
            .replace(/\s+/g, "");

        if (!/^[A-Za-z0-9+/]+=*$/.test(b64)) {
            return `Nội dung Base64 trong ${typeName} chứa ký tự không hợp lệ.`;
        }

        // Kiểm tra độ dài tối thiểu Base64
        // RSA 2048 ~ 1700 chars; EC P-256 ~ 160 chars; ngưỡng 100 để cover cả EC
        const minLength = expectedType === "CERTIFICATE" ? 800 : expectedType === "CSR" ? 200 : 100;
        if (b64.replace(/=/g, "").length < minLength) {
            return `Nội dung ${typeName} quá ngắn (ít hơn ${minLength} ký tự Base64) — có thể bị copy thiếu.`;
        }

        return null; // OK về mặt định dạng
    }

    // ─── Cập nhật nhãn và xóa state khi đổi mode ─────────────────────────────
    function updateLabels() {
        if (!lblBox1 || !lblBox2) return;

        box1.value = "";
        box2.value = "";

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

        const mode = document.querySelector('input[name="matcherMode"]:checked').value;
        const type1 = mode === "cert_key" ? "KEY" : "CSR";
        const type2 = "CERTIFICATE";

        const val1 = box1.value;
        const val2 = box2.value;

        // Khi ô rỗng: clear lỗi cũ
        if (!val1.trim()) {
            box1.classList.remove("is-invalid");
            if (errBox1) setDisplay(errBox1, "none");
        }
        if (!val2.trim()) {
            box2.classList.remove("is-invalid");
            if (errBox2) setDisplay(errBox2, "none");
        }

        const error1 = validatePEM(val1, type1);
        const error2 = validatePEM(val2, type2);

        // Inline error Box 1
        if (error1) {
            box1.classList.add("is-invalid");
            if (errBox1) setDisplay(errBox1, "block");
            if (errMsg1) errMsg1.textContent = error1;
        } else if (val1.trim()) {
            box1.classList.remove("is-invalid");
            if (errBox1) setDisplay(errBox1, "none");
        }

        // Inline error Box 2
        if (error2) {
            box2.classList.add("is-invalid");
            if (errBox2) setDisplay(errBox2, "block");
            if (errMsg2) errMsg2.textContent = error2;
        } else if (val2.trim()) {
            box2.classList.remove("is-invalid");
            if (errBox2) setDisplay(errBox2, "none");
        }

        btnSubmit.disabled = !!(error1 || error2 || !val1.trim() || !val2.trim());
    }

    // ─── Xử lý submit ────────────────────────────────────────────────────────
    if (form) {
        form.addEventListener("submit", async (e) => {
            e.preventDefault();

            const mode = document.querySelector('input[name="matcherMode"]:checked').value;
            const input1 = box1.value.trim();
            const input2 = box2.value.trim();

            setDisplay(resultCard, "none");
            setDisplay(errorCard, "none");
            setElementsEnabled([box1, box2, btnSubmit], false);
            toggleLoading(btnSubmit, iconNormal, iconLoading, true);

            let hasInputErrors = false;

            try {
                const response = await fetch(`${API_BASE_URL}/ssl/key-matcher/match`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ type: mode, input1, input2 }),
                });

                const data = await response.json();

                if (!response.ok) {
                    showError(errorCard, errorMsg, data.error || "Lỗi hệ thống không xác định.", [resultCard]);
                    return;
                }

                // Phân loại response theo input_errors:
                // - input_errors != null → lỗi parse/wrong-type → hiện inline dưới từng ô
                // - null → khớp hoặc không khớp → hiện resultCard
                if (data.input_errors) {
                    hasInputErrors = true;
                    handleInputErrors(data);
                } else {
                    renderResult(data);
                }

            } catch (err) {
                showError(errorCard, errorMsg, "Không thể kết nối đến máy chủ. Vui lòng thử lại.", [resultCard]);
            } finally {
                toggleLoading(btnSubmit, iconNormal, iconLoading, false);
                // Re-enable textarea để user có thể sửa, nhưng giữ nút khoá nếu có lỗi
                setElementsEnabled([box1, box2], true);
                btnSubmit.disabled = hasInputErrors;
            }
        });
    }

    // ─── Hiện lỗi parse từ backend vào đúng inline card của từng ô ──────────
    function handleInputErrors(data) {
        // Clear hoặc set lỗi cho box1
        if (data.input_errors?.input1) {
            box1.classList.add("is-invalid");
            if (errBox1) setDisplay(errBox1, "block");
            if (errMsg1) errMsg1.textContent = data.input_errors.input1;
        } else {
            box1.classList.remove("is-invalid");
            if (errBox1) setDisplay(errBox1, "none");
        }

        // Clear hoặc set lỗi cho box2
        if (data.input_errors?.input2) {
            box2.classList.add("is-invalid");
            if (errBox2) setDisplay(errBox2, "block");
            if (errMsg2) errMsg2.textContent = data.input_errors.input2;
        } else {
            box2.classList.remove("is-invalid");
            if (errBox2) setDisplay(errBox2, "none");
        }
        // Không hiện errorCard tổng — inline errors đã đủ rõ ràng
    }

    // ─── Render kết quả khớp / không khớp vào #resultCardMatcher ─────────────
    function renderResult(data) {
        setDisplay(resultCard, "block");

        const isMatched = data.matched;
        const colorClass = isMatched ? "success" : "error";
        const iconClass  = isMatched ? "fa-check" : "fa-xmark";

        resultTitle.style.textAlign = "center";
        resultTitle.style.width = "100%";

        resultTitle.innerHTML = `
            <div class="d-flex flex-col items-center justify-center w-full py-4">
                <div class="bg-${colorClass} text-white rounded-full d-flex items-center justify-center shadow-lg"
                     style="width: 72px; height: 72px; font-size: 2.5rem; margin-bottom: 1.25rem;">
                    <i class="fa-solid ${iconClass}"></i>
                </div>
                <div class="text-${colorClass} font-bold uppercase" style="font-size: 1.75rem;">${escapeHTML(data.status)}</div>
                <p class="text-primary font-medium mt-1 font-sans">${escapeHTML(data.message)}</p>
            </div>
        `;

        const currentMode = document.querySelector('input[name="matcherMode"]:checked')?.value;
        const label1 = currentMode === "csr_cert" ? "CSR Hash (Public Key SHA-256)" : "Private Key Hash (Public Key SHA-256)";
        const label2 = "Certificate Hash (Public Key SHA-256)";

        if (isMatched) {
            resultBody.innerHTML = `
                <div style="border-top: 1px solid var(--color-border); padding-top: 1.5rem; margin-top: 0.5rem;">
                    <div class="d-flex items-center justify-center gap-2 mb-6 p-2">
                        <i class="fa-solid fa-circle-check text-success"></i>
                        <span class="font-semibold text-secondary">Loại khóa:</span>
                        <span class="font-bold text-primary">${escapeHTML(data.key_type)} / ${escapeHTML(String(data.key_size))} bits</span>
                    </div>
                    <div class="ssl-checker__result-group p-4 rounded-lg" style="background-color: var(--color-surface-muted); border: 1px solid var(--color-border-subtle);">
                        <div class="ssl-checker__result-row" style="border-bottom: 1px dashed var(--color-border); padding-bottom: 0.75rem; margin-bottom: 0.75rem; flex-direction: column; gap: 0.25rem;">
                            <h5 class="ssl-checker__result-label" style="min-width: unset; width: unset;">${escapeHTML(label1)}:</h5>
                            <span class="ssl-checker__result-value font-mono text-xs break-all text-secondary">${escapeHTML(data.hash1)}</span>
                        </div>
                        <div class="ssl-checker__result-row" style="padding-top: 0.75rem; border: none; margin-bottom: 0; flex-direction: column; gap: 0.25rem;">
                            <h5 class="ssl-checker__result-label" style="min-width: unset; width: unset;">${escapeHTML(label2)}:</h5>
                            <span class="ssl-checker__result-value font-mono text-xs break-all text-secondary">${escapeHTML(data.hash2)}</span>
                        </div>
                    </div>
                </div>
            `;
        } else {
            resultBody.innerHTML = `
                <div style="border-top: 1px solid var(--color-border); padding-top: 1.5rem; margin-top: 0.5rem;">
                    <div class="ssl-checker__result-group p-4 rounded-lg" style="background-color: var(--color-surface-muted); border: 1px solid var(--color-border-subtle);">
                        <div class="ssl-checker__result-row" style="border-bottom: 1px dashed var(--color-border); padding-bottom: 0.75rem; margin-bottom: 0.75rem; flex-direction: column; gap: 0.25rem;">
                            <h5 class="ssl-checker__result-label text-error" style="min-width: unset; width: unset;">${escapeHTML(label1)}:</h5>
                            <span class="ssl-checker__result-value font-mono text-xs break-all text-error">${escapeHTML(data.hash1 || "—")}</span>
                        </div>
                        <div class="ssl-checker__result-row" style="padding-top: 0; border: none; margin-bottom: 0; flex-direction: column; gap: 0.25rem;">
                            <h5 class="ssl-checker__result-label text-error" style="min-width: unset; width: unset;">${escapeHTML(label2)}:</h5>
                            <span class="ssl-checker__result-value font-mono text-xs break-all text-error">${escapeHTML(data.hash2 || "—")}</span>
                        </div>
                    </div>
                </div>
            `;
        }

        resultCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    // ─── Event listeners ─────────────────────────────────────────────────────
    if (radioCertKey && radioCsrCert) {
        radioCertKey.addEventListener("change", updateLabels);
        radioCsrCert.addEventListener("change", updateLabels);
    }

    if (box1 && box2) {
        box1.addEventListener("input", checkValidations);
        box2.addEventListener("input", checkValidations);
    }

    updateLabels();
}

document.addEventListener("DOMContentLoaded", initKeyMatcherUI);
