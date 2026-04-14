import { isValidHostname } from "../../../utils/validation.js";
import { API_BASE_URL } from "../../../config.js";
import { 
    copyToClipboard, 
    toggleLoading, 
    setElementsEnabled,
    hide
} from "../../../utils/dom.js";

/**
 * SSL CSR Generator Module
 * Hardened & Refactored version
 */
function init() {
    const form = document.getElementById("formCsrGenerator");
    if (!form) return;

    // --- UI Elements ---
    const keyTypeRadios = form.querySelectorAll('input[name="keyType"]');
    const groupRsa = document.getElementById("keySizeRsa");
    const groupEcdsa = document.getElementById("keySizeEcdsa");
    const hintEcdsaRsa = document.getElementById("keySizeHint");
    const countryInput = document.getElementById("inputCsrCountry");
    const countryError = document.getElementById("countryValidationError");
    const btnGenerate = document.getElementById("btnGenerateCsr");
    const iconGenerateCsr = document.getElementById("iconGenerateCsr");
    const iconGenerateCsrLoading = document.getElementById("iconGenerateCsrLoading");
    const domainInput = document.getElementById("inputCsrDomain");
    const domainError = document.getElementById("csrDomainValidationError");
    const sansInput = document.getElementById("inputCsrSans");
    const sansErrorCard = document.getElementById("sansValidationError");
    const sansErrorMsg = document.getElementById("sansValidationMessage");

    const toolResultCard = document.getElementById("toolResultCsrGenerator");
    const resultBody = document.getElementById("resultCsrGeneratorContent");
    const toolErrorCard = document.getElementById("toolErrorCsrGenerator");
    const toolErrorMsg = document.getElementById("toolErrorCsrGeneratorMessage");

    // --- Helper Functions ---

    /**
     * Standard Save As / Download Helper
     */
    async function handleSaveAs(content, filename, contentType = "text/plain") {
        const blob = new Blob([content], { type: contentType });

        // Modern File System Access API
        if (window.showSaveFilePicker) {
            try {
                const handle = await window.showSaveFilePicker({
                    suggestedName: filename,
                    types: [{
                        description: 'SSL File',
                        accept: { [contentType]: [`.${filename.split('.').pop()}`] },
                    }],
                });
                const writable = await handle.createWritable();
                await writable.write(blob);
                await writable.close();
                return;
            } catch (err) {
                if (err.name === 'AbortError') return;
                console.warn("showSaveFilePicker failed, falling back to <a> tag:", err);
            }
        }

        // Standard Fallback
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.style.display = "none";
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        
        setTimeout(() => {
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }, 1000);
    }

    /**
     * Clear result/error cards on input change
     */
    function clearUIState() {
        if (toolResultCard) hide(toolResultCard);
        if (toolErrorCard) hide(toolErrorCard);
        const downloadArea = document.getElementById("csrDownloadArea");
        if (downloadArea) hide(downloadArea);
    }

    function isValidCN(raw) {
        if (!raw) return false;
        const val = raw.trim();
        const stripped = val.startsWith("*.") ? val.slice(2) : val;
        return isValidHostname(stripped);
    }

    function updateSubmitBtnState() {
        if (!domainInput || !btnGenerate) return;
        const cnVal = domainInput.value.trim();
        btnGenerate.disabled = !(cnVal.length > 0 && isValidCN(cnVal));
    }

    function validateSANsRealtime() {
        if (!sansInput) return true;
        const sansVal = sansInput.value.trim();
        
        if (!sansVal) {
            sansInput.classList.remove("is-invalid");
            if (sansErrorCard) hide(sansErrorCard);
            return true;
        }

        const items = sansVal.split(",").map(s => s.trim()).filter(Boolean);
        const invalid = items.filter(item => !isValidCN(item));

        if (invalid.length > 0) {
            sansInput.classList.add("is-invalid");
            if (sansErrorCard) {
                sansErrorCard.classList.remove("d-none");
                if (sansErrorMsg) sansErrorMsg.textContent = `SANs không hợp lệ: ${invalid.join(", ")}`;
            }
            return false;
        }

        if (items.length > 100) {
            sansInput.classList.add("is-invalid");
            if (sansErrorCard) {
                sansErrorCard.classList.remove("d-none");
                if (sansErrorMsg) sansErrorMsg.textContent = `Tối đa 100 SANs. Bạn đang nhập ${items.length} SANs.`;
            }
            return false;
        }

        sansInput.classList.remove("is-invalid");
        if (sansErrorCard) hide(sansErrorCard);
        return true;
    }

    /**
     * Render the generated results (CSR & Private Key)
     */
    function renderGeneratorResult(data, hostname) {
        if (!resultBody) return;

        resultBody.innerHTML = `
            <div class="csr-generator__result-wrapper mt-4 px-6">
                <div class="grid grid-cols-1 md-grid-cols-2 gap-4">
                    <!-- CSR Block -->
                    <div class="code-block">
                        <div class="code-block__header">
                            <span class="code-block__lang text-brand">
                                <i class="fa-solid fa-file-shield mr-2"></i> CSR
                            </span>
                            <div class="code-block__actions d-flex gap-1">
                                <button class="code-block__btn-copy js-copy-csr" title="Copy CSR">
                                    <i class="fa-regular fa-clone"></i>
                                </button>
                                <button class="code-block__btn-download js-download-csr" title="Download CSR (Save As)">
                                    <i class="fa-solid fa-download"></i>
                                </button>
                            </div>
                        </div>
                        <div class="code-block__body">
                            <code class="code-block__text text-xs" id="outputCsr">${data.csr}</code>
                        </div>
                    </div>

                    <!-- Private Key Block -->
                    <div class="code-block">
                        <div class="code-block__header">
                            <span class="code-block__lang text-error">
                                <i class="fa-solid fa-key mr-2"></i> Private Key
                            </span>
                            <div class="code-block__actions d-flex gap-1">
                                <button class="code-block__btn-copy js-copy-key" title="Copy Private Key">
                                    <i class="fa-regular fa-clone"></i>
                                </button>
                                <button class="code-block__btn-download js-download-key" title="Download Private Key (Save As)">
                                    <i class="fa-solid fa-download"></i>
                                </button>
                            </div>
                        </div>
                        <div class="code-block__body">
                            <code class="code-block__text text-xs" id="outputKey">${data.privateKey}</code>
                        </div>
                    </div>
                </div>
                
                <div class="message-card message-card--warning mt-4">
                    <div class="message-card__header">
                        <h4 class="message-card__title">
                            <i class="fa-solid fa-triangle-exclamation"></i>
                            Lưu ý bảo mật
                        </h4>
                    </div>
                    <div class="message-card__body">
                        <p class="message-card__message">
                            Chúng tôi không lưu trữ Private Key của bạn. Vui lòng tải xuống hoặc lưu lại an toàn ngay bây giờ. Nếu mất khóa này, bạn sẽ không thể cài đặt chứng chỉ SSL.
                        </p>
                    </div>
                </div>
            </div>
        `;

        // Attach Download events
        const btnDownloadCsr = resultBody.querySelector(".js-download-csr");
        const btnDownloadKey = resultBody.querySelector(".js-download-key");

        btnDownloadCsr?.addEventListener("click", () => {
            handleSaveAs(data.csr, `${hostname}.csr`, "application/x-pem-file");
        });

        btnDownloadKey?.addEventListener("click", () => {
            handleSaveAs(data.privateKey, `${hostname}.key`, "application/x-pem-file");
        });

        // Attach Copy events
        const btnCopyCsr = resultBody.querySelector(".js-copy-csr");
        const btnCopyKey = resultBody.querySelector(".js-copy-key");

        btnCopyCsr?.addEventListener("click", async () => {
            const success = await copyToClipboard(data.csr);
            if (success) {
                const icon = btnCopyCsr.querySelector("i");
                icon.className = "fa-solid fa-check text-success";
                setTimeout(() => icon.className = "fa-regular fa-clone", 2000);
            }
        });

        btnCopyKey?.addEventListener("click", async () => {
            const success = await copyToClipboard(data.privateKey);
            if (success) {
                const icon = btnCopyKey.querySelector("i");
                icon.className = "fa-solid fa-check text-success";
                setTimeout(() => icon.className = "fa-regular fa-clone", 2000);
            }
        });

        if (toolResultCard) {
            toolResultCard.classList.remove("d-none");
            toolResultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }

    // --- Event Listeners ---

    form.addEventListener("input", clearUIState);
    form.addEventListener("change", clearUIState);

    if (domainInput) {
        domainInput.addEventListener("input", () => {
            const val = domainInput.value.trim();
            const valid = val.length > 0 && isValidCN(val);

            domainInput.classList.toggle("is-invalid", !valid && val.length > 0);
            if (domainError) domainError.classList.toggle("d-none", valid || val.length === 0);

            updateSubmitBtnState();
        });
        updateSubmitBtnState(); // Initial check
    }

    if (sansInput) {
        sansInput.addEventListener("input", validateSANsRealtime);
        sansInput.addEventListener("blur", validateSANsRealtime);
    }

    if (countryInput) {
        countryInput.addEventListener("input", (e) => {
            let val = e.target.value.toUpperCase().trim();
            e.target.value = val;

            const isValid = val.length === 0 || (val.length === 2 && /^[A-Z]{2}$/.test(val));
            countryInput.classList.toggle("is-invalid", !isValid);
            if (countryError) countryError.classList.toggle("d-none", isValid);
        });
    }

    keyTypeRadios.forEach(radio => {
        radio.addEventListener("change", (e) => {
            const val = e.target.value;
            const isRsa = val === "rsa";

            if (groupRsa) groupRsa.classList.toggle("d-none", !isRsa);
            if (groupEcdsa) groupEcdsa.classList.toggle("d-none", isRsa);
            
            if (hintEcdsaRsa) {
                hintEcdsaRsa.textContent = isRsa 
                    ? "RSA 2048-bit: phổ biến nhất, tương thích cao. 4096-bit: bảo mật hơn nhưng chậm hơn."
                    : "ECDSA nhanh hơn, tốn ít tài nguyên hơn và cực kỳ bảo mật.";
            }

            // Set default key size
            if (isRsa) {
                const defaultRsa = groupRsa?.querySelector('input[value="2048"]');
                if (defaultRsa) defaultRsa.checked = true;
            } else {
                const defaultEcdsa = groupEcdsa?.querySelector('input[value="256"]');
                if (defaultEcdsa) defaultEcdsa.checked = true;
            }
        });
    });

    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const cnVal = domainInput?.value.trim() || "";
        if (!cnVal || !isValidCN(cnVal)) {
            domainInput?.focus();
            return;
        }

        if (countryInput) {
            const countryVal = countryInput.value.trim();
            if (countryVal && (countryVal.length !== 2 || !/^[A-Za-z]{2}$/.test(countryVal))) {
                countryInput.focus();
                return;
            }
        }

        if (!validateSANsRealtime()) {
            sansInput?.focus();
            return;
        }

        // Start Loading
        toggleLoading(btnGenerate, iconGenerateCsr, iconGenerateCsrLoading, true);
        
        try {
            const sansValue = sansInput ? sansInput.value.trim() : "";
            const sansArray = sansValue ? sansValue.split(",").map(s => s.trim()).filter(Boolean) : [];

            const keyTypeRadio = form.querySelector('input[name="keyType"]:checked');
            const keyType = keyTypeRadio ? keyTypeRadio.value : "rsa";
            const keySizeSelector = keyType === "rsa" ? 'input[name="keySizeRsa"]:checked' : 'input[name="keySizeEcdsa"]:checked';
            const keySizeRadio = form.querySelector(keySizeSelector);
            const keySize = keySizeRadio ? parseInt(keySizeRadio.value, 10) : (keyType === "rsa" ? 2048 : 256);

            const payload = {
                domainName: cnVal,
                sans: sansArray,
                country: countryInput?.value.trim() || "",
                state: document.getElementById("inputCsrState")?.value.trim() || "",
                locality: document.getElementById("inputCsrLocality")?.value.trim() || "",
                organization: document.getElementById("inputCsrOrg")?.value.trim() || "",
                organizationalUnit: document.getElementById("inputCsrOrgUnit")?.value.trim() || "",
                keyType: keyType,
                keySize: keySize
            };

            const response = await fetch(`${API_BASE_URL}/ssl/generator/csr`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            const result = await response.json();
            if (!response.ok || !result.success) {
                throw new Error(result.message || "Hệ thống gặp sự cố, không thể tạo CSR. Vui lòng thử lại!");
            }

            if (toolErrorCard) hide(toolErrorCard);
            renderGeneratorResult(result.data, cnVal);

        } catch (error) {
            console.error("CSR Generator Error:", error);
            if (toolResultCard) hide(toolResultCard);
            if (toolErrorCard && toolErrorMsg) {
                toolErrorMsg.textContent = error.message;
                toolErrorCard.classList.remove("d-none");
                toolErrorCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        } finally {
            toggleLoading(btnGenerate, iconGenerateCsr, iconGenerateCsrLoading, false);
            setElementsEnabled([domainInput, sansInput, btnGenerate], true);
        }
    });
}

document.addEventListener("DOMContentLoaded", init);

