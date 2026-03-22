import { isValidHostname } from "../../../utils/validation.js";
import { API_BASE_URL } from "../../../config.js";

document.addEventListener("DOMContentLoaded", () => {
    const form = document.getElementById("formCsrGenerator");
    if (!form) return;

    // Các thành phần UI
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

    // --- Lắng nghe thay đổi toàn form để xoá Card lỗi & Kết quả ---
    function hideToolCards() {
        const toolResultCard = document.getElementById("toolResultCsrGenerator");
        const toolErrorCard = document.getElementById("toolErrorCsrGenerator");
        if (toolResultCard) toolResultCard.classList.add("d-none");
        if (toolErrorCard) toolErrorCard.classList.add("d-none");
    }
    form.addEventListener("input", hideToolCards);
    form.addEventListener("change", hideToolCards);

    // --- Helper Validation CSR ---
    function isValidCN(raw) {
        if (!raw) return false;
        const val = raw.trim();
        const stripped = val.startsWith("*.") ? val.slice(2) : val;
        return isValidHostname(stripped);
    }

    function checkToggleSubmitBtn() {
        if (!domainInput || !btnGenerate) return;
        const cnVal = domainInput.value.trim();
        // Nút bị vô hiệu hóa nếu Common Name rỗng hoặc sai chuẩn
        btnGenerate.disabled = !(cnVal.length > 0 && isValidCN(cnVal));
    }

    function validateSANsRealtime() {
        if (!sansInput) return true;
        const sansVal = sansInput.value.trim();
        
        if (!sansVal) {
            sansInput.classList.remove("is-invalid");
            if (sansErrorCard) sansErrorCard.classList.add("d-none");
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
        if (sansErrorCard) sansErrorCard.classList.add("d-none");
        return true;
    }

    // --- 1. Gắn Events Realtime Validation ---

    // Domain (CN) Realtime
    if (domainInput) {
        const checkDomain = () => {
            const val = domainInput.value.trim();
            const valid = val.length > 0 && isValidCN(val);

            if (!valid && val.length > 0) {
                domainInput.classList.add("is-invalid");
                if (domainError) domainError.classList.remove("d-none");
            } else {
                domainInput.classList.remove("is-invalid");
                if (domainError) domainError.classList.add("d-none");
            }

            checkToggleSubmitBtn();
        };

        domainInput.addEventListener("input", checkDomain);
        domainInput.addEventListener("paste", () => setTimeout(() => domainInput.dispatchEvent(new Event("input")), 0));
        
        // Kích hoạt check 1 lần ngay từ đầu phục hồi UI Disabled Button sau khi Auto-fill
        checkToggleSubmitBtn();
    }

    // SANs Realtime
    if (sansInput) {
        sansInput.addEventListener("input", validateSANsRealtime);
        sansInput.addEventListener("blur", validateSANsRealtime);
        sansInput.addEventListener("paste", () => setTimeout(() => sansInput.dispatchEvent(new Event("input")), 0));
    }

    // Country Realtime & Auto-Uppercase
    if (countryInput) {
        countryInput.addEventListener("input", (e) => {
            let val = e.target.value;
            if (val !== val.toUpperCase()) {
                val = val.toUpperCase();
                e.target.value = val;
            }

            val = val.trim();
            if (val.length > 0 && (val.length !== 2 || !/^[A-Z]{2}$/.test(val))) {
                countryInput.classList.add("is-invalid");
                if (countryError) countryError.classList.remove("d-none");
            } else {
                countryInput.classList.remove("is-invalid");
                if (countryError) countryError.classList.add("d-none");
            }
        });
    }

    // --- 2. Xử lý logic switch Loại khóa (RSA / ECDSA) ---
    keyTypeRadios.forEach(radio => {
        radio.addEventListener("change", (e) => {
            const val = e.target.value;
            if (val === "rsa") {
                if (groupRsa) groupRsa.classList.remove("d-none");
                if (groupEcdsa) groupEcdsa.classList.add("d-none");
                if (hintEcdsaRsa) hintEcdsaRsa.textContent = "RSA 2048-bit: phổ biến nhất, tương thích cao. 4096-bit: bảo mật hơn nhưng chậm hơn.";

                const defaultRsa = groupRsa?.querySelector('input[value="2048"]');
                if (defaultRsa) defaultRsa.checked = true;

            } else if (val === "ecdsa") {
                if (groupEcdsa) groupEcdsa.classList.remove("d-none");
                if (groupRsa) groupRsa.classList.add("d-none");
                if (hintEcdsaRsa) hintEcdsaRsa.textContent = "ECDSA nhanh hơn, tốn ít tài nguyên thẻ hơn và cực kỳ bảo mật.";

                const defaultEcdsa = groupEcdsa?.querySelector('input[value="256"]');
                if (defaultEcdsa) defaultEcdsa.checked = true;
            }
        });
    });

    // --- 3. Xử lý Submit Form ---
    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        // Validate Common Name (Bắt buộc)
        const cnVal = domainInput ? domainInput.value.trim() : "";
        if (!cnVal || !isValidCN(cnVal)) {
            if (domainInput) domainInput.classList.add("is-invalid");
            if (domainError) domainError.classList.remove("d-none");
            if (domainInput) domainInput.focus();
            return;
        }

        // Validate Country (Tùy chọn, nhưng nếu có nhập phải đúng 2 ký tự)
        if (countryInput) {
            const countryVal = countryInput.value.trim();
            if (countryVal && (countryVal.length !== 2 || !/^[A-Za-z]{2}$/.test(countryVal))) {
                countryInput.classList.add("is-invalid");
                if (countryError) countryError.classList.remove("d-none");
                countryInput.focus();
                return;
            }
        }

        // Validate SANs
        if (!validateSANsRealtime()) {
            if (sansInput) sansInput.focus();
            return;
        }

        // Bắt đầu Loading State UI
        if (btnGenerate) btnGenerate.disabled = true;
        if (iconGenerateCsr) iconGenerateCsr.classList.add("d-none");
        if (iconGenerateCsrLoading) iconGenerateCsrLoading.classList.remove("d-none");
        
        try {
            // Chuẩn bị mảng SANs hợp chuẩn API []string
            const sansValue = sansInput ? sansInput.value.trim() : "";
            const sansArray = sansValue ? sansValue.split(",").map(s => s.trim()).filter(Boolean) : [];

            // Thu thập cấu hình khóa
            const keyTypeRadio = document.querySelector('input[name="keyType"]:checked');
            const keyType = keyTypeRadio ? keyTypeRadio.value : "rsa";
            const keySizeSelector = keyType === "rsa" ? 'input[name="keySizeRsa"]:checked' : 'input[name="keySizeEcdsa"]:checked';
            const keySizeRadio = document.querySelector(keySizeSelector);
            const keySize = keySizeRadio ? parseInt(keySizeRadio.value, 10) : (keyType === "rsa" ? 2048 : 256);

            const payload = {
                domainName: cnVal,
                sans: sansArray,
                country: countryInput ? countryInput.value.trim() : "",
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

            // Gán dữ liệu lên Result Card
            const toolResultCard = document.getElementById("toolResultCsrGenerator");
            const resultBody = document.getElementById("resultCsrGeneratorContent");
            const toolErrorCard = document.getElementById("toolErrorCsrGenerator");

            if (toolErrorCard) toolErrorCard.classList.add("d-none");
            
            if (toolResultCard && resultBody) {
                resultBody.innerHTML = `
                    <div class="result-card__item mb-4 bg-gray-50 rounded-md border border-gray-100 shadow-sm mt-4">
                        <div class="grid grid-cols-1 md-grid-cols-2 w-full" style="gap: 1.5rem;">
                            <div class="code-block w-full" style="width: 100%; max-width: 100%; overflow: hidden;">
                                <div class="code-block__header">
                                    <span class="code-block__lang text-brand font-bold">
                                        <i class="fa-solid fa-file-shield text-brand mr-2"></i> Certificate Signing Request
                                    </span>
                                    <button class="code-block__btn-copy js-copy-code font-bold text-gray-500 hover:text-gray-900" type="button" data-clipboard-target="#generatedCsrCode">
                                        <i class="fa-regular fa-clone mr-2"></i> Copy CSR
                                    </button>
                                </div>
                                <pre class="code-block__pre rounded-b-md" style="width: 100%; max-width: 100%; margin: 0; padding: 1rem; overflow-x: auto; background-color: var(--color-gray-50);"><code id="generatedCsrCode" class="font-mono text-xs" style="white-space: pre;">${result.data.csr}</code></pre>
                            </div>
                            <div class="code-block w-full" style="width: 100%; max-width: 100%; overflow: hidden;">
                                <div class="code-block__header">
                                    <span class="code-block__lang text-danger font-bold">
                                        <i class="fa-solid fa-key text-danger mr-2"></i> Private Key
                                    </span>
                                    <button class="code-block__btn-copy js-copy-code font-bold text-gray-500 hover:text-gray-900" type="button" data-clipboard-target="#generatedPrivateKey">
                                        <i class="fa-regular fa-clone mr-2"></i> Copy Private Key
                                    </button>
                                </div>
                                <pre class="code-block__pre rounded-b-md" style="width: 100%; max-width: 100%; margin: 0; padding: 1rem; overflow-x: auto; background-color: var(--color-gray-50);"><code id="generatedPrivateKey" class="font-mono text-xs" style="white-space: pre;">${result.data.privateKey}</code></pre>
                            </div>
                        </div>
                    </div>
                `;

                toolResultCard.classList.remove("d-none");
                toolResultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }

        } catch (error) {
            console.error("Lỗi khi tạo CSR:", error);
            const toolErrorCard = document.getElementById("toolErrorCsrGenerator");
            const toolErrorMsg = document.getElementById("toolErrorCsrGeneratorMessage");
            const toolResultCard = document.getElementById("toolResultCsrGenerator");

            if (toolResultCard) toolResultCard.classList.add("d-none");
            if (toolErrorCard && toolErrorMsg) {
                toolErrorMsg.textContent = error.message;
                toolErrorCard.classList.remove("d-none");
                toolErrorCard.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        } finally {
            // Trả lại trạng thái UI cho người dùng để có thể tương tác lại.
            if (btnGenerate) btnGenerate.disabled = false;
            if (iconGenerateCsr) iconGenerateCsr.classList.remove("d-none");
            if (iconGenerateCsrLoading) iconGenerateCsrLoading.classList.add("d-none");
        }
    });
});
