import {
    toggleLoading,
    setDisplay,
    setElementsEnabled,
    showError,
} from "../../../utils/index.js";
import { API_BASE_URL } from "../../../config.js";

/**
 * SSL Converter Module
 * Refactored to be robust against browser gesture timeouts
 */
export function init() {
    const form = document.getElementById("formConverter");
    if (!form) return;

    // --- DOM Selections ---
    const selectCurrent = document.getElementById("currentCertFormat");
    const selectTarget = document.getElementById("targetCertFormat");
    const inputCert = document.getElementById("inputFileCertificate");
    const inputKey = document.getElementById("inputFilePrivateKey");
    const inputChain1 = document.getElementById("inputFileChain1");
    const inputChain2 = document.getElementById("inputFileChain2");
    const inputPfxPw = document.getElementById("inputPfxPassword");

    const btnSubmit = document.getElementById("btnConvertCertificate");
    const iconNormal = document.getElementById("btnConvertCertificateIcon");
    const iconLoading = document.getElementById("btnConvertCertificateLoading");

    const groupKey = document.getElementById("groupPrivateKey");
    const groupChain = [document.getElementById("groupChain1"), document.getElementById("groupChain2")];
    const groupPfxPassword = document.getElementById("groupPfxPassword");
    const groupPfxWarning = document.getElementById("groupPfxWarning");

    const mainErrorCard = document.getElementById("toolErrorConverter");
    const mainSuccessCard = document.getElementById("toolSuccessConverter");

    // --- Configuration ---
    const MAX_FILE_SIZE = 1024 * 1024; // Increases to 1MB
    const TARGET_OPTIONS = {
        "pem": ["der", "p7b", "pfx"],
        "der": ["pem"],
        "p7b": ["pem", "pfx"],
        "pfx": ["pem"]
    };
    const LABELS = { "pem": "Standard PEM", "der": "DER / Binary", "p7b": "PKCS#7 / P7B", "pfx": "PKCS#12 / PFX" };

    // --- UI Logic ---
    function updateVisibility() {
        const current = selectCurrent.value;
        const target = selectTarget.value;

        // Private Key only needed for PFX target
        setDisplay(groupKey, target === "pfx" ? "block" : "none");
        
        // Chains needed for PFX or P7B targets
        const showChain = (target === "pfx" || target === "p7b");
        groupChain.forEach(el => setDisplay(el, showChain ? "block" : "none"));

        // Password needed if Source OR Target is PFX
        const needsPw = (current === "pfx" || target === "pfx");
        setDisplay(groupPfxPassword, needsPw ? "block" : "none"); // Changed to block for consistency
        setDisplay(groupPfxWarning, needsPw ? "block" : "none");
    }

    function syncTargetOptions() {
        const current = selectCurrent.value;
        const allowed = TARGET_OPTIONS[current] || [];
        const oldVal = selectTarget.value;

        selectTarget.innerHTML = "";
        allowed.forEach(val => {
            const opt = document.createElement("option");
            opt.value = val;
            opt.textContent = LABELS[val];
            selectTarget.appendChild(opt);
        });

        if (allowed.includes(oldVal)) selectTarget.value = oldVal;
        updateVisibility();
    }

    // --- Result Reset ---
    function clearResults() {
        setDisplay(mainErrorCard, "none");
        if (mainSuccessCard) setDisplay(mainSuccessCard, "none");
        const downloadArea = document.getElementById("converterDownloadArea");
        if (downloadArea) setDisplay(downloadArea, "none");
    }

    // --- Download Helper ---
    async function triggerDownload(base64Data, filename, contentType) {
        try {
            const byteCharacters = atob(base64Data);
            const byteNumbers = new Array(byteCharacters.length);
            for (let i = 0; i < byteCharacters.length; i++) {
                byteNumbers[i] = byteCharacters.charCodeAt(i);
            }
            const byteArray = new Uint8Array(byteNumbers);
            const blob = new Blob([byteArray], { type: contentType });

            // 1. Update UI manual download area if exists
            const downloadArea = document.getElementById("converterDownloadArea");
            const filenameDisplay = document.getElementById("converterFilenameDisplay");
            const btnManual = document.getElementById("btnManualDownload");

            if (downloadArea && filenameDisplay && btnManual) {
                filenameDisplay.textContent = filename || "certificate.der";
                setDisplay(downloadArea, "block");
                
                // Clear old listeners to avoid multiple downloads
                const newBtn = btnManual.cloneNode(true);
                btnManual.parentNode.replaceChild(newBtn, btnManual);
                
                newBtn.addEventListener("click", async () => {
                    await handleSaveAs(blob, filename);
                });
            }

            // 2. Show Success UI only
            // We no longer trigger an automated silent download to avoid 
            // duplicate downloads and the "UUID filename" issue.
            // The user will click the manual button to trigger a clean Save As dialog.
            return true;
        } catch (err) {
            console.error("Download trigger failed:", err);
            return false;
        }
    }

    async function handleSaveAs(blob, filename, silent = false) {
        // Modern File System Access API
        if (window.showSaveFilePicker && !silent) {
            try {
                const handle = await window.showSaveFilePicker({
                    suggestedName: filename || "certificate.der",
                    types: [{
                        description: 'SSL Certificate File',
                        accept: { [blob.type || 'application/octet-stream']: ['.crt', '.pem', '.der', '.pfx', '.p7b'] },
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
        a.download = filename || "certificate.der";
        document.body.appendChild(a);
        a.click();
        
        setTimeout(() => {
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);
        }, 1000);
    }

    // --- Form Submision ---
    form.addEventListener("submit", async (e) => {
        e.preventDefault();

        const formData = new FormData();
        formData.append("currentFormat", selectCurrent.value);
        formData.append("targetFormat", selectTarget.value);
        
        if (inputCert.files[0]) formData.append("certificate", inputCert.files[0]);
        if (inputKey.files[0]) formData.append("privateKey", inputKey.files[0]);
        if (inputChain1.files[0]) formData.append("chain1", inputChain1.files[0]);
        if (inputChain2.files[0]) formData.append("chain2", inputChain2.files[0]);
        if (inputPfxPw.value) formData.append("pfxPassword", inputPfxPw.value);

        // UI Reset
        setDisplay(mainErrorCard, "none");
        if (mainSuccessCard) setDisplay(mainSuccessCard, "none");
        const downloadArea = document.getElementById("converterDownloadArea");
        if (downloadArea) setDisplay(downloadArea, "none");

        try {
            toggleLoading(btnSubmit, iconNormal, iconLoading, true);
            setElementsEnabled([btnSubmit, selectCurrent, selectTarget, inputCert, inputPfxPw], false);

            const response = await fetch(`${API_BASE_URL}/ssl/converter/convert`, {
                method: "POST",
                body: formData
            });

            const result = await response.json();
            console.log("Converter API Response:", result);

            // Logic check: ưu tiên response.ok và bọc dữ liệu trong .data
            if (!response.ok || (result.success === false)) {
                const errMsg = result.error || result.message || "Quá trình chuyển đổi thất bại. Vui lòng kiểm tra lại tệp và mật khẩu.";
                throw new Error(errMsg);
            }

            // SUCCESS - Lấy dữ liệu từ result.data (do backend đã bọc APIResponse)
            const payload = result.data || result; 
            const { filename, data, contentType } = payload;
            
            const ok = await triggerDownload(data, filename, contentType);

            if (ok) {
                if (mainSuccessCard) {
                    setDisplay(mainSuccessCard, "block");
                    mainSuccessCard.scrollIntoView({ behavior: "smooth", block: "center" });
                }
                // Clear password for security
                if (inputPfxPw) inputPfxPw.value = "";
            } else {
                throw new Error("Không thể tạo tệp tải về trên trình duyệt này.");
            }

        } catch (err) {
            showError(mainErrorCard, mainErrorCard.querySelector(".message-card__message"), err.message);
            if (mainSuccessCard) setDisplay(mainSuccessCard, "none");
        } finally {
            toggleLoading(btnSubmit, iconNormal, iconLoading, false);
            setElementsEnabled([btnSubmit, selectCurrent, selectTarget, inputCert, inputPfxPw], true);
        }
    });

    // --- Init ---
    selectCurrent.addEventListener("change", () => {
        syncTargetOptions();
        clearResults();
    });
    selectTarget.addEventListener("change", () => {
        updateVisibility();
        clearResults();
    });

    [inputCert, inputKey, inputChain1, inputChain2, inputPfxPw].forEach(input => {
        if (!input) return;
        const eventType = input.tagName === "INPUT" && input.type === "file" ? "change" : "input";
        input.addEventListener(eventType, clearResults);
    });

    syncTargetOptions();
}

document.addEventListener("DOMContentLoaded", init);
