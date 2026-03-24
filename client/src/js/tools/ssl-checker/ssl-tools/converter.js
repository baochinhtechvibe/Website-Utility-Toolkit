import {
    toggleLoading,
    setDisplay,
    setElementsEnabled,
    showError,
} from "../../../utils/index.js";
import { API_BASE_URL } from "../../../config.js";

document.addEventListener("DOMContentLoaded", () => {
    // ─── DOM Elements ────────────────────────────────────────────────────────
    const form = document.getElementById("formConverter");
    if (!form) return;

    // Selects & Inputs
    const selectCurrent = document.getElementById("currentCertFormat");
    const selectTarget = document.getElementById("targetCertFormat");
    const inputCert = document.getElementById("inputFileCertificate");
    const inputKey = document.getElementById("inputFilePrivateKey");
    const inputChain1 = document.getElementById("inputFileChain1");
    const inputChain2 = document.getElementById("inputFileChain2");
    const inputPfxPw = document.getElementById("inputPfxPassword");

    // Groups
    const groupKey = document.getElementById("groupPrivateKey");
    const groupChain1 = document.getElementById("groupChain1");
    const groupChain2 = document.getElementById("groupChain2");
    const groupPfxPassword = document.getElementById("groupPfxPassword");
    const groupPfxWarning = document.getElementById("groupPfxWarning");

    // Error blocks (we need to inject or use them if they exist)
    const btnSubmit = document.getElementById("btnConvertCertificate");
    const iconNormal = document.getElementById("btnConvertCertificateIcon");
    const iconLoading = document.getElementById("btnConvertCertificateLoading");
    const mainErrorCard = document.getElementById("toolErrorConverter");

    // ─── Validation Constraints ──────────────────────────────────────────────
    const MAX_FILE_SIZE = 512 * 1024; // 512KB

    const allowedExtensions = {
        "pem": [".pem", ".crt", ".cer", ".key"],
        "der": [".der", ".cer"],
        "p7b": [".p7b", ".p7c"],
        "pfx": [".pfx", ".p12"],
    };

    const validTargets = {
        "pem": ["der", "p7b", "pfx"],
        "der": ["pem"],
        "p7b": ["pem", "pfx"],
        "pfx": ["pem"],
    };

    const targetLabels = {
        "pem": "Standard PEM",
        "der": "DER / Binary",
        "p7b": "PKCS#7 / P7B",
        "pfx": "PKCS#12 / PFX"
    };

    // Map: [current→target] → các fields BẮT BUỘC phải có file
    const requiredFields = {
        "pem→der": ["cert"],
        "pem→p7b": ["cert"],           // chain1, chain2 optional
        "pem→pfx": ["cert", "key"],    // chain optional, password required
        "der→pem": ["cert"],
        "p7b→pem": ["cert"],
        "p7b→pfx": ["cert"],           // chain optional, password required 
        "pfx→pem": ["cert"],           // password required
    };

    // ─── State Management ────────────────────────────────────────────────────
    let state = {
        current: selectCurrent.value || "pem",
        target: selectTarget.value || "der",
        certFile: null,
        keyFile: null,
        chain1File: null,
        chain2File: null,
        pfxPassword: "",
    };

    // ─── Pure Functions ──────────────────────────────────────────────────────
    function isValidFileExtension(file, format) {
        if (!file) return false;
        const ext = "." + file.name.split(".").pop().toLowerCase();
        return allowedExtensions[format]?.includes(ext) ?? false;
    }

    function needsPassword(s) {
        return s.current === "pfx" || s.target === "pfx";
    }

    function validate(s) {
        const errors = {};
        const key = `${s.current}→${s.target}`;
        const required = requiredFields[key] || [];

        // Validate Cert
        if (required.includes("cert")) {
            if (!s.certFile) {
                errors.cert = "Vui lòng chọn tệp chứng chỉ (Certificate).";
            } else {
                if (s.certFile.size > MAX_FILE_SIZE) {
                    errors.cert = "Tệp quá lớn (tối đa 512KB).";
                } else if (!isValidFileExtension(s.certFile, s.current)) {
                    errors.cert = `Đuôi mở rộng không hợp lệ cho định dạng ${s.current.toUpperCase()}.`;
                }
            }
        }

        // Validate Key
        if (s.target === "pfx") { // Private Key field is only visible when generating PFX
            if (required.includes("key")) {
                if (!s.keyFile) {
                    errors.key = "Vui lòng chọn tệp Private Key để đóng gói PFX.";
                } else {
                    if (s.keyFile.size > MAX_FILE_SIZE) {
                        errors.key = "Tệp quá lớn (tối đa 512KB).";
                    } else if (!isValidFileExtension(s.keyFile, "pem")) {
                        errors.key = "Private Key phải ở định dạng PEM (.key, .pem).";
                    }
                }
            }
        }

        // Validate Password
        if (needsPassword(s)) {
            if (!s.pfxPassword) {
                errors.password = "Vui lòng nhập mật khẩu PFX.";
            }
        }

        // Validate optional chains size/ext (if provided)
        if (s.target === "pfx" || s.target === "p7b") {
            if (s.chain1File) {
                if (s.chain1File.size > MAX_FILE_SIZE) {
                    errors.chain1 = "Tệp quá lớn (tối đa 512KB).";
                } else if (!isValidFileExtension(s.chain1File, "pem")) {
                    errors.chain1 = "Chain phải ở định dạng PEM.";
                }
            }
            if (s.chain2File) {
                if (s.chain2File.size > MAX_FILE_SIZE) {
                    errors.chain2 = "Tệp quá lớn (tối đa 512KB).";
                } else if (!isValidFileExtension(s.chain2File, "pem")) {
                    errors.chain2 = "Chain phải ở định dạng PEM.";
                }
            }
        }

        return errors;
    }

    // ─── UI Updates ──────────────────────────────────────────────────────────
    function buildTargetOptions(current) {
        const allowedTargets = validTargets[current] || validTargets["pem"];
        const currentTarget = selectTarget.value;
        
        selectTarget.innerHTML = "";
        let hasPrevious = false;

        allowedTargets.forEach(tgt => {
            const el = document.createElement("option");
            el.value = tgt;
            el.textContent = targetLabels[tgt];
            selectTarget.appendChild(el);
            if (tgt === currentTarget) hasPrevious = true;
        });

        selectTarget.value = hasPrevious ? currentTarget : allowedTargets[0];
        state.target = selectTarget.value;
    }

    function removeInlineError(inputEl) {
        const existingError = inputEl.parentElement.querySelector(".input-error-msg");
        if (existingError) {
            existingError.remove();
        }
        inputEl.style.borderColor = "";
    }

    function showInlineError(inputEl, msg) {
        removeInlineError(inputEl);
        if (!msg) return;

        inputEl.style.borderColor = "var(--color-error)";
        const errorDiv = document.createElement("div");
        errorDiv.className = "input-error-msg text-error text-sm mt-1";
        errorDiv.textContent = msg;
        inputEl.parentElement.appendChild(errorDiv);
    }

    function updateUI() {
        // 1. Cập nhật ẩn/hiện các block
        const target = state.target;

        setDisplay(groupKey, target === "pfx" ? "block" : "none");
        setDisplay(groupChain1, (target === "pfx" || target === "p7b") ? "block" : "none");
        setDisplay(groupChain2, (target === "pfx" || target === "p7b") ? "block" : "none");

        const pwdNeeded = needsPassword(state);
        setDisplay(groupPfxPassword, pwdNeeded ? "flex" : "none");
        setDisplay(groupPfxWarning, pwdNeeded ? "block" : "none");

        // 2. Clear old errors
        removeInlineError(inputCert);
        removeInlineError(inputKey);
        removeInlineError(inputChain1);
        removeInlineError(inputChain2);
        removeInlineError(inputPfxPw);
        setDisplay(mainErrorCard, "none");

        // 3. Validation & Nút Submit
        const errors = validate(state);
        const hasErrors = Object.keys(errors).length > 0;

        // Chỉ show lỗi nếu field đó đã được touched (có file) hoặc là password.
        // Để UX tốt, không báo đỏ ngay khi user vừa load form. 
        // Nhưng ta sẽ disable submit button nếu invalid.
        btnSubmit.disabled = hasErrors;

        // Nếu user chọn file sai, sẽ hiện lỗi liền
        if (state.certFile && errors.cert) showInlineError(inputCert, errors.cert);
        if (state.keyFile && errors.key) showInlineError(inputKey, errors.key);
        if (state.chain1File && errors.chain1) showInlineError(inputChain1, errors.chain1);
        if (state.chain2File && errors.chain2) showInlineError(inputChain2, errors.chain2);
        
        // Riêng password nếu cần mà gõ sai thì báo (khi đang gõ)
        if (state.pfxPassword && errors.password) showInlineError(inputPfxPw, errors.password);
    }

    function updateState() {
        state.current = selectCurrent.value;
        // Check nếu selectCurrent đổi, đổi target nếu target ko hơp lệ
        if (validTargets[state.current].indexOf(selectTarget.value) === -1) {
             state.target = validTargets[state.current][0];
        } else {
             state.target = selectTarget.value;
        }
        
        state.certFile = inputCert.files[0] || null;
        state.keyFile = inputKey.files[0] || null;
        state.chain1File = inputChain1.files[0] || null;
        state.chain2File = inputChain2.files[0] || null;
        state.pfxPassword = inputPfxPw.value || "";

        updateUI();
    }

    // ─── Event Listeners ─────────────────────────────────────────────────────
    selectCurrent.addEventListener("change", () => {
        buildTargetOptions(selectCurrent.value);
        updateState();
    });
    
    selectTarget.addEventListener("change", updateState);
    inputCert.addEventListener("change", updateState);
    inputKey.addEventListener("change", updateState);
    inputChain1.addEventListener("change", updateState);
    inputChain2.addEventListener("change", updateState);
    inputPfxPw.addEventListener("input", updateState);

    // Initial load
    buildTargetOptions(state.current);
    updateState();

    // ─── Submit Handler ──────────────────────────────────────────────────────
    form.addEventListener("submit", async(e) => {
        e.preventDefault();

        // 1. Validate lại trước khi gửi
        const errors = validate(state);
        if (Object.keys(errors).length > 0) {
            // Show all errors
            if (errors.cert) showInlineError(inputCert, errors.cert);
            if (errors.key) showInlineError(inputKey, errors.key);
            if (errors.chain1) showInlineError(inputChain1, errors.chain1);
            if (errors.chain2) showInlineError(inputChain2, errors.chain2);
            if (errors.password) showInlineError(inputPfxPw, errors.password);
            
            showError(mainErrorCard, mainErrorCard.querySelector(".error-card__message"), "Có lỗi trong form. Vui lòng kiểm tra lại.");
            return;
        }

        // 2. Chuẩn bị FormData (vì có file upload)
        const formData = new FormData();
        formData.append("currentFormat", state.current);
        formData.append("targetFormat", state.target);
        formData.append("certificate", state.certFile);
        
        if (state.target === "pfx" && state.keyFile) {
            formData.append("privateKey", state.keyFile);
        }
        if ((state.target === "pfx" || state.target === "p7b")) {
            if (state.chain1File) formData.append("chain1", state.chain1File);
            if (state.chain2File) formData.append("chain2", state.chain2File);
        }
        if (needsPassword(state)) {
            formData.append("pfxPassword", state.pfxPassword);
        }

        // Disable button & loading
        setElementsEnabled([btnSubmit], false);
        toggleLoading(btnSubmit, iconNormal, iconLoading, true);
        setDisplay(mainErrorCard, "none");

        try {
            const response = await fetch(`${API_BASE_URL}/ssl/converter/convert`, {
                method: "POST",
                body: formData,
            });

            const resData = await response.json();

            if (!response.ok) {
                throw new Error(resData.error || "Không thể chuyển đổi chứng chỉ. Hãy kiểm tra lại định dạng và mật khẩu.");
            }

            // Xử lý download file từ Base64
            const { filename, data, contentType } = resData;
            
            // Convert base64 to binary ArrayBuffer
            let binaryString;
            try {
                binaryString = window.atob(data);
            } catch {
                throw new Error("Dữ liệu trả về từ server bị lỗi — vui lòng thử lại");
            }

            const len = binaryString.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }
            
            // Create Blob and trigger download
            const blob = new Blob([bytes], { type: contentType });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.style.display = "none";
            a.href = url;
            a.download = filename;
            
            document.body.appendChild(a);
            try {
                a.click();
            } finally {
                window.URL.revokeObjectURL(url);
                document.body.removeChild(a);
            }

        } catch (err) {
            showError(mainErrorCard, mainErrorCard.querySelector(".error-card__message"), err.message || "Không thể kết nối đến máy chủ.");
        } finally {
            toggleLoading(btnSubmit, iconNormal, iconLoading, false);
            // Re-enable bằng State Flow
            updateState(); 
        }
    });

});
