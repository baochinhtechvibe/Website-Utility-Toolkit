/**
 * chmod.js
 * Core logic for Chmod Calculator Tool
 */

import { 
    $, 
    $$, 
} from "../../utils/index.js";

document.addEventListener("DOMContentLoaded", () => {
    initChmod();
});

function initChmod() {
    setupEventListeners();
    syncFromOctal("644"); // Set default 644 on load
}

/**
 * Main update function to sync all UI elements
 */
function updateAll(source = "other") {
    const octal = calculateOctal();
    const symbolic = calculateSymbolic();
    
    // Update numeric/text fields
    $("#chmodOctal").value = octal;
    $("#chmodSymbolic").value = symbolic;

    // Update Master Input if the change didn't come from it
    if (source !== "master") {
        const displayOctal = octal.replace(/^0+/, "");
        $("#masterChmodInput").value = displayOctal === "" ? "" : displayOctal;
        $("#masterChmodInput").classList.remove("is-invalid");
        $("#masterValidationError").classList.add("d-none");
    }
    
    // Update components
    updateTerminalPreview(symbolic);
    updateCommandDisplay(octal);
    checkSecurity(octal, symbolic);
}

/**
 * Calculates the octal value based on checked boxes
 * @returns {string} 4-digit octal (e.g., "0755")
 */
function calculateOctal() {
    const groups = ["special", "owner", "group", "others"];
    let result = "";
    
    groups.forEach(group => {
        let sum = 0;
        $$(`.perm-check[data-group="${group}"]`).forEach(cb => {
            if (cb.checked) {
                sum += parseInt(cb.getAttribute("data-bit"));
            }
        });
        result += sum.toString();
    });
    
    return result;
}

/**
 * Translates bits to symbolic notation (e.g., rwxr-xr-x)
 * Handles SUID (s/S), SGID (s/S), and Sticky Bit (t/T)
 */
function calculateSymbolic() {
    const getGroupBits = (group) => {
        let bits = { r: false, w: false, x: false };
        $$(`.perm-check[data-group="${group}"]`).forEach(cb => {
            const bit = cb.getAttribute("data-bit");
            if (cb.checked) {
                if (bit === "4") bits.r = true;
                if (bit === "2") bits.w = true;
                if (bit === "1") bits.x = true;
            }
        });
        return bits;
    };

    const owner = getGroupBits("owner");
    const group = getGroupBits("group");
    const others = getGroupBits("others");
    const special = getGroupBits("special"); // 4: SUID, 2: SGID, 1: Sticky

    let res = "";

    // Owner
    res += owner.r ? "r" : "-";
    res += owner.w ? "w" : "-";
    if (special.r) { // SUID
        res += owner.x ? "s" : "S";
    } else {
        res += owner.x ? "x" : "-";
    }

    // Group
    res += group.r ? "r" : "-";
    res += group.w ? "w" : "-";
    if (special.w) { // SGID
        res += group.x ? "s" : "S";
    } else {
        res += group.x ? "x" : "-";
    }

    // Others
    res += others.r ? "r" : "-";
    res += others.w ? "w" : "-";
    if (special.x) { // Sticky
        res += others.x ? "t" : "T";
    } else {
        res += others.x ? "x" : "-";
    }

    return res;
}

/**
 * Advanced sync from Master Input (handles both Octal and Symbolic)
 */
function syncFromMaster(val) {
    val = val.trim();
    if (!val) {
        setInvalid(false);
        // Reset to default (644) when empty
        syncFromOctal("644", "master");
        return;
    }

    // 1. Detect Octal (3-4 digits, 0-7)
    const octalRegex = /^[0-7]{3,4}$/;
    if (octalRegex.test(val)) {
        setInvalid(false);
        syncFromOctal(val, "master");
        return;
    }

    // 2. Detect Symbolic (10 chars, e.g., -rwxr-xr-x)
    const symbolicRegex = /^[-d][r-][w-][xSs-][r-][w-][xSs-][r-][w-][xTt-]$/;
    if (symbolicRegex.test(val)) {
        setInvalid(false);
        syncFromSymbolic(val);
        return;
    }

    // 3. Invalid
    setInvalid(true);
}

function setInvalid(isInvalid) {
    const input = $("#masterChmodInput");
    const error = $("#masterValidationError");
    if (isInvalid) {
        input.classList.add("is-invalid");
        error.classList.remove("d-none");
    } else {
        input.classList.remove("is-invalid");
        error.classList.add("d-none");
    }
}

/**
 * Updates checkboxes from Symbolic string
 */
function syncFromSymbolic(str) {
    const groups = ["owner", "group", "others"];
    const specialBits = { owner: 4, group: 2, others: 1 };
    let specialSum = 0;

    // Reset all special bits first
    $$('.perm-check[data-group="special"]').forEach(cb => cb.checked = false);

    for (let i = 0; i < 3; i++) {
        const group = groups[i];
        const start = 1 + (i * 3);
        const r = str[start] === 'r';
        const w = str[start + 1] === 'w';
        const xChar = str[start + 2];
        
        const x = "xsbt".includes(xChar.toLowerCase());
        const isSpecial = "sStT".includes(xChar);

        if (isSpecial) {
            specialSum += specialBits[group];
        }

        $(`.perm-check[data-group="${group}"][data-bit="4"]`).checked = r;
        $(`.perm-check[data-group="${group}"][data-bit="2"]`).checked = w;
        $(`.perm-check[data-group="${group}"][data-bit="1"]`).checked = x;
    }

    // Apply special bits
    for (let i = 0; i < 3; i++) {
        const bit = [4, 2, 1][i];
        const cb = $(`.perm-check[data-group="special"][data-bit="${bit}"]`);
        if (cb) cb.checked = (specialSum & bit) === bit;
    }

    updateAll("master");
}

/**
 * Updates checkboxes from Octal input is changed manually
 * @param {string} val 
 */
function syncFromOctal(val, source = "other") {
    // Sanitize: allow only numbers, max 4 digits
    val = val.replace(/[^0-7]/g, "").substring(0, 4);
    if (val.length < 3) return; // Wait for enough digits
    if (val.length === 3) val = "0" + val;
    
    const groups = ["special", "owner", "group", "others"];
    for (let i = 0; i < 4; i++) {
        const digit = parseInt(val[i]);
        const group = groups[i];
        
        $$(`.perm-check[data-group="${group}"]`).forEach(cb => {
            const bit = parseInt(cb.getAttribute("data-bit"));
            cb.checked = (digit & bit) === bit;
        });
    }
    updateAll(source);
}

/**
 * Updates the simulated terminal display
 */
function updateTerminalPreview(symbolic) {
    const preview = $("#terminalPreview");
    if (!preview) return;
    
    const filename = $("#targetFilename")?.value || "filename";
    const now = new Date();
    const month = now.toLocaleString('en-US', { month: 'short' });
    const day = now.getDate().toString().padStart(2, ' ');
    const time = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
    
    // Note: 4096 is standard directory size in bytes, not the year.
    preview.innerHTML = `
<span class="t-perm">-${symbolic}</span> <span class="t-meta">1 user group 4096 ${month} ${day} ${time}</span> <span class="t-file">${filename}</span>`;
}

/**
 * Generates and displays the final command
 */
function updateCommandDisplay(octal) {
    const display = $("#generatedCommand");
    if (!display) return;
    
    const isRecursive = $("#recursiveToggle").checked;
    const cmdType = $("#commandType").value;
    const filename = $("#targetFilename")?.value || "filename";
    const recFlag = isRecursive ? " -R" : "";
    
    // Toggle recursive checkbox visibility (not applicable for find)
    const recursiveWrapper = $("#recursiveToggle").closest(".recursive-wrapper");
    if (cmdType.startsWith("find")) {
        recursiveWrapper?.classList.add("d-none");
    } else {
        recursiveWrapper?.classList.remove("d-none");
    }
    
    let commandHtml = "";
    const currentOctal = octal.replace(/^0+/, "") || "0";
    
    // Smart preset suggestions based on mode
    let displayOctal = currentOctal;
    if (currentOctal === "0") {
        if (cmdType === "find-f") displayOctal = "644";
        if (cmdType === "find-d") displayOctal = "755";
    }

    const span = (cls, text) => `<span class="${cls}">${text}</span>`;

    if (cmdType === "chmod") {
        commandHtml = `${span("code-program", "chmod")}${isRecursive ? " " + span("code-keyword", "-R") : ""} ${span("code-value", displayOctal)} ${span("code-string", filename)}`;
    } else if (cmdType === "find-f") {
        commandHtml = `${span("code-program", "find")} . ${span("code-keyword", "-type f")} ${span("code-keyword", "-name")} ${span("code-string", `"${filename}"`)} ${span("code-parameter", "-exec chmod")} ${span("code-value", displayOctal)} ${span("code-keyword", "{} +")}`;
    } else if (cmdType === "find-d") {
        commandHtml = `${span("code-program", "find")} . ${span("code-keyword", "-type d")} ${span("code-keyword", "-name")} ${span("code-string", `"${filename}"`)} ${span("code-parameter", "-exec chmod")} ${span("code-value", displayOctal)} ${span("code-keyword", "{} +")}`;
    }
    
    display.innerHTML = commandHtml;
}

/**
 * Security audit logic
 */
function checkSecurity(octal, symbolic) {
    const advisor = $("#securityAdvisor");
    const message = $("#securityMessage");
    if (!advisor || !message) return;

    let warning = null;
    const othersWrite = symbolic[7] === 'w';
    const is777 = octal.endsWith("777");
    const hasSUID = octal.startsWith("4") || octal.startsWith("2") || octal.startsWith("6");

    if (is777) {
        warning = "<b>NGUY HIỂM: Phát hiện quyền 777.</b> Điều này cho phép TẤT CẢ MỌI NGƯỜI có thể đọc, ghi và thực thi file này. Cực kỳ rủi ro trong môi trường production.";
    } else if (othersWrite) {
        warning = "<b>Cảnh báo: Quyền Ghi công cộng (World-Writable).</b> Những người dùng khác có quyền chỉnh sửa file này, dễ dẫn đến các lỗ hổng bảo mật.";
    } else if (hasSUID) {
        warning = "<b>Thận trọng: Các bit đặc biệt đang bật.</b> SUID/SGID cho phép file thực thi với quyền của chủ sở hữu hoặc nhóm. Hãy cực kỳ cẩn trọng khi sử dụng.";
    }

    if (warning) {
        message.innerHTML = warning;
        advisor.classList.remove("d-none");
    } else {
        advisor.classList.add("d-none");
    }
}

/**
 * All event listeners
 */
function setupEventListeners() {
    // 1. Checkbox changes
    $$(".perm-check").forEach(cb => {
        cb.addEventListener("change", updateAll);
    });

    // 2. Octal input change
    $("#chmodOctal")?.addEventListener("input", (e) => {
        syncFromOctal(e.target.value);
    });

    // 2.5 Master input change
    $("#masterChmodInput")?.addEventListener("input", (e) => {
        syncFromMaster(e.target.value);
    });

    // 2.7 Target filename change
    $("#targetFilename")?.addEventListener("input", updateAll);

    // 3. Command options
    $("#recursiveToggle")?.addEventListener("change", updateAll);
    $("#commandType")?.addEventListener("change", updateAll);

    // 4. Copy buttons
    $$(".btn-copy-small").forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-target");
            const text = $(targetId)?.value;
            copyText(text, btn);
        });
    });

    $("#btnCopyCommand")?.addEventListener("click", () => {
        const text = $("#generatedCommand")?.textContent;
        copyText(text, $("#btnCopyCommand"));
    });
}

/**
 * Simple copy helper
 */
async function copyText(text, btn) {
    if (!text) return;
    try {
        await navigator.clipboard.writeText(text);
        const originalHtml = btn.innerHTML;
        // Only change the icon, no text
        btn.innerHTML = `<i class="fa-solid fa-check"></i>`;
        setTimeout(() => {
            btn.innerHTML = originalHtml;
        }, 1500);
    } catch (err) {
        console.error("Failed to copy", err);
    }
}
