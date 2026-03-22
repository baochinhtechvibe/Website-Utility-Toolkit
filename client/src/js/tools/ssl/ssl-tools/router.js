/* ==========================
    SSL TOOLS ROUTER
   ==========================
*/
import {
    setDisplay,
    resetUI
} from "../../../utils/index.js";
// ===================================================
//  TOOL MENU BUTTONS (Sidebar / Toolbar)
// ===================================================
const toolMenuButtons = document.querySelectorAll(".js-tool-btn");
// ===================================================
//  TOOL CONTAINERS (Tool Panels / Sections)
// ===================================================
const toolChecker = document.getElementById("toolChecker");
const toolCsrGenerator = document.getElementById("toolCsrGenerator");
const toolCsr = document.getElementById("toolCsr");
const toolCert = document.getElementById("toolCert");
const toolMatcher = document.getElementById("toolMatcher");
const toolConverter = document.getElementById("toolConverter");

// Checker-specific cards
const toolResultChecker = document.getElementById("toolResultChecker");
const toolErrorChecker = document.getElementById("toolErrorChecker");
const toolShareLink = document.getElementById("toolShareLink");

// CSR-specific cards
const resultCardCsr = document.getElementById("resultCardCsr");
const errorCardCsr = document.getElementById("errorCardCsr");

const RESET_SECTIONS = [
    toolResultChecker,
    toolErrorChecker,
    toolShareLink,
    resultCardCsr,
    errorCardCsr
];


// ===================================================
//  TOOL MAP: slug => { panel }
// ===================================================

const TOOL_MAP = {
    "ssl-checker":   { panel: toolChecker },
    "csr-generator": { panel: toolCsrGenerator },
    "csr-decoder":   { panel: toolCsr },
    "cert-decoder":  { panel: toolCert },
    "key-matcher":   { panel: toolMatcher },
    "ssl-converter": { panel: toolConverter }
};

/** Slug đang active */
let currentSlug = "ssl-checker";


/**
 * Active tool theo slug (chỉ show/hide, KHÔNG đổi URL)
 */
function activateTool(slug) {

    if (!TOOL_MAP[slug]) {
        slug = "ssl-checker";
    }

    /* ===== RESET RESULT UI khi chuyển tool ===== */
    if (slug !== currentSlug) {
        resetUI(RESET_SECTIONS);
    }

    const targetPanel = TOOL_MAP[slug].panel;

    /* ================= RESET BUTTON ================= */
    toolMenuButtons.forEach(btn => {
        btn.classList.remove("active");
    });

    /* ================= HIDE OLD PANELS ================= */
    Object.values(TOOL_MAP).forEach(item => {
        if (!item.panel || item.panel === targetPanel) return;
        item.panel.classList.remove("ssl-tools__section--active");
        setDisplay(item.panel, "none");
    });

    /* ================= ACTIVE BUTTON ================= */
    const activeBtn = document.querySelector(`.js-tool-btn[data-slug="${slug}"]`);
    if (activeBtn) {
        activeBtn.classList.add("active");
    }

    /* ================= SHOW NEW PANEL ================= */
    if (targetPanel) {
        setDisplay(targetPanel, "block");
        // Force reflow
        targetPanel.offsetHeight;
        targetPanel.classList.add("ssl-tools__section--active");
    }

    currentSlug = slug;
}


/**
 * Bind click trên các nút menu
 */
function bindToolMenu() {
    toolMenuButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const slug = btn.dataset.slug;
            if (slug) {
                activateTool(slug);
            }
        });
    });
}


// ===================================================
//  INITIALIZATION
// ===================================================

function initSSLTools() {
    bindToolMenu();
    // Mặc định hiển thị SSL Checker
    activateTool("ssl-checker");
}

document.addEventListener("DOMContentLoaded", initSSLTools);