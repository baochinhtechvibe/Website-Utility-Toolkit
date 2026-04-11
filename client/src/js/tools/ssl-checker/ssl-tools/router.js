import { resetUI } from "../../../utils/index.js";

/**
 * SSL Tools Router
 * Handles tab switching and result resetting
 */

const RESET_SECTIONS = [
    "toolResultChecker",
    "toolErrorChecker",
    "toolShareLink",
    "resultCardCsr",
    "errorCardCsr",
    "resultCardCert",
    "errorCardCert",
    "resultCardMatcher",
    "errorCardMatcher",
    "toolResultCsrGenerator",
    "toolErrorCsrGenerator",
    "cacheNotice"
];

const TOOL_MAP = {
    "ssl-checker":   "toolChecker",
    "csr-generator": "toolCsrGenerator",
    "csr-decoder":   "toolCsr",
    "cert-decoder":  "toolCert",
    "key-matcher":   "toolMatcher",
    "ssl-converter": "toolConverter"
};

let currentSlug = "ssl-checker";

function activateTool(slug) {
    if (!TOOL_MAP[slug]) {
        slug = "ssl-checker";
    }

    // 1. Reset results if switching
    if (slug !== currentSlug) {
        const resetElements = RESET_SECTIONS.map(id => document.getElementById(id)).filter(el => el);
        resetUI(resetElements);
    }

    const targetId = TOOL_MAP[slug];
    const targetPanel = document.getElementById(targetId);

    // 2. Clear active classes from all buttons
    const toolBtns = document.querySelectorAll(".js-tool-btn");
    toolBtns.forEach(btn => {
        btn.classList.remove("active");
    });

    // 3. Set active button
    const activeBtn = document.querySelector(`.js-tool-btn[data-slug="${slug}"]`);
    if (activeBtn) {
        activeBtn.classList.add("active");
    }

    // 4. Toggle Sections using d-block / d-none classes to avoid !important conflicts
    Object.values(TOOL_MAP).forEach(id => {
        const panel = document.getElementById(id);
        if (!panel) return;

        if (id === targetId) {
            panel.classList.remove("d-none");
            panel.classList.add("d-block", "ssl-tools__section--active");
        } else {
            panel.classList.remove("d-block", "ssl-tools__section--active");
            panel.classList.add("d-none");
        }
    });

    // Scroll to top for better mobile UX
    window.scrollTo({ top: 0, behavior: "smooth" });

    currentSlug = slug;
}

export function init() {
    const toolBtns = document.querySelectorAll(".js-tool-btn");
    if (toolBtns.length === 0) return;

    toolBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const slug = btn.dataset.slug;
            if (slug) {
                activateTool(slug);
            }
        });
    });

    // Initialize state
    const currentURL = new URL(window.location.href);
    const initialSlug = currentURL.searchParams.get("tool") || "ssl-checker";
    activateTool(initialSlug);
}

document.addEventListener("DOMContentLoaded", init);
