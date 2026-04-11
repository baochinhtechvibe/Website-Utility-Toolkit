import "./ssl-tools/checker.js";
import "./ssl-tools/csr-decoder.js";
import "./ssl-tools/csr-generator.js";
import "./ssl-tools/cert-decoder.js";
import "./ssl-tools/key-matcher.js";
import "./ssl-tools/converter.js";
import "./ssl-tools/router.js";

/**
 * Universal logic for Copying Code Blocks
 * Supports all tools within the SSL suite
 */
export function initCopyHelper() {
    document.addEventListener("click", async (e) => {
        const btn = e.target.closest(".js-copy-code");
        if (!btn || btn.disabled) return;

        try {
            const selector = btn.getAttribute("data-clipboard-target");
            if (!selector) return;

            const codeEl = document.querySelector(selector);
            if (!codeEl) return;

            btn.disabled = true;

            // Get raw text (avoiding inner spans for syntax highlighting)
            const textToCopy = codeEl.innerText || codeEl.textContent;

            await navigator.clipboard.writeText(textToCopy.trim());

            // Success feedback
            const originalHTML = btn.innerHTML;
            btn.innerHTML = `<i class="fa-solid fa-check"></i>`;

            setTimeout(() => {
                btn.innerHTML = originalHTML;
                btn.disabled = false;
            }, 2000);

        } catch (err) {
            btn.disabled = false;
            console.error("COPY FAIL:", err);
        }
    });
}

// Initialize global helpers
document.addEventListener("DOMContentLoaded", initCopyHelper);
