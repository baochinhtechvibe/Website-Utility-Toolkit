import "./ssl-tools/checker.js";
import "./ssl-tools/csr-decoder.js";
import "./ssl-tools/router.js";

document.addEventListener("click", async (e) => {
    const btn = e.target.closest(".js-copy-code");
    if (!btn) return;

    if (btn.disabled) return;

    try {
        btn.disabled = true;

        const selector = btn.dataset.clipboardTarget;
        const container = btn.closest(".code-block__body");
        const codeEl = container?.querySelector(selector);
        if (!codeEl) return;

        const raw = codeEl.textContent;
        const cleaned = raw.replace(/\s+/g, " ").trim();

        await navigator.clipboard.writeText(cleaned);

        btn.innerHTML = `<i class="fa-solid fa-check"></i>`;

        setTimeout(() => {
            btn.innerHTML = `<i class="fa-regular fa-copy"></i>`;
            btn.disabled = false;
        }, 3000);

    } catch (e) {
        btn.disabled = false;
        console.error("COPY FAIL:", e);
    }
});

// Logic chuyển tab (Navigation Tools)
const toolBtns = document.querySelectorAll(".js-tool-btn");
const toolSections = document.querySelectorAll(".ssl-tools__section");

toolBtns.forEach(btn => {
    btn.addEventListener("click", () => {
        // Xóa class active ở mọi nút
        toolBtns.forEach(b => b.classList.remove("active"));
        // Thêm class active cho nút vừa click
        btn.classList.add("active");

        // Lấy slug của tab
        const slug = btn.dataset.slug;

        // Ẩn tất cả section, gỡ class active
        toolSections.forEach(sec => {
            sec.classList.remove("ssl-tools__section--active", "d-block");
            sec.classList.add("d-none");
        });

        // Hiển thị section tương ứng với slug
        const targetSec = document.querySelector(`.ssl-tools__section[data-slug="${slug}"]`);
        if (targetSec) {
            targetSec.classList.remove("d-none");
            targetSec.classList.add("ssl-tools__section--active", "d-block");
        }
    });
});