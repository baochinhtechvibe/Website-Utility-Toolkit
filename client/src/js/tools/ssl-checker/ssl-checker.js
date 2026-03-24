import "./ssl-tools/checker.js";
import "./ssl-tools/csr-decoder.js";
import "./ssl-tools/csr-generator.js";
import "./ssl-tools/cert-decoder.js";
import "./ssl-tools/key-matcher.js";
import "./ssl-tools/converter.js";
import "./ssl-tools/router.js";

document.addEventListener("click", async (e) => {
    const btn = e.target.closest(".js-copy-code");
    if (!btn) return;

    if (btn.disabled) return;

    try {
        const selector = btn.getAttribute("data-clipboard-target");
        if (!selector) return;

        const codeEl = document.querySelector(selector);
        if (!codeEl) return;

        btn.disabled = true;

        // Lấy text thô (tránh lấy cả markup span nếu có)
        const textToCopy = codeEl.innerText || codeEl.textContent;

        await navigator.clipboard.writeText(textToCopy.trim());

        // Lưu HTML ban đầu
        const originalHTML = btn.innerHTML;

        // Hiện feedback thành công
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