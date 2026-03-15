/*
===============================================
    URL UTILITIES FUNCTIONS
    Các hàm xử lý URL, link, API
=================================================
*/
/**
 * Get IP info link
 */
export function getIPInfoLink(ip) {
    return `https://check-host.net/ip-info?host=${ip}`;
}

/**
 * Gán chức năng tra cứu WHOIS cho button
 *
 * - Hiển thị button
 * - Bind sự kiện click
 * - Tự chọn trang WHOIS phù hợp (.vn / quốc tế)
 *
 * @param {HTMLElement} btnWhois - Nút WHOIS
 * @param {string} domain - Tên miền cần tra cứu
 */
export function getWhoisDomain(btnWhois, domain) {

    // Validate
    if (!btnWhois || !domain) {
        console.warn("getWhoisDomain: invalid params", btnWhois, domain);
        return;
    }

    btnWhois.style.display = "flex";

    btnWhois.onclick = null;

    btnWhois.onclick = () => {

        let whoisURL = "";

        // Domain Việt Nam
        if (domain.endsWith(".vn")) {
            whoisURL = `https://tino.vn/whois?domain=${encodeURIComponent(domain)}`;
        }

        // Quốc tế
        else {
            whoisURL = `https://www.whois.com/whois/${encodeURIComponent(domain)}`;
        }

        // Mở tab mới
        window.open(whoisURL, "_blank", "noopener,noreferrer");
    };
}

/**
 * Gắn chức năng copy nội dung input vào clipboard cho 1 button
 *
 * @param {HTMLInputElement|HTMLTextAreaElement} inputEl
 *        Ô input/textarea chứa text cần copy
 *
 * @param {HTMLButtonElement} buttonEl
 *        Nút bấm để trigger copy
 *
 * @param {Object} [options]
 *        Tuỳ chọn hiển thị (không bắt buộc)
 *
 * @param {string} [options.successText="Đã copy!"]
 *        Text hiển thị khi copy thành công
 *
 * @param {string} [options.defaultText="Copy"]
 *        Text mặc định của button
 *
 * @param {number} [options.resetDelay=3000]
 *        Thời gian (ms) để reset button về trạng thái ban đầu
 */
export function setupCopyButton(inputEl, buttonEl, options = {}) {
    if (!inputEl || !buttonEl) return;

    const {
        successText = "Đã copy!",
        defaultText = "Copy",
        resetDelay = 3000
    } = options;

    // Lưu HTML ban đầu để restore lại
    const defaultHTML = buttonEl.innerHTML;

    buttonEl.addEventListener("click", async () => {
        try {
            // Chọn toàn bộ text (tốt cho mobile)
            inputEl.select();
            inputEl.setSelectionRange(0, 99999);

            // Copy vào clipboard
            await navigator.clipboard.writeText(inputEl.value);

            // Hiển thị trạng thái thành công
            buttonEl.innerHTML = `
                <i class="fa-solid fa-check"></i>
                <span>${successText}</span>
            `;

            // Reset về trạng thái ban đầu
            setTimeout(() => {
                buttonEl.innerHTML = defaultHTML || `
                    <i class="fas fa-copy"></i>
                    <span>${defaultText}</span>
                `;
            }, resetDelay);

        } catch (err) {
            console.error("Copy failed:", err);
        }
    });
}

