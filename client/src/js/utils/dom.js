// js/utils/dom.js

/*
===============================================
    DOM / UI HELPER FUNCTIONS
    Các hàm hỗ trợ thao tác giao diện (display,
    loading, error, query selector...)
=================================================
*/


// ================================
// DISPLAY CONTROL
// Quản lý hiển thị element bằng utility class
// ================================

/**
 * Thay đổi trạng thái hiển thị của element
 * bằng các class d-* (Bootstrap / custom)
 *
 * @param {HTMLElement} el
 * @param {string} mode - none | block | flex | inline | inline-block
 */
export function setDisplay(el, mode = "none") {

    if (!el) return;

    const classes = [
        "d-none",
        "d-block",
        "d-flex",
        "d-inline",
        "d-inline-block"
    ];

    // Xóa toàn bộ class display cũ
    el.classList.remove(...classes);

    // Gắn class mới
    if (mode) {
        el.classList.add(`d-${mode}`);
    }
}


/**
 * Hiển thị element (display: block)
 *
 * @param {HTMLElement} el
 */
export function show(el) {
    setDisplay(el, "block");
}


/**
 * Ẩn element (display: none)
 *
 * @param {HTMLElement} el
 */
export function hide(el) {
    setDisplay(el, "none");
}

/**
 * Reset UI bằng cách ẩn danh sách element truyền vào
 *
 * @param {HTMLElement[]} elements
 */
export function resetUI(elements = []) {
    showElements("none", ...elements);
}

/**
 * Reset tất cả thành phần nhập liệu trong container
 * @param {HTMLElement|string} root - element hoặc selector
 */
export function resetInputsInContainer(root) {
    const container =
        typeof root === "string"
            ? document.querySelector(root)
            : root;

    if (!container) return;

    // reset form chuẩn nếu có
    container.querySelectorAll("form").forEach(form => {
        form.reset();
    });

    // reset input rời ngoài form
    container
        .querySelectorAll("input, textarea, select")
        .forEach(el => {
            const tag = el.tagName.toLowerCase();
            const type = (el.type || "").toLowerCase();

            if (tag === "select") {
                el.selectedIndex = 0;
                return;
            }

            if (type === "checkbox" || type === "radio") {
                el.checked = false;
                return;
            }

            if (type === "button" || type === "submit" || type === "hidden") {
                return;
            }

            el.value = "";
        });

    // clear custom data-state nếu bạn có dùng
    container
        .querySelectorAll("[data-state]")
        .forEach(el => el.setAttribute("data-state", "idle"));
}




// ================================
// MULTI DISPLAY
// Hiển thị / ẩn nhiều element cùng lúc
// ================================

/**
 * Hiển thị nhiều element theo mode
 *
 * @param {string} mode
 * @param {...HTMLElement} elements
 */
export function showElements(mode, ...elements) {

    elements.forEach(el => {

        if (el) {
            setDisplay(el, mode);
        }

    });
}



// ================================
// LOADING STATE
// Quản lý trạng thái loading cho button
// ================================

/**
 * Bật / tắt trạng thái loading cho button
 *
 * - Disable button khi loading
 * - Ẩn icon thường
 * - Hiện icon loading
 *
 * @param {HTMLButtonElement} button
 * @param {HTMLElement} normalIcon
 * @param {HTMLElement} loadingIcon
 * @param {boolean} isLoading
 */
export function toggleLoading(
    button,
    normalIcon,
    loadingIcon,
    isLoading = true
) {

    if (!button) return;

    // Disable / enable button
    button.disabled = isLoading;

    // Toggle icon hiển thị
    normalIcon?.classList.toggle("d-none", isLoading);

    loadingIcon?.classList.toggle("d-none", !isLoading);
}

// ================================
// ENABLE / DISABLE MULTIPLE ELEMENTS
// Bật / tắt trạng thái disabled cho nhiều element
// ================================

/**
 * Bật hoặc tắt trạng thái disabled của danh sách element
 *
 * Dùng cho input, button, select, textarea...
 * Giúp khóa / mở form khi submit hoặc loading
 *
 * Quy ước:
 *  - status = true  → enable (disabled = false)
 *  - status = false → disable (disabled = true)
 *
 * Hàm sẽ tự bỏ qua:
 *  - element null / undefined
 *  - element không có thuộc tính disabled
 *
 * @param {HTMLElement[]} elements - Danh sách element cần xử lý
 * @param {boolean} status - true = enable, false = disable
 */
export function setElementsEnabled(elements = [], status = true) {

    if (!Array.isArray(elements)) return;

    elements.forEach(el => {

        if (!el) return;

        // chỉ set nếu element có thuộc tính disabled
        if ("disabled" in el) {
            el.disabled = !status;
        }

    });
}



// ================================
// ERROR DISPLAY
// Hiển thị lỗi và ẩn các section khác
// ================================

/**
 * Hiển thị section lỗi kèm message
 * và ẩn các section không liên quan
 *
 * @param {HTMLElement} section - Section hiển thị lỗi
 * @param {HTMLElement} messageEl - Element chứa nội dung lỗi
 * @param {string} message - Nội dung lỗi
 * @param {HTMLElement[]} hideSections - Các section cần ẩn
 */
export function showError(
    section,
    messageEl,
    message,
    hideSections = []
) {

    if (!section || !messageEl) return;

    // Set nội dung lỗi (cho phép HTML để hiển thị link nếu có)
    messageEl.innerHTML = message;

    // Hiện section lỗi
    setDisplay(section, "block");

    // Ẩn các section khác
    hideSections.forEach(el => {
        setDisplay(el, "none");
    });

    // Scroll tới vị trí lỗi
    section.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}



// ================================
// SHORT QUERY SELECTORS
// Rút gọn querySelector
// ================================

/**
 * querySelector rút gọn
 *
 * @param {string} s
 * @param {HTMLElement|Document} scope
 * @returns {HTMLElement|null}
 */
export const $ = (s, scope = document) =>
    scope.querySelector(s);


/**
 * querySelectorAll rút gọn
 *
 * @param {string} s
 * @param {HTMLElement|Document} scope
 * @returns {NodeListOf<Element>}
 */
export const $$ = (s, scope = document) =>
    scope.querySelectorAll(s);


/**
 * Render nội dung header kết quả vào một element.
 *
 * @param {HTMLElement} el - Phần tử DOM sẽ hiển thị kết quả.
 * @param {string} msg - Nội dung thông báo cần hiển thị.
 *
 * Nếu `el` không tồn tại thì hàm sẽ dừng ngay để tránh lỗi.
 * Khi hợp lệ, hàm sẽ chèn icon thành công và message vào bên trong element.
 */
export function renderSuccessHeader(el, msg) {
    if (!el) return;

    el.innerHTML = `
        <i class="fa-solid fa-circle-check result__icon--checked"></i>
        ${msg}
    `
}