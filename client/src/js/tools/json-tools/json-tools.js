// =================================//
//  JSON DATA TOOLS - MAIN JAVASCRIPT
//==================================//
import {
    setDisplay,
    showElements,
    hide,
    show,
    escapeHTML,
} from "../../utils/index.js";
import { API_BASE_URL } from "../../config.js";

// =================================//
//  INIT PATTERN
//==================================//
function init() {
    // ---- DOM Cache ----
    const tabs = document.querySelectorAll(".json-tools__tab");
    const panels = document.querySelectorAll(".json-tools__panel");
    const errorCard = document.getElementById("errorCard");
    const errorMessage = document.getElementById("errorMessage");

    // Formatter
    const formatterInput = document.getElementById("formatterInput");
    const formatterOutput = document.getElementById("formatterOutput");
    const btnFormat = document.getElementById("btnFormat");
    const btnFormat4 = document.getElementById("btnFormat4");
    const btnMinify = document.getElementById("btnMinify");
    const btnCopyFormatter = document.getElementById("btnCopyFormatter");
    const btnClearFormatter = document.getElementById("btnClearFormatter");
    const formatterStats = document.getElementById("formatterStats");
    const formatterSize = document.getElementById("formatterSize");
    const formatterKeys = document.getElementById("formatterKeys");
    const formatterDepth = document.getElementById("formatterDepth");

    // Validator
    const validatorInput = document.getElementById("validatorInput");
    const validatorOutput = document.getElementById("validatorOutput");
    const btnValidate = document.getElementById("btnValidate");
    const btnClearValidator = document.getElementById("btnClearValidator");

    // Diff
    const diffInputLeft = document.getElementById("diffInputLeft");
    const diffInputRight = document.getElementById("diffInputRight");
    const btnSwapDiff = document.getElementById("btnSwapDiff");
    const btnClearDiff = document.getElementById("btnClearDiff");
    const btnDiffSplit = document.getElementById("btnDiffSplit");
    const btnDiffUnified = document.getElementById("btnDiffUnified");
    const diffResult = document.getElementById("diffResult");
    const diffSplitView = document.getElementById("diffSplitView");
    const diffUnifiedView = document.getElementById("diffUnifiedView");
    const diffSplitLeft = document.getElementById("diffSplitLeft");
    const diffSplitRight = document.getElementById("diffSplitRight");
    const diffAdded = document.getElementById("diffAdded");
    const diffRemoved = document.getElementById("diffRemoved");
    const diffModified = document.getElementById("diffModified");

    // To Go Struct
    const toGoInput = document.getElementById("toGoInput");
    const toGoOutput = document.getElementById("toGoOutput");
    const btnConvertGo = document.getElementById("btnConvertGo");
    const btnCopyGo = document.getElementById("btnCopyGo");
    const btnClearGo = document.getElementById("btnClearGo");
    const toGoLoading = document.getElementById("toGoLoading");

    // To YAML
    const toYamlInput = document.getElementById("toYamlInput");
    const toYamlOutput = document.getElementById("toYamlOutput");
    const btnConvertYaml = document.getElementById("btnConvertYaml");
    const btnCopyYaml = document.getElementById("btnCopyYaml");
    const btnClearYaml = document.getElementById("btnClearYaml");
    const toYamlLoading = document.getElementById("toYamlLoading");

    // State
    let currentDiffView = "split";
    let diffDebounceTimer = null;

    // =================================//
    //  BUTTON STATE MANAGEMENT
    //==================================//
    function updateButtonStates() {
        const formatterEmpty = formatterInput.value.trim() === '';
        btnFormat.disabled = formatterEmpty;
        btnFormat4.disabled = formatterEmpty;
        btnMinify.disabled = formatterEmpty;
        btnClearFormatter.disabled = formatterEmpty;
        btnCopyFormatter.disabled = formatterEmpty;

        const validatorEmpty = validatorInput.value.trim() === '';
        btnValidate.disabled = validatorEmpty;
        btnClearValidator.disabled = validatorEmpty;

        const diffEmpty = diffInputLeft.value.trim() === '' && diffInputRight.value.trim() === '';
        btnSwapDiff.disabled = diffEmpty;
        btnClearDiff.disabled = diffEmpty;

        const toGoEmpty = toGoInput.value.trim() === '';
        btnConvertGo.disabled = toGoEmpty;
        btnClearGo.disabled = toGoEmpty;
        btnCopyGo.disabled = toGoEmpty;

        const toYamlEmpty = toYamlInput.value.trim() === '';
        btnConvertYaml.disabled = toYamlEmpty;
        btnClearYaml.disabled = toYamlEmpty;
        btnCopyYaml.disabled = toYamlEmpty;
    }

    // Call on load
    updateButtonStates();

    // =================================//
    //  TAB SWITCHING
    //==================================//
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const target = tab.dataset.tab;

            // Deactivate all
            tabs.forEach(t => {
                t.classList.remove("json-tools__tab--active");
                t.setAttribute("aria-selected", "false");
            });
            panels.forEach(p => p.classList.remove("json-tools__panel--active"));

            // Activate clicked
            tab.classList.add("json-tools__tab--active");
            tab.setAttribute("aria-selected", "true");

            const panel = document.getElementById(`panel-${target}`);
            if (panel) {
                panel.classList.add("json-tools__panel--active");
            }

            // Hide error card on tab switch
            hide(errorCard);
        });
    });

    // =================================//
    //  UTILITY: JSON Analysis
    //==================================//
    function countKeys(obj) {
        let count = 0;
        if (typeof obj === "object" && obj !== null) {
            if (Array.isArray(obj)) {
                obj.forEach(item => {
                    count += countKeys(item);
                });
            } else {
                for (const key in obj) {
                    count++;
                    count += countKeys(obj[key]);
                }
            }
        }
        return count;
    }

    function getDepth(obj) {
        if (typeof obj !== "object" || obj === null) return 0;
        let maxChildDepth = 0;
        const children = Array.isArray(obj) ? obj : Object.values(obj);
        for (const child of children) {
            const childDepth = getDepth(child);
            if (childDepth > maxChildDepth) maxChildDepth = childDepth;
        }
        return 1 + maxChildDepth;
    }

    // =================================//
    //  SYNTAX HIGHLIGHTING (JSON)
    //==================================//
    function highlightJSON(json) {
        const escaped = escapeHTML(json);
        return escaped.replace(
            /("(?:\\.|[^"\\])*")\s*(:)?|(\b(?:true|false)\b)|(\bnull\b)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
            (match, str, colon, bool, nil, num) => {
                if (str) {
                    if (colon) {
                        return `<span class="json-key">${str}</span>:`;
                    }
                    return `<span class="json-string">${str}</span>`;
                }
                if (bool) return `<span class="json-boolean">${match}</span>`;
                if (nil) return `<span class="json-null">${match}</span>`;
                if (num) return `<span class="json-number">${match}</span>`;
                return match;
            }
        );
    }

    function highlightGo(code) {
        const escaped = escapeHTML(code);
        return escaped
            // Go keywords
            .replace(/\b(type|struct|string|int|int64|float64|bool|interface|map|package)\b/g, '<span class="go-keyword">$1</span>')
            // JSON tags
            .replace(/(`json:"[^"]*"`)/g, '<span class="go-tag">$1</span>')
            // Comments
            .replace(/(\/\/.*)/g, '<span class="go-comment">$1</span>');
    }

    function highlightYAML(code) {
        const escaped = escapeHTML(code);
        return escaped
            // YAML keys (word followed by colon)
            .replace(/^(\s*)([\w.-]+)(\s*:)/gm, '$1<span class="yaml-key">$2</span>$3')
            // Strings in quotes
            .replace(/("[^"]*"|'[^']*')/g, '<span class="yaml-string">$1</span>')
            // Booleans
            .replace(/:\s+(true|false)\s*$/gm, ': <span class="yaml-boolean">$1</span>')
            // Null
            .replace(/:\s+(null|~)\s*$/gm, ': <span class="yaml-null">$1</span>')
            // Numbers
            .replace(/:\s+(-?\d+(?:\.\d+)?)\s*$/gm, ': <span class="yaml-number">$1</span>')
            // Comments
            .replace(/(#.*)/g, '<span class="yaml-comment">$1</span>');
    }

    // =================================//
    //  SHOW ERROR
    //==================================//
    function showToolError(msg) {
        if (errorMessage) errorMessage.innerHTML = msg;
        show(errorCard);
        errorCard.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function hideError() {
        hide(errorCard);
    }

    // =================================//
    //  ERROR TRANSLATION
    //==================================//
    function translateJSONError(msg, raw) {
        let text = msg || "";
        
        // Remove browser-native (line X column Y)
        text = text.replace(/\s*\(line\s+\d+\s+column\s+\d+\)\s*/i, "");

        // Extract position
        const posMatch = text.match(/position\s+(\d+)/i) || text.match(/at position\s+(\d+)/i);
        let lineInfoStr = "";
        if (posMatch) {
            const pos = parseInt(posMatch[1], 10);
            const lineInfo = getLineCol(raw, pos);
            lineInfoStr = `<br><strong>Vị trí:</strong> Dòng ${lineInfo.line}, Cột ${lineInfo.col}`;
        }

        // Translate common tokens intuitively
        text = text.replace(/Unexpected token '([^']+)',/i, "Ký tự không hợp lệ '$1',");
        text = text.replace(/Unexpected token ([^ ]+) in JSON/i, "Ký tự không hợp lệ '$1'");
        text = text.replace(/Expected double-quoted property name in JSON/i, "Các key (thuộc tính) phải được đặt trong dấu ngoặc kép");
        text = text.replace(/Expected ',' or '\}' after property value in JSON/i, "Thiếu dấu phẩy ',' hoặc ngoặc nhọn '}' sau giá trị");
        text = text.replace(/Expected ':' after property name in JSON/i, "Thiếu dấu hai chấm ':' (hoặc gõ sai ngoặc kép '\"' bên trong key)");
        text = text.replace(/Unexpected end of JSON input/i, "Cấu trúc JSON bị thiếu hoặc chưa đóng ngoặc kết thúc");
        text = text.replace(/Unexpected string in JSON/i, "Chuỗi ký tự không đúng định dạng");
        text = text.replace(/Unexpected number in JSON/i, "Giá trị số không hợp lệ");
        text = text.replace(/is not valid JSON/i, "không phải là định dạng JSON hợp lệ");
        
        text = text.replace(/at position \d+/i, ""); 
        text = text.replace(/in JSON/i, "");
        text = text.replace(/\s+/g, " ").trim();

        return `<code>${escapeHTML(text)}</code>${lineInfoStr}`;
    }

    // =================================//
    //  FORMATTER / MINIFY LOGIC
    //==================================//
    function formatJSON(spaces) {
        hideError();
        const raw = formatterInput.value.trim();
        if (!raw) {
            formatterOutput.innerHTML = "Kết quả sẽ hiển thị tại đây...";
            formatterOutput.classList.add("json-tools__output--empty");
            hide(formatterStats);
            return;
        }

        try {
            const parsed = JSON.parse(raw);
            const formatted = JSON.stringify(parsed, null, spaces);
            formatterOutput.innerHTML = highlightJSON(formatted);
            formatterOutput.classList.remove("json-tools__output--empty");

            // Stats
            const byteSize = new Blob([formatted]).size;
            formatterSize.textContent = byteSize.toLocaleString();
            formatterKeys.textContent = countKeys(parsed);
            formatterDepth.textContent = getDepth(parsed);
            setDisplay(formatterStats, "flex");
        } catch (e) {
            showToolError(`JSON không hợp lệ: ${translateJSONError(e.message, raw)}`);
            formatterOutput.innerHTML = "";
            formatterOutput.classList.add("json-tools__output--empty");
        }
    }

    function minifyJSON() {
        hideError();
        const raw = formatterInput.value.trim();
        if (!raw) return;

        try {
            const parsed = JSON.parse(raw);
            const minified = JSON.stringify(parsed);
            formatterOutput.textContent = minified;
            formatterOutput.classList.remove("json-tools__output--empty");

            const byteSize = new Blob([minified]).size;
            formatterSize.textContent = byteSize.toLocaleString();
            formatterKeys.textContent = countKeys(parsed);
            formatterDepth.textContent = getDepth(parsed);
            setDisplay(formatterStats, "flex");
        } catch (e) {
            showToolError(`JSON không hợp lệ: ${translateJSONError(e.message, raw)}`);
        }
    }

    btnFormat.addEventListener("click", () => formatJSON(2));
    btnFormat4.addEventListener("click", () => formatJSON(4));
    btnMinify.addEventListener("click", minifyJSON);

    btnCopyFormatter.addEventListener("click", () => {
        const text = formatterOutput.textContent;
        if (!text || formatterOutput.classList.contains("json-tools__output--empty")) return;
        copyToClipboard(text, btnCopyFormatter);
    });

    btnClearFormatter.addEventListener("click", () => {
        formatterInput.value = "";
        formatterOutput.innerHTML = "Kết quả sẽ hiển thị tại đây...";
        formatterOutput.classList.add("json-tools__output--empty");
        hide(formatterStats);
        hideError();
    });

    // =================================//
    //  VALIDATOR LOGIC
    //==================================//
    btnValidate.addEventListener("click", () => {
        hideError();
        const raw = validatorInput.value.trim();
        if (!raw) {
            validatorOutput.innerHTML = "Kết quả validate sẽ hiển thị tại đây...";
            validatorOutput.classList.add("json-tools__validator-box--empty");
            return;
        }

        try {
            const parsed = JSON.parse(raw);
            validatorOutput.classList.remove("json-tools__validator-box--empty");

            const keys = countKeys(parsed);
            const depth = getDepth(parsed);
            const type = Array.isArray(parsed) ? "Array" : typeof parsed === "object" ? "Object" : typeof parsed;
            const byteSize = new Blob([raw]).size;

            validatorOutput.innerHTML = `
                <div class="message-card message-card--success">
                    <div class="message-card__header">
                        <h4 class="message-card__title">
                            <i class="fa-solid fa-circle-check"></i> JSON hợp lệ!
                        </h4>
                    </div>
                    <div class="message-card__body">
                        <p class="message-card__message">
                            <strong>Kiểu dữ liệu:</strong> ${type}<br>
                            <strong>Tổng keys:</strong> ${keys}<br>
                            <strong>Độ sâu:</strong> ${depth}<br>
                            <strong>Kích thước:</strong> ${byteSize.toLocaleString()} bytes
                        </p>
                    </div>
                </div>
            `;
        } catch (e) {
            validatorOutput.classList.remove("json-tools__validator-box--empty");
            validatorInput.classList.add("is-invalid");

            // Extract position and natively highlight the error character
            const posMatch = e.message.match(/position\s+(\d+)/i) || e.message.match(/at position\s+(\d+)/i);
            if (posMatch) {
                const pos = parseInt(posMatch[1], 10);
                // Highlight the error character in textarea natively (with a slight delay to ensure UI updates)
                setTimeout(() => {
                    validatorInput.focus();
                    
                    // If error is at the end of the input, select the last char, otherwise select the specific char
                    const startPos = Math.min(pos, raw.length - 1);
                    validatorInput.setSelectionRange(startPos, startPos + 1);
                }, 50);
            }

            validatorOutput.innerHTML = `
                <div class="message-card message-card--error">
                    <div class="message-card__header">
                        <h4 class="message-card__title">
                            <i class="fa-solid fa-triangle-exclamation"></i> JSON không hợp lệ!
                        </h4>
                    </div>
                    <div class="message-card__body">
                        <p class="message-card__message">
                            <strong>Lỗi phân tích:</strong> ${translateJSONError(e.message, raw)}
                        </p>
                    </div>
                </div>
            `;
        }
    });

    // Reset errors and manage button states on type
    const allInputs = document.querySelectorAll(".json-tools__input");
    allInputs.forEach(input => {
        input.addEventListener("input", () => {
            updateButtonStates();
            hideError();
            if (input === validatorInput && validatorInput.classList.contains("is-invalid")) {
                validatorInput.classList.remove("is-invalid");
                validatorOutput.innerHTML = "Kết quả validate sẽ hiển thị tại đây...";
                validatorOutput.classList.add("json-tools__validator-box--empty");
            }
            if (input === formatterInput) {
                hide(formatterStats);
            }
        });
    });

    btnClearValidator.addEventListener("click", () => {
        validatorInput.value = "";
        validatorInput.classList.remove("is-invalid");
        validatorOutput.innerHTML = "Kết quả validate sẽ hiển thị tại đây...";
        validatorOutput.classList.add("json-tools__validator-box--empty");
        hideError();
    });

    function getLineCol(str, pos) {
        const lines = str.substring(0, pos).split("\n");
        return { line: lines.length, col: lines[lines.length - 1].length + 1 };
    }

    // =================================//
    //  DIFF COMPARE LOGIC
    //==================================//
    function flattenJSON(obj, prefix = "") {
        const result = {};
        if (typeof obj !== "object" || obj === null) {
            result[prefix || "(root)"] = obj;
            return result;
        }
        if (Array.isArray(obj)) {
            if (obj.length === 0) {
                result[prefix || "(root)"] = [];
                return result;
            }
            obj.forEach((item, index) => {
                const key = prefix ? `${prefix}[${index}]` : `[${index}]`;
                Object.assign(result, flattenJSON(item, key));
            });
        } else {
            const keys = Object.keys(obj);
            if (keys.length === 0) {
                result[prefix || "(root)"] = {};
                return result;
            }
            keys.forEach(k => {
                const key = prefix ? `${prefix}.${k}` : k;
                Object.assign(result, flattenJSON(obj[k], key));
            });
        }
        return result;
    }

    function computeDiff(leftObj, rightObj) {
        const leftFlat = flattenJSON(leftObj);
        const rightFlat = flattenJSON(rightObj);
        const allKeys = new Set([...Object.keys(leftFlat), ...Object.keys(rightFlat)]);

        const added = [];
        const removed = [];
        const modified = [];
        const unchanged = [];

        allKeys.forEach(key => {
            const inLeft = key in leftFlat;
            const inRight = key in rightFlat;

            if (inLeft && inRight) {
                const lv = JSON.stringify(leftFlat[key]);
                const rv = JSON.stringify(rightFlat[key]);
                if (lv === rv) {
                    unchanged.push({ key, value: leftFlat[key] });
                } else {
                    modified.push({ key, oldValue: leftFlat[key], newValue: rightFlat[key] });
                }
            } else if (inLeft && !inRight) {
                removed.push({ key, value: leftFlat[key] });
            } else {
                added.push({ key, value: rightFlat[key] });
            }
        });

        return { added, removed, modified, unchanged };
    }

    function renderDiffLine(type, key, value, prefix = "") {
        const typeClass = `json-tools__diff-line--${type}`;
        const symbol = type === "added" ? "+" : type === "removed" ? "-" : type === "modified" ? "~" : " ";
        const displayValue = typeof value === "string" ? `"${escapeHTML(value)}"` : escapeHTML(JSON.stringify(value));
        return `<div class="json-tools__diff-line ${typeClass}">
            <span class="json-tools__line-num">${symbol}</span>${prefix}<strong>${escapeHTML(key)}</strong>: ${displayValue}
        </div>`;
    }

    function renderDiff() {
        const leftRaw = diffInputLeft.value.trim();
        const rightRaw = diffInputRight.value.trim();

        if (!leftRaw || !rightRaw) {
            hide(diffResult);
            return;
        }

        let leftObj, rightObj;
        try {
            leftObj = JSON.parse(leftRaw);
        } catch (e) {
            showToolError(`JSON gốc (Original) không hợp lệ: ${translateJSONError(e.message, leftRaw)}`);
            hide(diffResult);
            return;
        }
        try {
            rightObj = JSON.parse(rightRaw);
        } catch (e) {
            showToolError(`JSON chỉnh sửa (Modified) không hợp lệ: ${translateJSONError(e.message, rightRaw)}`);
            hide(diffResult);
            return;
        }

        hideError();
        const diff = computeDiff(leftObj, rightObj);

        // Update summary
        diffAdded.textContent = diff.added.length;
        diffRemoved.textContent = diff.removed.length;
        diffModified.textContent = diff.modified.length;

        // Check if identical
        if (diff.added.length === 0 && diff.removed.length === 0 && diff.modified.length === 0) {
            show(diffResult);
            diffSplitLeft.innerHTML = `<div class="json-tools__diff-line json-tools__diff-line--unchanged">Hai JSON hoàn toàn giống nhau.</div>`;
            diffSplitRight.innerHTML = `<div class="json-tools__diff-line json-tools__diff-line--unchanged">Hai JSON hoàn toàn giống nhau.</div>`;
            diffUnifiedView.innerHTML = `<div class="json-tools__diff-line json-tools__diff-line--unchanged">Hai JSON hoàn toàn giống nhau.</div>`;
            return;
        }

        show(diffResult);

        // Split View
        let leftHtml = "";
        let rightHtml = "";
        let unifiedHtml = "";

        // Removed (only in left)
        diff.removed.forEach(item => {
            leftHtml += renderDiffLine("removed", item.key, item.value);
            rightHtml += `<div class="json-tools__diff-line json-tools__diff-line--removed"><span class="json-tools__line-num">-</span>&nbsp;</div>`;
            unifiedHtml += renderDiffLine("removed", item.key, item.value, "");
        });

        // Modified
        diff.modified.forEach(item => {
            leftHtml += renderDiffLine("modified", item.key, item.oldValue);
            rightHtml += renderDiffLine("modified", item.key, item.newValue);
            unifiedHtml += `<div class="json-tools__diff-line json-tools__diff-line--removed">
                <span class="json-tools__line-num">-</span><strong>${escapeHTML(item.key)}</strong>: ${escapeHTML(JSON.stringify(item.oldValue))}
            </div>`;
            unifiedHtml += `<div class="json-tools__diff-line json-tools__diff-line--added">
                <span class="json-tools__line-num">+</span><strong>${escapeHTML(item.key)}</strong>: ${escapeHTML(JSON.stringify(item.newValue))}
            </div>`;
        });

        // Added (only in right)
        diff.added.forEach(item => {
            leftHtml += `<div class="json-tools__diff-line json-tools__diff-line--added"><span class="json-tools__line-num">+</span>&nbsp;</div>`;
            rightHtml += renderDiffLine("added", item.key, item.value);
            unifiedHtml += renderDiffLine("added", item.key, item.value, "");
        });

        // Unchanged
        diff.unchanged.forEach(item => {
            const line = renderDiffLine("unchanged", item.key, item.value);
            leftHtml += line;
            rightHtml += line;
            unifiedHtml += line;
        });

        diffSplitLeft.innerHTML = leftHtml;
        diffSplitRight.innerHTML = rightHtml;
        diffUnifiedView.innerHTML = unifiedHtml;

        // Sync scroll (Split View)
        syncScroll(diffSplitLeft, diffSplitRight);
    }

    function syncScroll(el1, el2) {
        let isScrolling = false;
        el1.addEventListener("scroll", () => {
            if (isScrolling) return;
            isScrolling = true;
            el2.scrollTop = el1.scrollTop;
            requestAnimationFrame(() => { isScrolling = false; });
        });
        el2.addEventListener("scroll", () => {
            if (isScrolling) return;
            isScrolling = true;
            el1.scrollTop = el2.scrollTop;
            requestAnimationFrame(() => { isScrolling = false; });
        });
    }

    // Auto-compare with debounce
    function debounceDiff() {
        clearTimeout(diffDebounceTimer);
        diffDebounceTimer = setTimeout(renderDiff, 300);
    }

    diffInputLeft.addEventListener("input", debounceDiff);
    diffInputRight.addEventListener("input", debounceDiff);

    btnSwapDiff.addEventListener("click", () => {
        const temp = diffInputLeft.value;
        diffInputLeft.value = diffInputRight.value;
        diffInputRight.value = temp;
        renderDiff();
    });

    btnClearDiff.addEventListener("click", () => {
        diffInputLeft.value = "";
        diffInputRight.value = "";
        hide(diffResult);
        hideError();
    });

    // Diff view toggle
    btnDiffSplit.addEventListener("click", () => {
        currentDiffView = "split";
        btnDiffSplit.classList.add("json-tools__diff-view-btn--active", "btn-action");
        btnDiffUnified.classList.remove("json-tools__diff-view-btn--active", "btn-action");
        show(diffSplitView);
        hide(diffUnifiedView);
    });

    btnDiffUnified.addEventListener("click", () => {
        currentDiffView = "unified";
        btnDiffUnified.classList.add("json-tools__diff-view-btn--active", "btn-action");
        btnDiffSplit.classList.remove("json-tools__diff-view-btn--active", "btn-action");
        hide(diffSplitView);
        show(diffUnifiedView);
    });

    // =================================//
    //  TO GO STRUCT – Backend API
    //==================================//
    btnConvertGo.addEventListener("click", async () => {
        hideError();
        const raw = toGoInput.value.trim();
        if (!raw) return;

        // Validate locally first
        try {
            JSON.parse(raw);
        } catch (e) {
            showToolError(`JSON không hợp lệ: ${translateJSONError(e.message, raw)}`);
            return;
        }

        btnConvertGo.disabled = true;
        setDisplay(toGoLoading, "inline-block");

        try {
            const response = await fetch(`${API_BASE_URL}/json/to-go`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ json: raw }),
            });
            const data = await response.json();

            if (!data.success) {
                showToolError(data.message || data.error || "Lỗi chuyển đổi Go Struct");
                return;
            }

            toGoOutput.innerHTML = highlightGo(data.data.result);
            toGoOutput.classList.remove("json-tools__output--empty");
        } catch (e) {
            showToolError("Lỗi kết nối server. Vui lòng thử lại!");
        } finally {
            btnConvertGo.disabled = toGoInput.value.trim() === '';
            hide(toGoLoading);
        }
    });

    btnCopyGo.addEventListener("click", () => {
        const text = toGoOutput.textContent;
        if (!text || toGoOutput.classList.contains("json-tools__output--empty")) return;
        copyToClipboard(text, btnCopyGo);
    });

    btnClearGo.addEventListener("click", () => {
        toGoInput.value = "";
        toGoOutput.innerHTML = "Go Struct sẽ hiển thị tại đây...";
        toGoOutput.classList.add("json-tools__output--empty");
        hideError();
    });

    // =================================//
    //  TO YAML – Backend API
    //==================================//
    btnConvertYaml.addEventListener("click", async () => {
        hideError();
        const raw = toYamlInput.value.trim();
        if (!raw) return;

        try {
            JSON.parse(raw);
        } catch (e) {
            showToolError(`JSON không hợp lệ: ${translateJSONError(e.message, raw)}`);
            return;
        }

        btnConvertYaml.disabled = true;
        setDisplay(toYamlLoading, "inline-block");

        try {
            const response = await fetch(`${API_BASE_URL}/json/to-yaml`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ json: raw }),
            });
            const data = await response.json();

            if (!data.success) {
                showToolError(data.message || data.error || "Lỗi chuyển đổi YAML");
                return;
            }

            toYamlOutput.innerHTML = highlightYAML(data.data.result);
            toYamlOutput.classList.remove("json-tools__output--empty");
        } catch (e) {
            showToolError("Lỗi kết nối server. Vui lòng thử lại!");
        } finally {
            btnConvertYaml.disabled = toYamlInput.value.trim() === '';
            hide(toYamlLoading);
        }
    });

    btnCopyYaml.addEventListener("click", () => {
        const text = toYamlOutput.textContent;
        if (!text || toYamlOutput.classList.contains("json-tools__output--empty")) return;
        copyToClipboard(text, btnCopyYaml);
    });

    btnClearYaml.addEventListener("click", () => {
        toYamlInput.value = "";
        toYamlOutput.innerHTML = "YAML sẽ hiển thị tại đây...";
        toYamlOutput.classList.add("json-tools__output--empty");
        hideError();
    });

    // =================================//
    //  CLIPBOARD HELPER
    //==================================//
    function copyToClipboard(text, btn) {
        navigator.clipboard.writeText(text).then(() => {
            const icon = btn.querySelector("i");
            const originalClass = icon.className;
            icon.className = "fa-solid fa-check";
            btn.classList.add("btn-success");

            setTimeout(() => {
                icon.className = originalClass;
                btn.classList.remove("btn-success");
            }, 1500);
        }).catch(() => {
            // Fallback
            const textarea = document.createElement("textarea");
            textarea.value = text;
            textarea.style.position = "fixed";
            textarea.style.opacity = "0";
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand("copy");
            document.body.removeChild(textarea);
        });
    }
}

document.addEventListener("DOMContentLoaded", init);
