/**
 * encode-decode.js
 * Encoding / Decoding Tools – Base64, URL, JWT
 * Module pattern với init() entry point.
 */

const EncodeDecode = (() => {
    // ===== STATE =====
    let currentMode = 'base64_enc';
    let lastOutput = '';

    // ===== DOM REFS =====
    const dom = {};

    // ===== MODE CONFIG =====
    const MODES = {
        base64_enc: {
            inputLabel: 'Input – Nhập văn bản cần mã hóa (Base64)',
            outputLabel: 'Output – Kết quả Base64 Encode',
            btnLabel: '<i class="fa-solid fa-lock"></i> Encode',
            placeholder: 'Nhập văn bản cần encode sang Base64...',
            jwtView: false,
        },
        base64_dec: {
            inputLabel: 'Input – Nhập chuỗi Base64 cần giải mã',
            outputLabel: 'Output – Văn bản sau khi giải mã',
            btnLabel: '<i class="fa-solid fa-lock-open"></i> Decode',
            placeholder: 'Nhập chuỗi Base64 cần decode...',
            jwtView: false,
        },
        url_enc: {
            inputLabel: 'Input – Nhập URL hoặc văn bản cần mã hóa',
            outputLabel: 'Output – Kết quả URL Encode',
            btnLabel: '<i class="fa-solid fa-link"></i> Encode',
            placeholder: 'Nhập URL hoặc văn bản cần URL encode...',
            jwtView: false,
        },
        url_dec: {
            inputLabel: 'Input – Nhập chuỗi URL Encoded cần giải mã',
            outputLabel: 'Output – Văn bản sau khi giải mã',
            btnLabel: '<i class="fa-solid fa-link-slash"></i> Decode',
            placeholder: 'Nhập chuỗi URL encoded cần decode...',
            jwtView: false,
        },
        jwt_dec: {
            inputLabel: 'Input – Nhập JWT Token cần phân tích',
            outputLabel: '',
            btnLabel: '<i class="fa-solid fa-key"></i> Decode JWT',
            placeholder: 'Nhập JWT Token vào đây (eyJ...)',
            jwtView: true,
            passView: false,
        },
        pass_gen: {
            inputLabel: '',
            outputLabel: 'Output – Mật khẩu được tạo',
            btnLabel: '<i class="fa-solid fa-wand-magic-sparkles"></i> Generate Password',
            placeholder: '',
            jwtView: false,
            passView: true,
        },
    };

    // ===== CORE LOGIC =====

    /**
     * Safe Base64 encode – handles Unicode characters
     */
    function base64Encode(str) {
        try {
            // TextEncoder giúp handle Unicode chuẩn
            const bytes = new TextEncoder().encode(str);
            let binary = '';
            bytes.forEach(b => binary += String.fromCharCode(b));
            return btoa(binary);
        } catch (e) {
            throw new Error('Không thể mã hóa: dữ liệu chứa ký tự không hợp lệ.');
        }
    }

    /**
     * Safe Base64 decode – handles Unicode characters
     */
    function base64Decode(str) {
        try {
            // Chuẩn hóa Base64Url sang Base64 chuẩn
            const std = str.replace(/-/g, '+').replace(/_/g, '/');
            const padded = std + '=='.slice(0, (4 - std.length % 4) % 4);
            const binary = atob(padded);
            const bytes = new Uint8Array(binary.length);
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i);
            }
            return new TextDecoder('utf-8').decode(bytes);
        } catch (e) {
            throw new Error('Chuỗi Base64 không hợp lệ. Vui lòng kiểm tra lại định dạng đầu vào.');
        }
    }

    /**
     * URL Encode – full encoding
     */
    function urlEncode(str) {
        try {
            return encodeURIComponent(str);
        } catch (e) {
            throw new Error('Không thể mã hóa URL: dữ liệu không hợp lệ.');
        }
    }

    /**
     * URL Decode
     */
    function urlDecode(str) {
        try {
            return decodeURIComponent(str);
        } catch (e) {
            throw new Error('Chuỗi URL Encoded không hợp lệ. Vui lòng kiểm tra dữ liệu đầu vào.');
        }
    }

    /**
     * JWT Decode – tách Header, Payload, Signature
     */
    function jwtDecode(token) {
        const parts = token.trim().split('.');
        if (parts.length !== 3) {
            throw new Error('JWT không đúng định dạng. Token JWT hợp lệ phải gồm 3 phần phân cách bằng dấu chấm (.)');
        }

        let header, payload;
        try {
            header = JSON.parse(base64Decode(parts[0]));
        } catch (e) {
            throw new Error('Không thể giải mã phần Header của JWT. Định dạng không hợp lệ.');
        }

        try {
            payload = JSON.parse(base64Decode(parts[1]));
        } catch (e) {
            throw new Error('Không thể giải mã phần Payload của JWT. Định dạng không hợp lệ.');
        }

        return {
            header,
            payload,
            signature: parts[2],
        };
    }
    
    /**
     * Password Generator – Cryptographically secure
     */
    function generatePassword() {
        const length = parseInt(dom.passLengthNum.value) || 16;
        const useUpper = dom.passUpper.checked;
        const useLower = dom.passLower.checked;
        const useNumbers = dom.passNumbers.checked;
        const useSpecial = dom.passSpecial.checked;
        const excludeAmbiguous = dom.passExcludeAmbiguous.checked;

        const upperChars = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // Exclude I, O by default for ambiguous if needed
        const lowerChars = "abcdefghijkmnopqrstuvwxyz"; // Exclude l, o
        const numberChars = "23456789"; // Exclude 1, 0
        const specialChars = "!@#$%^&*()_+~`|}{[]:;?><,./-=";

        let charset = "";
        if (useUpper) charset += excludeAmbiguous ? upperChars : "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        if (useLower) charset += excludeAmbiguous ? lowerChars : "abcdefghijklmnopqrstuvwxyz";
        if (useNumbers) charset += excludeAmbiguous ? numberChars : "0123456789";
        if (useSpecial) charset += specialChars;

        if (charset === "") {
            throw new Error('Vui lòng chọn ít nhất một loại ký tự để tạo mật khẩu.');
        }

        let password = "";
        const array = new Uint32Array(length);
        window.crypto.getRandomValues(array);

        for (let i = 0; i < length; i++) {
            password += charset[array[i] % charset.length];
        }

        return password;
    }

    /**
     * JSON Syntax Highlight – áp dụng code tokens của hệ thống
     */
    function highlightJson(obj) {
        const json = JSON.stringify(obj, null, 2);
        return json
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(
                /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
                (match) => {
                    let cls = 'code-value'; // number default
                    if (/^"/.test(match)) {
                        if (/:$/.test(match)) {
                            cls = 'code-keyword'; // key
                        } else {
                            cls = 'code-string'; // string value
                        }
                    } else if (/true|false/.test(match)) {
                        cls = 'code-func'; // boolean
                    } else if (/null/.test(match)) {
                        cls = 'code-comment'; // null
                    }
                    return `<span class="${cls}">${match}</span>`;
                }
            );
    }

    // ===== UI FUNCTIONS =====

    function showError(msg) {
        dom.encodeError.classList.remove('d-none');
        dom.encodeErrorMsg.textContent = msg;
    }

    function hideError() {
        dom.encodeError.classList.add('d-none');
    }

    function setOutput(content, isEmpty = false) {
        dom.encodeOutput.innerHTML = content;
        if (isEmpty) {
            dom.encodeOutput.classList.add('encode-tools__output--empty');
        } else {
            dom.encodeOutput.classList.remove('encode-tools__output--empty');
        }
    }

    function setJwtOutput(header, payload, signature) {
        // Header
        dom.jwtHeader.innerHTML = highlightJson(header);
        dom.jwtHeader.classList.remove('encode-tools__output--empty');

        // Payload – thêm phân tích timestamps nếu có
        const payloadWithInfo = { ...payload };

        // Annotate exp/iat/nbf thành thời gian đọc được
        ['exp', 'iat', 'nbf'].forEach(field => {
            if (payloadWithInfo[field]) {
                const dt = new Date(payloadWithInfo[field] * 1000);
                payloadWithInfo[`${field}_human`] = dt.toLocaleString('vi-VN', { timeZone: 'Asia/Ho_Chi_Minh' });
            }
        });

        dom.jwtPayload.innerHTML = highlightJson(payloadWithInfo);
        dom.jwtPayload.classList.remove('encode-tools__output--empty');

        // Signature
        dom.jwtSignature.textContent = signature;
        dom.jwtSignature.classList.remove('encode-tools__output--empty');
    }

    function resetJwtOutput() {
        dom.jwtHeader.innerHTML = 'Header sẽ hiển thị tại đây...';
        dom.jwtHeader.classList.add('encode-tools__output--empty');
        dom.jwtPayload.innerHTML = 'Payload sẽ hiển thị tại đây...';
        dom.jwtPayload.classList.add('encode-tools__output--empty');
        dom.jwtSignature.textContent = 'Signature sẽ hiển thị tại đây...';
        dom.jwtSignature.classList.add('encode-tools__output--empty');
    }

    function updateButtonStates() {
        const hasInput = dom.encodeInput.value.trim().length > 0;
        dom.btnConvert.disabled = (currentMode !== 'pass_gen' && !hasInput);
        dom.btnCopyOutput.disabled = !lastOutput;

        // Ẩn/hiện Swap & Clear theo có nội dung hay không
        // Nút Swap vô dụng với PassGen và JWT Decode nên sẽ ẩn luôn
        const isSwapUseless = currentMode === 'pass_gen' || currentMode === 'jwt_dec';
        dom.btnSwap.classList.toggle('d-none', !lastOutput || isSwapUseless);
        dom.btnClear.classList.toggle('d-none', !hasInput);
    }

    /**
     * Chuyển đổi giao diện khi chọn Mode mới
     */
    function applyMode(mode) {
        currentMode = mode;
        const config = MODES[mode];
        if (!config) return;

        // Cập nhật label và placeholder
        dom.inputLabel.textContent = config.inputLabel;
        dom.outputLabel.textContent = config.outputLabel;
        dom.btnConvertLabel.innerHTML = config.btnLabel;
        dom.encodeInput.placeholder = config.placeholder;

        // Toggle JWT view / PassGen view vs default view
        if (config.jwtView) {
            dom.outputSection.classList.add('d-none');
            dom.jwtSection.classList.remove('d-none');
            dom.inputSection.classList.remove('d-none');
            dom.passGenConfig.classList.add('d-none');
        } else if (config.passView) {
            dom.outputSection.classList.remove('d-none');
            dom.jwtSection.classList.add('d-none');
            dom.inputSection.classList.add('d-none'); // Hide text input for PassGen
            dom.passGenConfig.classList.remove('d-none');
        } else {
            dom.outputSection.classList.remove('d-none');
            dom.jwtSection.classList.add('d-none');
            dom.inputSection.classList.remove('d-none');
            dom.passGenConfig.classList.add('d-none');
        }

        // Reset outputs
        setOutput('Kết quả sẽ hiển thị tại đây...', true);
        resetJwtOutput();
        hideError();
        lastOutput = '';
        updateButtonStates();
    }

    /**
     * Thực hiện chuyển đổi theo mode hiện tại
     */
    function doConvert() {
        if (currentMode === 'pass_gen') {
            runTask();
            return;
        }

        const input = dom.encodeInput.value;
        if (!input.trim()) return;
        runTask();
    }

    function runTask() {
        hideError();
        lastOutput = '';

        try {
            let result;
            const input = dom.encodeInput.value;

            switch (currentMode) {
                case 'base64_enc':
                    result = base64Encode(input);
                    setOutput(escapeHtml(result));
                    lastOutput = result;
                    break;

                case 'base64_dec':
                    result = base64Decode(input);
                    setOutput(escapeHtml(result));
                    lastOutput = result;
                    break;

                case 'url_enc':
                    result = urlEncode(input);
                    setOutput(escapeHtml(result));
                    lastOutput = result;
                    break;

                case 'url_dec':
                    result = urlDecode(input);
                    setOutput(escapeHtml(result));
                    lastOutput = result;
                    break;

                case 'jwt_dec': {
                    const jwtResult = jwtDecode(input);
                    setJwtOutput(jwtResult.header, jwtResult.payload, jwtResult.signature);
                    lastOutput = JSON.stringify(jwtResult, null, 2);
                    break;
                }

                case 'pass_gen':
                    result = generatePassword();
                    setOutput(escapeHtml(result));
                    lastOutput = result;
                    break;

                default:
                    break;
            }
        } catch (err) {
            showError(err.message);
        }

        updateButtonStates();
    }

    /**
     * Swap output -> input
     */
    function doSwap() {
        if (!lastOutput) return;
        dom.encodeInput.value = lastOutput;
        setOutput('Kết quả sẽ hiển thị tại đây...', true);
        resetJwtOutput();
        lastOutput = '';
        hideError();
        updateButtonStates();
    }

    function escapeHtml(str) {
        return str
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    async function copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
        } catch (e) {
            // fallback
            const ta = document.createElement('textarea');
            ta.value = text;
            document.body.appendChild(ta);
            ta.select();
            document.execCommand('copy');
            document.body.removeChild(ta);
        }
    }

    // ===== INIT =====
    function init() {
        // Cache DOM elements
        dom.encodeInput    = document.getElementById('encodeInput');
        dom.encodeOutput   = document.getElementById('encodeOutput');
        dom.outputSection  = document.getElementById('outputSection');
        dom.jwtSection     = document.getElementById('jwtSection');
        dom.jwtHeader      = document.getElementById('jwtHeader');
        dom.jwtPayload     = document.getElementById('jwtPayload');
        dom.jwtSignature   = document.getElementById('jwtSignature');
        dom.encodeError    = document.getElementById('encodeError');
        dom.encodeErrorMsg = document.getElementById('encodeErrorMsg');
        dom.btnConvert     = document.getElementById('btnConvert');
        dom.btnSwap        = document.getElementById('btnSwap');
        dom.btnCopyOutput  = document.getElementById('btnCopyOutput');
        dom.btnClear       = document.getElementById('btnClear');
        dom.btnConvertLabel = document.getElementById('btnConvertLabel');
        dom.inputLabel     = document.getElementById('inputLabel');
        dom.outputLabel    = document.getElementById('outputLabel');
        dom.modeBtns       = document.querySelectorAll('.encode-tools__modes .btn');

        // PassGen elements
        dom.passGenConfig = document.getElementById('passGenConfig');
        dom.inputSection  = document.getElementById('inputSection');
        dom.passUpper     = document.getElementById('passUpper');
        dom.passLower     = document.getElementById('passLower');
        dom.passNumbers   = document.getElementById('passNumbers');
        dom.passSpecial   = document.getElementById('passSpecial');
        dom.passLengthNum = document.getElementById('passLengthNum');
        dom.passLengthRange = document.getElementById('passLengthRange');
        dom.passExcludeAmbiguous = document.getElementById('passExcludeAmbiguous');

        // Mode button click
        dom.modeBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                dom.modeBtns.forEach(b => {
                    b.classList.remove('btn-action');
                    b.classList.add('btn-outline');
                });
                btn.classList.add('btn-action');
                btn.classList.remove('btn-outline');
                applyMode(btn.dataset.mode);
            });
        });

        // Input realtime → clear error, update button state
        dom.encodeInput.addEventListener('input', () => {
            hideError();
            // Clear output khi input thay đổi
            if (lastOutput) {
                setOutput('Kết quả sẽ hiển thị tại đây...', true);
                resetJwtOutput();
                lastOutput = '';
            }
            updateButtonStates();
        });

        // Convert button
        dom.btnConvert.addEventListener('click', doConvert);

        // Also convert on Ctrl+Enter
        dom.encodeInput.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                doConvert();
            }
        });

        // Swap button
        dom.btnSwap.addEventListener('click', doSwap);

        // Copy output
        dom.btnCopyOutput.addEventListener('click', async () => {
            if (!lastOutput) return;
            await copyToClipboard(lastOutput);
            const originalHTML = dom.btnCopyOutput.innerHTML;
            dom.btnCopyOutput.innerHTML = '<i class="fa-solid fa-check"></i> Đã copy!';
            setTimeout(() => {
                dom.btnCopyOutput.innerHTML = originalHTML;
            }, 1800);
        });

        // Clear
        dom.btnClear.addEventListener('click', () => {
            dom.encodeInput.value = '';
            setOutput('Kết quả sẽ hiển thị tại đây...', true);
            resetJwtOutput();
            hideError();
            lastOutput = '';
            updateButtonStates();
        });

        // Sync length number and range
        dom.passLengthNum?.addEventListener('input', (e) => {
            dom.passLengthRange.value = e.target.value;
        });
        dom.passLengthRange?.addEventListener('input', (e) => {
            dom.passLengthNum.value = e.target.value;
        });

        // Initial state
        applyMode('base64_enc');
    }

    return { init };
})();

document.addEventListener('DOMContentLoaded', EncodeDecode.init);
