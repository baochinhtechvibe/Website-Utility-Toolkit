import { 
    $, 
    $$, 
    escapeHTML,
    copyToClipboard
} from "../../utils/index.js";

const EncodeDecode = (() => {
    // ===== STATE =====
    let currentMode = 'base64_enc';
    let lastOutput = '';

    // Cache cho random values dùng batching
    let rndBatch = new Uint32Array(0);
    let rndIdx = 0;

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
            jwtView: true
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
            // Tính toán số lượng padding cần thiết để chia hết cho 4
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
     * Lấy số nguyên ngẫu nhiên trong khoảng [0, max - 1] 
     * Sử dụng rejection sampling để loại bỏ hoàn toàn modulo bias.
     */
    function getSecureRandomInt(max) {
        if (max <= 1) return 0;
        const maxRange = Math.floor(4294967296 / max) * max;
        let randomVal;
        
        do {
            if (rndIdx >= rndBatch.length) {
                // Tự động refill batch nếu hết (hoặc lần đầu gọi)
                // Lấy 256 phần tử một lần cho bốc
                rndBatch = window.crypto.getRandomValues(new Uint32Array(256));
                rndIdx = 0;
            }
            randomVal = rndBatch[rndIdx++];
        } while (randomVal >= maxRange);
        
        return randomVal % max;
    }

    /**
     * Fisher-Yates Shuffle – Trộn mảng không bias dùng crypto
     */
    function secureShuffle(arr) {
        if (!arr.length) return arr;
        for (let i = arr.length - 1; i > 0; i--) {
            const j = getSecureRandomInt(i + 1);
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr;
    }
    
    /**
     * Password Generator – Cryptographically secure
     */
    function generatePassword(length, options) {
        const charSets = {
            uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            lowercase: "abcdefghijklmnopqrstuvwxyz",
            numbers: "0123456789",
            symbols: "!@#$%^&*()_+~`|}{[]:;?><,./-="
        };

        const AMBIGUOUS = /[Il1O0o]/g;
        let allChars = "";
        const guaranteedChars = [];

        // Lọc charset và đảm bảo mỗi loại có ít nhất 1 ký tự
        Object.keys(options).forEach(key => {
            if (options[key] && charSets[key]) {
                const set = options.excludeAmbiguous 
                    ? charSets[key].replace(AMBIGUOUS, '') 
                    : charSets[key];

                if (set.length === 0) return;

                allChars += set;
                // Lấy 1 ký tự ngẫu nhiên bảo đảm an toàn tuyệt đối (no bias)
                guaranteedChars.push(set[getSecureRandomInt(set.length)]);
            }
        });

        if (allChars === "") {
            throw new Error('Vui lòng chọn ít nhất một loại ký tự để tạo mật khẩu.');
        }

        if (length < guaranteedChars.length) {
            throw new Error(`Độ dài mật khẩu tối thiểu cho các tùy chọn đã chọn là ${guaranteedChars.length}.`);
        }

        // Tạo các ký tự còn lại
        const remainingLength = length - guaranteedChars.length;
        let passwordArray = [...guaranteedChars];

        if (remainingLength > 0) {
            for (let i = 0; i < remainingLength; i++) {
                passwordArray.push(allChars[getSecureRandomInt(allChars.length)]);
            }
        }

        // Trộn mảng mật khẩu bằng Fisher-Yates (không bias)
        return secureShuffle(passwordArray).join("");
    }

    /**
     * JSON Syntax Highlight – áp dụng code tokens của hệ thống
     */
    function highlightJson(obj) {
        // Bước 1: Stringify và Escape HTML các ký tự đặc biệt trước
        const escapedJson = JSON.stringify(obj, null, 2)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');

        // Bước 2: Highlight dựa trên chuỗi đã được escape
        // Tối ưu regex để tránh bọc span vào các entity HTML (như &amp;) trong string
        return escapedJson.replace(
            /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*?"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
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
            // Chỉ trim cho decode và JWT, không trim cho encode để giữ nguyên khoảng trắng nếu user cần
            const input = ['base64_dec', 'url_dec', 'jwt_dec'].includes(currentMode)
                ? dom.encodeInput.value.trim()
                : dom.encodeInput.value;

            switch (currentMode) {
                case 'base64_enc':
                    result = base64Encode(input);
                    setOutput(escapeHTML(result));
                    lastOutput = result;
                    break;

                case 'base64_dec':
                    result = base64Decode(input);
                    setOutput(escapeHTML(result));
                    lastOutput = result;
                    break;

                case 'url_enc':
                    result = urlEncode(input);
                    setOutput(escapeHTML(result));
                    lastOutput = result;
                    break;

                case 'url_dec':
                    result = urlDecode(input);
                    setOutput(escapeHTML(result));
                    lastOutput = result;
                    break;

                case 'jwt_dec': {
                    const jwtResult = jwtDecode(input);
                    setJwtOutput(jwtResult.header, jwtResult.payload, jwtResult.signature);
                    lastOutput = JSON.stringify(jwtResult, null, 2);
                    break;
                }

                case 'pass_gen': {
                    // Clamp độ dài từ 4 đến 64 và đồng bộ ngược lại UI
                    const clamped = Math.min(64, Math.max(4, parseInt(dom.passLengthNum.value) || 16));
                    dom.passLengthNum.value = clamped;
                    dom.passLengthRange.value = clamped;
                    
                    const options = {
                        uppercase: dom.passUpper.checked,
                        lowercase: dom.passLower.checked,
                        numbers: dom.passNumbers.checked,
                        symbols: dom.passSpecial.checked,
                        excludeAmbiguous: dom.passExcludeAmbiguous.checked
                    };
                    result = generatePassword(clamped, options);
                    setOutput(escapeHTML(result));
                    lastOutput = result;
                    break;
                }

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
        if (!lastOutput || currentMode === 'jwt_dec') return;
        dom.encodeInput.value = lastOutput;
        setOutput('Kết quả sẽ hiển thị tại đây...', true);
        resetJwtOutput();
        lastOutput = '';
        hideError();
        updateButtonStates();
    }

    // Các hàm utility local đã được thay thế bằng hàng Utils xịn xò

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
            // Update range nhưng chưa clamp number ngay để mượt mà khi gõ
            const val = parseInt(e.target.value);
            if (!isNaN(val)) {
                dom.passLengthRange.value = val;
            }
        });

        dom.passLengthNum?.addEventListener('blur', (e) => {
            // Clamp giá trị chuẩn khi kết thúc nhập liệu
            const val = Math.min(64, Math.max(4, parseInt(e.target.value) || 16));
            e.target.value = val;
            dom.passLengthRange.value = val;
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
