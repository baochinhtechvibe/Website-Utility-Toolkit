// js/utils/file-upload.js

/**
 * Khởi tạo tính năng Switch Radio (Dán text vs Tải file)
 * @param {string} radioName Name của input radio (paste / upload)
 * @param {string} pasteZoneId ID của div bọc thẻ textarea
 * @param {string} uploadZoneId ID của div bọc thẻ dropzone
 * @param {string} dropzoneId ID của thẻ div dropzone chứa file input
 * @param {string} fileInputId ID của thẻ input type="file"
 * @param {string} textareaId ID của thẻ textarea đích cần nhét text vào
 */
export function initFileUploadToggle(radioName, pasteZoneId, uploadZoneId, dropzoneId, fileInputId, textareaId) {
    const radios = document.querySelectorAll(`input[name="${radioName}"]`);
    const pasteZone = document.getElementById(pasteZoneId);
    const uploadZone = document.getElementById(uploadZoneId);
    const dropzone = document.getElementById(dropzoneId);
    const fileInput = document.getElementById(fileInputId);
    const textarea = document.getElementById(textareaId);

    if (!radios.length || !pasteZone || !uploadZone || !dropzone || !fileInput || !textarea) {
        return;
    }

    const textSpan = dropzone.querySelector('.js-upload-text');

    // Mặc định luôn hiện chức năng được chọn đầu tiên (phòng hờ HTML không check)
    const activeRadio = Array.from(radios).find(r => r.checked) || radios[0];
    if (activeRadio.value === 'upload') {
        pasteZone.classList.add('d-none');
        uploadZone.classList.remove('d-none');
    }

    // Lắng nghe sự kiện đổi chế độ nhập liệu
    radios.forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.value === 'upload') {
                pasteZone.classList.add('d-none');
                uploadZone.classList.remove('d-none');
            } else {
                uploadZone.classList.add('d-none');
                pasteZone.classList.remove('d-none');
            }
        });
    });

    const handleFile = (file) => {
        if (!file) return;
        
        // Cản các file trên 2MB để tránh treo browser
        if (file.size > 2 * 1024 * 1024) {
            alert('File quá lớn. Vui lòng chọn tệp nhỏ hơn 2MB.');
            fileInput.value = ""; // Reset
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            // Chép nội dung file vào textarea và kích hoạt event `input` để code Validation cũ chạy
            textarea.value = e.target.result;
            textarea.dispatchEvent(new Event('input'));
            
            dropzone.classList.add('ssl-file-upload--has-file');
            if (textSpan) textSpan.textContent = `Đã tải: ${file.name}`;
        };
        
        reader.onerror = () => {
            alert("Lỗi khi đọc file. Vui lòng thử lại.");
            fileInput.value = "";
        };

        reader.readAsText(file); // Chỉ đọc text vì ta chỉ quan tâm nội dung dạng text (PEM)
    };

    // --- Drag and Drop Events ---
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('ssl-file-upload--dragover');
    });

    dropzone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dropzone.classList.remove('ssl-file-upload--dragover');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('ssl-file-upload--dragover');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files; // Sync lại input để form submit đúng (dù ko cần)
            handleFile(e.dataTransfer.files[0]);
        }
    });

    // --- Click Event ---
    fileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });
}

/**
 * Reset trạng thái của File Upload Dropzone về ban đầu
 * @param {string} dropzoneId 
 * @param {string} defaultText 
 */
export function resetFileUpload(dropzoneId, defaultText) {
    const dropzone = document.getElementById(dropzoneId);
    if (!dropzone) return;

    const fileInput = dropzone.querySelector('input[type="file"]');
    const textSpan = dropzone.querySelector('.js-upload-text');

    if (fileInput) fileInput.value = "";
    if (textSpan && defaultText) textSpan.textContent = defaultText;
    
    dropzone.classList.remove('ssl-file-upload--has-file');
    dropzone.classList.remove('ssl-file-upload--dragover');
    dropzone.classList.remove('ssl-file-upload--valid');
    dropzone.classList.remove('ssl-file-upload--invalid');
}
