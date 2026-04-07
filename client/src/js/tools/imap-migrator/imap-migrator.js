import { API_BASE_URL } from '../../config.js';

document.addEventListener('DOMContentLoaded', () => {
    // ─── DOM Elements ─────────────────────────────────────────────────────────────
    
    // Steps
    const step1Connection = document.getElementById('step1-connection');
    const step2Folders = document.getElementById('step2-folders');
    const step3Progress = document.getElementById('step3-progress');
    
    // Step 1 Form
    const imapForm = document.getElementById('imapForm');
    const btnConnect = document.getElementById('btnConnect');
    const connectIcon = document.getElementById('connectIcon');
    const connectLoading = document.getElementById('connectLoading');
    const connError = document.getElementById('connError');
    const connErrorMsg = document.getElementById('connErrorMsg');
    
    // Step 2 Folders
    const modeAll = document.getElementById('modeAll');
    const modeSelected = document.getElementById('modeSelected');
    const folderPickerContainer = document.getElementById('folderPickerContainer');
    const folderTree = document.getElementById('folderTree');
    const btnStart = document.getElementById('btnStart');
    const startIcon = document.getElementById('startIcon');
    const startLoading = document.getElementById('startLoading');
    const startError = document.getElementById('startError');
    const startErrorMsg = document.getElementById('startErrorMsg');
    
    // Step 3 Progress
    const jobStatusBadge = document.getElementById('jobStatusBadge');
    const statFolders = document.getElementById('statFolders');
    const statCopied = document.getElementById('statCopied');
    const statSkipped = document.getElementById('statSkipped');
    const statErrors = document.getElementById('statErrors');
    const currentFolderLbl = document.getElementById('currentFolderLbl');
    const currentProgressLbl = document.getElementById('currentProgressLbl');
    const currentProgressBar = document.getElementById('currentProgressBar');
    const logsConsole = document.getElementById('logsConsole');
    const btnCancel = document.getElementById('btnCancel');
    const btnNew = document.getElementById('btnNew');
    
    // Warning
    const activeJobWarning = document.getElementById('activeJobWarning');
    const btnRestoreJob = document.getElementById('btnRestoreJob');

    // State
    let currentJobId = sessionStorage.getItem('imap_migrator_job_id');
    let sseSource = null;
    let endpointCache = {}; // Cache the endpoint used to list folders
    
    // ─── Initialize ───────────────────────────────────────────────────────────────
    
    init();
    
    async function init() {
        // Toggle folder picker based on mode
        modeAll.addEventListener('change', () => folderPickerContainer.classList.add('d-none'));
        modeSelected.addEventListener('change', () => folderPickerContainer.classList.remove('d-none'));
        
        btnRestoreJob.addEventListener('click', restoreJobView);
        btnNew.addEventListener('click', resetWizard);
        btnCancel.addEventListener('click', cancelJob);
        
        imapForm.addEventListener('submit', handleConnect);
        btnStart.addEventListener('click', handleStartJob);

        if (currentJobId) {
            checkCurrentJob(currentJobId);
        }

        // Setup password toggle
        const togglePassBtns = document.querySelectorAll('.btn-toggle-pass');
        togglePassBtns.forEach(btn => {
            btn.addEventListener('click', function(e) {
                e.preventDefault();
                const targetId = this.getAttribute('data-target');
                const targetInput = document.getElementById(targetId);
                const icon = this.querySelector('i');
                
                if (targetInput.type === 'password') {
                    targetInput.type = 'text';
                    icon.classList.remove('fa-eye-slash');
                    icon.classList.add('fa-eye');
                } else {
                    targetInput.type = 'password';
                    icon.classList.remove('fa-eye');
                    icon.classList.add('fa-eye-slash');
                }
            });
        });
    }
    
    // ─── Step 1: Connect & List Folders ──────────────────────────────────────────
    
    async function handleConnect(e) {
        e.preventDefault();
        
        // Hide previous errors
        connError.classList.add('d-none');
        
        // Build Endpoint Config
        const srcEndpoint = {
            host: document.getElementById('srcHost').value.trim(),
            port: parseInt(document.getElementById('srcPort').value) || 993,
            security: document.getElementById('srcSecurity').value,
            username: document.getElementById('srcUser').value.trim(),
            password: document.getElementById('srcPass').value
        };
        
        const dstEndpoint = {
            host: document.getElementById('dstHost').value.trim(),
            port: parseInt(document.getElementById('dstPort').value) || 993,
            security: document.getElementById('dstSecurity').value,
            username: document.getElementById('dstUser').value.trim(),
            password: document.getElementById('dstPass').value
        };
        
        endpointCache = { source: srcEndpoint, dest: dstEndpoint };
        
        setConnectLoading(true);
        
        try {
            // Check List Folders on Source
            const res = await fetch(`${API_BASE_URL}/imap-migrator/list-folders`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ endpoint: srcEndpoint })
            });
            
            const data = await res.json();
            
            if (!res.ok || !data.success) {
                showConnError("Máy chủ Nguồn: " + (data.message || data.error || 'Lỗi kết nối'));
                return;
            }
            
            // Also Test Dest Connection to ensure we don't fail later
            const resDst = await fetch(`${API_BASE_URL}/imap-migrator/test-connection`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ endpoint: dstEndpoint })
            });
            const dataDst = await resDst.json();
            
            if (!resDst.ok || !dataDst.success) {
                showConnError("Máy chủ Đích: " + (dataDst.message || dataDst.error || 'Lỗi kết nối'));
                return;
            }
            
            // Success: Build Tree and Move to Step 2
            buildFolderTreeUI(data.data.folders);
            
            step1Connection.classList.add('d-none');
            step2Folders.classList.remove('d-none');
            // reset mode to all
            modeAll.checked = true;
            folderPickerContainer.classList.add('d-none');
            
        } catch (err) {
            showConnError(err.message);
        } finally {
            setConnectLoading(false);
        }
    }
    
    function showConnError(msg) {
        connErrorMsg.textContent = msg;
        connError.classList.remove('d-none');
    }
    
    function setConnectLoading(isLoading) {
        if (isLoading) {
            btnConnect.disabled = true;
            connectIcon.classList.add('d-none');
            connectLoading.classList.remove('d-none');
        } else {
            btnConnect.disabled = false;
            connectIcon.classList.remove('d-none');
            connectLoading.classList.add('d-none');
        }
    }
    
    // ─── Step 2: Folder Tree UI ──────────────────────────────────────────────────
    
    function buildFolderTreeUI(folders) {
        folderTree.innerHTML = '';
        if (!folders || folders.length === 0) {
            folderTree.innerHTML = '<li class="text-muted">Không tìm thấy thư mục nào</li>';
            return;
        }
        
        folders.forEach(node => {
            folderTree.appendChild(createTreeNode(node));
        });
        
        // Setup checkbox cascading behavior
        setupTreeCheckboxes();
    }
    
    function createTreeNode(node) {
        const li = document.createElement('li');
        
        const itemDiv = document.createElement('div');
        itemDiv.className = 'imap-tree-item';
        
        const hasChildren = node.children && node.children.length > 0;
        
        // Toggle icon
        if (hasChildren) {
            const toggle = document.createElement('i');
            toggle.className = 'fa-solid fa-caret-down imap-tree-toggle';
            toggle.addEventListener('click', (e) => {
                const childUl = li.querySelector('ul');
                if (childUl) {
                    childUl.classList.toggle('d-none');
                    toggle.classList.toggle('fa-caret-down');
                    toggle.classList.toggle('fa-caret-right');
                }
            });
            itemDiv.appendChild(toggle);
        } else {
            const spacer = document.createElement('span');
            spacer.style.width = '16px';
            spacer.style.display = 'inline-block';
            itemDiv.appendChild(spacer);
        }
        
        // Checkbox
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'imap-tree-checkbox';
        cb.value = node.fullPath;
        itemDiv.appendChild(cb);
        
        // Icon & Label
        const icon = document.createElement('i');
        icon.className = 'fa-regular fa-folder text-warning';
        itemDiv.appendChild(icon);
        
        const label = document.createElement('span');
        label.className = 'imap-tree-label';
        label.textContent = node.name;
        label.addEventListener('click', () => { cb.click(); });
        itemDiv.appendChild(label);
        
        li.appendChild(itemDiv);
        
        // Children
        if (hasChildren) {
            const childrenUl = document.createElement('ul');
            node.children.forEach(childNode => {
                childrenUl.appendChild(createTreeNode(childNode));
            });
            li.appendChild(childrenUl);
        }
        
        return li;
    }
    
    function setupTreeCheckboxes() {
        const checkboxes = folderTree.querySelectorAll('input[type="checkbox"]');
        checkboxes.forEach(cb => {
            cb.addEventListener('change', function(e) {
                const isChecked = this.checked;
                // Update children
                const parentLi = this.closest('li');
                const childCheckboxes = parentLi.querySelectorAll('ul input[type="checkbox"]');
                childCheckboxes.forEach(childCb => {
                    childCb.checked = isChecked;
                });
                
                // Indeterminate / Update parents
                updateParents(this);
            });
        });
    }
    
    function updateParents(checkbox) {
        let parentLi = checkbox.closest('ul').closest('li');
        while (parentLi) {
            const parentCb = parentLi.querySelector(':scope > div > input[type="checkbox"]');
            const siblingCbs = parentLi.querySelectorAll(':scope > ul > li > div > input[type="checkbox"]');
            
            let allChecked = true;
            let someChecked = false;
            
            siblingCbs.forEach(cb => {
                if (cb.checked) {
                    someChecked = true;
                } else {
                    allChecked = false;
                }
                if (cb.indeterminate) {
                    someChecked = true;
                    allChecked = false;
                }
            });
            
            if (parentCb) {
                parentCb.checked = allChecked;
                parentCb.indeterminate = !allChecked && someChecked;
            }
            
            parentLi = parentLi.closest('ul').closest('li');
        }
    }
    
    function getSelectedFolders() {
        // We only need to collect checked checkboxes.
        // Even if parent is checked and children are checked, backend canonicalizes it.
        const checked = folderTree.querySelectorAll('input[type="checkbox"]:checked');
        return Array.from(checked).map(cb => cb.value);
    }
    
    // ─── Step 3: Start Job ───────────────────────────────────────────────────────
    
    async function handleStartJob() {
        startError.classList.add('d-none');
        
        const reqPayload = {
            source: endpointCache.source,
            dest: endpointCache.dest,
            mode: document.querySelector('input[name="migrateMode"]:checked').value,
            folders: []
        };
        
        if (reqPayload.mode === 'selected') {
            reqPayload.folders = getSelectedFolders();
            if (reqPayload.folders.length === 0) {
                startErrorMsg.textContent = "Vui lòng chọn ít nhất 1 thư mục.";
                startError.classList.remove('d-none');
                return;
            }
        }
        
        setStartLoading(true);
        
        try {
            const res = await fetch(`${API_BASE_URL}/imap-migrator/start`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(reqPayload)
            });
            
            const data = await res.json();
            
            if (!res.ok || !data.success) {
                startErrorMsg.textContent = data.message || data.error || 'Không thể bắt đầu tiến trình mới.';
                startError.classList.remove('d-none');
                return;
            }
            
            // Success
            currentJobId = data.data.jobId;
            sessionStorage.setItem('imap_migrator_job_id', currentJobId);
            
            endpointCache = {}; // Security: Clear credentials from memory
            
            step2Folders.classList.add('d-none');
            restoreJobView();
            
        } catch (err) {
            startErrorMsg.textContent = err.message;
            startError.classList.remove('d-none');
        } finally {
            setStartLoading(false);
        }
    }
    
    function setStartLoading(isLoading) {
        if (isLoading) {
            btnStart.disabled = true;
            startIcon.classList.add('d-none');
            startLoading.classList.remove('d-none');
        } else {
            btnStart.disabled = false;
            startIcon.classList.remove('d-none');
            startLoading.classList.add('d-none');
        }
    }
    
    // ─── Job Monitoring (SSE & Status) ───────────────────────────────────────────
    
    async function checkCurrentJob(jobId) {
        try {
            const res = await fetch(`${API_BASE_URL}/imap-migrator/status?jobId=${jobId}`);
            const data = await res.json();
            
            if (!res.ok || !data.success) {
                // Job expired or not found
                sessionStorage.removeItem('imap_migrator_job_id');
                currentJobId = null;
                return;
            }
            
            const snap = data.data;
            if (snap.status === 'running') {
                activeJobWarning.classList.remove('d-none');
            } else if (snap.status === 'done' || snap.status === 'error' || snap.status === 'cancelled') {
                // Still exists in cache, allow viewing it if no other is active
                activeJobWarning.classList.remove('d-none');
                btnRestoreJob.textContent = "Xem kết quả tiến trình gần nhất";
            }
            
        } catch (err) {
            // Silently ignore network errors for status polling
            console.error(err);
        }
    }
    
    function restoreJobView() {
        activeJobWarning.classList.add('d-none');
        step1Connection.classList.add('d-none');
        step2Folders.classList.add('d-none');
        step3Progress.classList.remove('d-none');
        
        // Reset logs
        logsConsole.innerHTML = '<div class="imap-log-entry ">Đang kết nối hệ thống log...</div>';
        resetStats();
        
        pollStatusSilent(currentJobId); // Immediatley populate UI stats on reload
        startSSE(currentJobId);
    }
    
    let sseRetryCount = 0;
    const maxSseRetries = 5;

    function startSSE(jobId) {
        sseRetryCount = 0; // reset on fresh connect

        if (sseSource) {
            sseSource.close();
        }
        
        btnCancel.classList.remove('d-none');
        btnNew.classList.add('d-none');
        
        updateJobBadge('running', 'Đang hoạt động');
        
        sseSource = new EventSource(`${API_BASE_URL}/imap-migrator/stream?jobId=${jobId}`);
        
        sseSource.onmessage = function(event) {
            const ev = JSON.parse(event.data);
            handleSSEEvent(ev);
        };
        
        sseSource.onerror = function() {
            sseSource.close();
            sseRetryCount++;
            
            fetch(`${API_BASE_URL}/imap-migrator/status?jobId=${jobId}`)
                .then(r => r.json())
                .then(d => {
                    if (d.data?.status === 'running' && sseRetryCount <= maxSseRetries) {
                        appendLog(`Đang kết nối lại... (${sseRetryCount}/${maxSseRetries})`, 'warning');
                        setTimeout(() => startSSE(jobId), 3000);
                    } else {
                        if (d.data) finalizeJobState(d.data);
                        else appendLog('Không thể lấy trạng thái cuối cùng của tiến trình.', 'error');
                    }
                }).catch(e => {
                    appendLog('Mất kết nối. Không thể kiểm tra trạng thái.', 'error');
                });
        };
    }
    
    function handleSSEEvent(ev) {
        switch(ev.type) {
            case "HEARTBEAT":
                // Ignore visually
                break;
            case "INFO":
                appendLog(`[INFO] ${ev.folder ? ev.folder + ': ' : ''}${ev.message}`, 'warning');
                break;
            case "FOLDER_START":
                currentFolderLbl.textContent = ev.folder;
                currentProgressLbl.textContent = '0%';
                currentProgressBar.style.width = '0%';
                appendLog(`[START] Bắt đầu đồng bộ thư mục: ${ev.folder} (${ev.total} emails)`, 'info');
                break;
            case "PROGRESS":
                // Update Progress bar
                let p = 0;
                if (ev.total > 0) {
                    p = Math.round((ev.copied / ev.total) * 100);
                }
                currentProgressLbl.textContent = `${p}%`;
                currentProgressBar.style.width = `${p}%`;
                
                // Add to total completed counter 
                // Wait, SSE gives incremental progress within folder? Yes, `ev.copied` is accumulated per folder.
                // We should rely on standard stats update or just wait for SERVER to emit global stats?
                // Actually the backend emits global TotalCopied implicitly via FOLDER_DONE, or we can just fetch status.
                break;
            case "FOLDER_DONE":
                if (ev.errors > 0 && ev.message) {
                    appendLog(`[ERROR] Thư mục ${ev.folder}: ${ev.message}`, 'error');
                } else if (ev.errors > 0) {
                    appendLog(`[DONE] Hoàn tất thư mục ${ev.folder}. Thành công: ${ev.copied}, Bỏ qua: ${ev.skipped}, Lỗi: ${ev.errors}`, 'warning');
                } else {
                    appendLog(`[DONE] Hoàn tất thư mục ${ev.folder}. Thành công: ${ev.copied}, Bỏ qua: ${ev.skipped}, Lỗi: ${ev.errors}`, 'success');
                }
                // Refresh full status
                pollStatusSilent(currentJobId);
                break;
            case "EMAIL_SKIPPED":
                appendLog(`[SKIPPED] ${ev.folder} - UID ${ev.uid}: ${ev.message}`, 'warning');
                pollStatusSilent(currentJobId);
                break;
            case "EMAIL_ERROR":
                appendLog(`[ERROR] ${ev.folder} - UID ${ev.uid}: ${ev.message}`, 'error');
                pollStatusSilent(currentJobId);
                break;
            case "COMPLETE":
                appendLog(`[COMPLETE] Toàn bộ tiến trình đã chuyển thành công. TỔNG CỘNG: ${ev.totalCopied} thư, ${ev.totalErrors} lỗi, bỏ qua ${ev.totalSkipped}`, 'success');
                pollStatusSilent(currentJobId); // Will trigger finalizeJobState
                break;
            case "ERROR":
                appendLog(`[ERROR] NGHIÊM TRỌNG: ${ev.message}`, 'error');
                pollStatusSilent(currentJobId);
                break;
        }
    }
    
    function appendLog(msg, type = 'info') {
        const div = document.createElement('div');
        div.className = `imap-log-entry imap-log-entry--${type}`;
        
        const timestamp = new Date().toLocaleTimeString();
        div.textContent = `[${timestamp}] ${msg}`;
        
        logsConsole.appendChild(div);
        
        // auto scroll
        logsConsole.scrollTop = logsConsole.scrollHeight;
    }
    
    // ─── Status Updates ──────────────────────────────────────────────────────────
    
    async function pollStatusSilent(jobId) {
        try {
            const res = await fetch(`${API_BASE_URL}/imap-migrator/status?jobId=${jobId}`);
            const data = await res.json();
            if (data.success) {
                updateStatsUI(data.data);
                if (data.data.status !== 'running') {
                    finalizeJobState(data.data);
                }
            }
        } catch(e) {}
    }
    
    function updateStatsUI(snap) {
        statFolders.textContent = `${snap.completedFolders} / ${snap.totalFolders}`;
        statCopied.textContent = snap.totalCopied;
        statSkipped.textContent = snap.totalSkipped;
        statErrors.textContent = snap.totalErrors;
        
        if (snap.currentFolder) {
            currentFolderLbl.textContent = snap.currentFolder;
        }
    }
    
    function resetStats() {
        statFolders.textContent = `0 / 0`;
        statCopied.textContent = `0`;
        statSkipped.textContent = `0`;
        statErrors.textContent = `0`;
        currentFolderLbl.textContent = `--`;
        currentProgressLbl.textContent = `0%`;
        currentProgressBar.style.width = `0%`;
    }
    
    function updateJobBadge(status, text) {
        jobStatusBadge.className = 'badge';
        jobStatusBadge.textContent = text;
        
        if (status === 'running') jobStatusBadge.classList.add('badge-info');
        else if (status === 'done') jobStatusBadge.classList.add('badge-success');
        else if (status === 'error') jobStatusBadge.classList.add('badge-error');
        else if (status === 'cancelled') jobStatusBadge.classList.add('badge-warning');
        else jobStatusBadge.classList.add('badge-default');
    }
    
    function finalizeJobState(snap) {
        if (sseSource) {
            sseSource.close();
            sseSource = null;
        }
        
        btnCancel.classList.add('d-none');
        btnNew.classList.remove('d-none');
        
        sessionStorage.removeItem('imap_migrator_job_id');
        
        if (snap.status === 'done') {
            updateJobBadge('done', 'Thành công');
            currentProgressBar.style.width = '100%';
            currentProgressLbl.textContent = '100%';
        } else if (snap.status === 'cancelled') {
            updateJobBadge('cancelled', 'Đã hủy bỏ');
        } else if (snap.status === 'error') {
            updateJobBadge('error', 'Lỗi tiến trình');
            appendLog(`[FAIL] ${snap.lastError || 'Lỗi không xác định'}`, 'error');
        }
    }
    
    async function cancelJob() {
        if (!confirm('Bạn có chắc chắn muốn hủy bỏ tiến trình này? (Thư mục đã chuyển sẽ giữ nguyên, thư đang chuyển sẽ bị dừng)')) {
            return;
        }
        
        btnCancel.disabled = true;
        
        try {
            await fetch(`${API_BASE_URL}/imap-migrator/cancel?jobId=${currentJobId}`, { method: 'POST' });
            // SSE should receive Cancelled or we poll
            setTimeout(() => pollStatusSilent(currentJobId), 1000);
        } catch(e) {
            alert('Lỗi hủy tiến trình: ' + e.message);
            btnCancel.disabled = false;
        }
    }
    
    function resetWizard() {
        if (sseSource) sseSource.close();
        
        step3Progress.classList.add('d-none');
        step2Folders.classList.add('d-none');
        step1Connection.classList.remove('d-none');
        
        currentJobId = null;
        sessionStorage.removeItem('imap_migrator_job_id');
        
        resetStats();
        btnCancel.disabled = false;
    }
});
