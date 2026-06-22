import { API_BASE_URL } from '../../config.js';

// --- Session ID Management ---
function getSessionId() {
    let sid = localStorage.getItem('imap_migrator_session');
    if (!sid) {
        sid = (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : 'session-' + Math.random().toString(36).substr(2, 9);
        localStorage.setItem('imap_migrator_session', sid);
    }
    return sid;
}

// Wrapper for fetch to auto-inject X-Session-ID
async function fetchWithSession(url, options = {}) {
    const headers = options.headers || {};
    headers['X-Session-ID'] = getSessionId();
    options.headers = headers;
    return fetch(url, options);
}

document.addEventListener('DOMContentLoaded', () => {
    // ─── DOM Elements ─────────────────────────────────────────────────────────────

    // Steps
    const step1Connection = document.getElementById('step1-connection');
    const step2Folders = document.getElementById('step2-folders');

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

    // Queue Dashboard
    const btnRefreshQueue = document.getElementById('btnRefreshQueue');
    const queueList = document.getElementById('queueList');

    // Modal Details
    const modal = document.getElementById('step3-progress');
    const btnCloseModal = document.getElementById('btnCloseModal');
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

    // State
    let currentJobId = null;
    let lastLogOffset = 0;
    let sseSource = null;
    let endpointCache = {}; // Cache the endpoint used to list folders
    let queuePollTimer = null;

    // ─── Initialize ───────────────────────────────────────────────────────────────

    init();

    async function init() {
        // Toggle folder picker based on mode
        modeAll.addEventListener('change', () => folderPickerContainer.classList.add('d-none'));
        modeSelected.addEventListener('change', () => folderPickerContainer.classList.remove('d-none'));

        btnCloseModal.addEventListener('click', closeJobModal);
        btnCancel.addEventListener('click', cancelJob);
        btnRefreshQueue.addEventListener('click', pollQueue);

        imapForm.addEventListener('submit', handleConnect);
        btnStart.addEventListener('click', handleStartJob);

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

        // Initial queue poll
        pollQueue();
        queuePollTimer = setInterval(pollQueue, 5000);
    }

    // ─── Queue Dashboard ─────────────────────────────────────────────────────────

    async function pollQueue() {
        try {
            const res = await fetchWithSession(`${API_BASE_URL}/imap-migrator/my-jobs`);
            const data = await res.json();
            if (data.success && Array.isArray(data.data)) {
                renderQueueList(data.data);
            }
        } catch (e) {
            console.error("Lỗi lấy danh sách queue:", e);
        }
    }

    function renderQueueList(jobs) {
        queueList.innerHTML = '';
        if (jobs.length === 0) {
            queueList.innerHTML = '<tr><td colspan="4" class="text-center text-muted py-4">Chưa có tiến trình nào</td></tr>';
            return;
        }

        jobs.forEach(job => {
            const tr = document.createElement('tr');

            // Thời gian
            const tdTime = document.createElement('td');
            const d = new Date(job.startedAt);
            tdTime.innerHTML = `
                <div class="font-bold text-sm">${d.toLocaleDateString('vi-VN')}</div>
                <div class="text-xs text-muted">${d.toLocaleTimeString('vi-VN')}</div>
            `;

            // Nguồn -> Đích
            const tdRoute = document.createElement('td');
            tdRoute.innerHTML = `
                <div class="font-bold text-sm">${job.sourceUser}@${job.source}</div>
                <div class="text-xs text-muted"><i class="fa-solid fa-arrow-down mr-1"></i> ${job.destUser}@${job.dest}</div>
            `;

            // Status & Mini Progress
            const tdStatus = document.createElement('td');
            let badgeClass = 'badge-default';
            let statusText = 'Đang chờ';
            if (job.status === 'running') {
                badgeClass = 'badge-info'; statusText = 'Đang chạy';
            } else if (job.status === 'done') {
                badgeClass = 'badge-success'; statusText = 'Hoàn thành';
            } else if (job.status === 'error') {
                badgeClass = 'badge-error'; statusText = 'Lỗi';
            } else if (job.status === 'cancelled') {
                badgeClass = 'badge-warning'; statusText = 'Đã huỷ';
            }

            tdStatus.innerHTML = `<span class="badge ${badgeClass} badge-sm">${statusText}</span>`;

            if (job.status === 'running') {
                let p = 0;
                if (job.totalFolders > 0) {
                    let exactFolders = job.completedFolders;
                    if (job.currentFolderTotal && job.currentFolderTotal > 0) {
                        exactFolders += (job.currentFolderCopied / job.currentFolderTotal);
                    }
                    p = Math.round((exactFolders / job.totalFolders) * 100);
                }

                const progWrap = document.createElement('div');
                progWrap.className = 'progress-bar-wrap imap-queue-progress mt-1';
                const progFill = document.createElement('div');
                progFill.className = 'progress-bar-fill';
                progFill.style.setProperty('--progress-width', `${p}%`);
                progWrap.appendChild(progFill);
                tdStatus.appendChild(progWrap);
            }

            // Thao tác
            const tdActions = document.createElement('td');
            tdActions.className = "text-right";

            const btnView = document.createElement('button');
            btnView.type = "button";
            btnView.className = "btn btn-outline btn-sm";
            btnView.innerHTML = '<i class="fa-solid fa-eye"></i> Xem chi tiết';
            btnView.onclick = (e) => {
                e.preventDefault();
                openJobModal(job.jobId);
            };

            tdActions.appendChild(btnView);

            tr.appendChild(tdTime);
            tr.appendChild(tdRoute);
            tr.appendChild(tdStatus);
            tr.appendChild(tdActions);

            queueList.appendChild(tr);
        });
    }

    // ─── Step 1: Connect & List Folders ──────────────────────────────────────────

    async function handleConnect(e) {
        e.preventDefault();
        connError.classList.add('d-none');

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
            const res = await fetchWithSession(`${API_BASE_URL}/imap-migrator/list-folders`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ endpoint: srcEndpoint })
            });
            const data = await res.json();

            if (!res.ok || !data.success) {
                showConnError("Máy chủ Nguồn: " + (data.message || data.error || 'Lỗi kết nối'));
                return;
            }

            const resDst = await fetchWithSession(`${API_BASE_URL}/imap-migrator/test-connection`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ endpoint: dstEndpoint })
            });
            const dataDst = await resDst.json();

            if (!resDst.ok || !dataDst.success) {
                showConnError("Máy chủ Đích: " + (dataDst.message || dataDst.error || 'Lỗi kết nối'));
                return;
            }

            buildFolderTreeUI(data.data.folders);
            step1Connection.classList.add('d-none');
            step2Folders.classList.remove('d-none');
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
        setupTreeCheckboxes();
    }

    function createTreeNode(node) {
        const li = document.createElement('li');
        const itemDiv = document.createElement('div');
        itemDiv.className = 'imap-tree-item';

        const hasChildren = node.children && node.children.length > 0;

        if (hasChildren) {
            const toggle = document.createElement('i');
            toggle.className = 'fa-solid fa-caret-down imap-tree-toggle';
            toggle.addEventListener('click', () => {
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
            spacer.className = 'imap-tree-spacer';
            itemDiv.appendChild(spacer);
        }

        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.className = 'imap-tree-checkbox';
        cb.value = node.fullPath;
        itemDiv.appendChild(cb);

        const icon = document.createElement('i');
        icon.className = 'fa-regular fa-folder text-warning';
        itemDiv.appendChild(icon);

        const label = document.createElement('span');
        label.className = 'imap-tree-label';
        label.textContent = node.name;
        label.addEventListener('click', () => { cb.click(); });
        itemDiv.appendChild(label);

        li.appendChild(itemDiv);

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
            cb.addEventListener('change', function() {
                const isChecked = this.checked;
                const parentLi = this.closest('li');
                const childCheckboxes = parentLi.querySelectorAll('ul input[type="checkbox"]');
                childCheckboxes.forEach(childCb => childCb.checked = isChecked);
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
                if (cb.checked) someChecked = true;
                else allChecked = false;
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
            const res = await fetchWithSession(`${API_BASE_URL}/imap-migrator/start`, {
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

            // Thành công: Reset form, báo thành công, update queue
            endpointCache = {};
            step2Folders.classList.add('d-none');
            step1Connection.classList.remove('d-none');
            imapForm.reset();

            pollQueue(); // Refresh queue immediately

            // Scroll down to queue dashboard
            document.getElementById('queueDashboard').scrollIntoView({ behavior: 'smooth' });

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

    // ─── Modal Details (SSE & Status) ───────────────────────────────────────────

    function openJobModal(jobId) {
        currentJobId = jobId;
        lastLogOffset = 0; // Reset offset khi mở job mới
        modal.classList.remove('d-none');

        // Reset logs
        logsConsole.innerHTML = '<div class="imap-log-entry ">Đang tải lịch sử log...</div>';
        resetStats();

        pollStatusSilent(currentJobId);
        startSSE(currentJobId);
    }

    function closeJobModal() {
        if (sseSource) {
            sseSource.close();
            sseSource = null;
        }
        currentJobId = null;
        modal.classList.add('d-none');
    }

    let sseRetryCount = 0;
    const maxSseRetries = 5;

    function startSSE(jobId) {
        sseRetryCount = 0;

        if (sseSource) sseSource.close();

        btnCancel.classList.remove('d-none');
        updateJobBadge('running', 'Đang hoạt động');

        // sse event source does not support custom headers natively.
        // We will pass session id as query param to bypass if needed,
        // though HandleStream only checks jobId.
        // Pass session id as query param since EventSource doesn't support headers
        const sid = getSessionId();

        // Connect real-time SSE. backend HandleStream will subscribe,
        // then read file from fromOffset, send VERBOSE_CHUNK, and stream new events.
        // This ensures 0 gap between old logs and new logs.
        sseSource = new EventSource(`${API_BASE_URL}/imap-migrator/stream?jobId=${jobId}&sessionId=${sid}&fromOffset=${lastLogOffset}`);

        sseSource.onmessage = function(event) {
            const ev = JSON.parse(event.data);
            handleSSEEvent(ev);
        };

        sseSource.onerror = function() {
            sseSource.close();
            sseRetryCount++;

            fetchWithSession(`${API_BASE_URL}/imap-migrator/status?jobId=${jobId}`)
                .then(r => r.json())
                .then(d => {
                    if (d.data?.status === 'running' && sseRetryCount <= maxSseRetries) {
                        appendLog(`Đang kết nối lại... (${sseRetryCount}/${maxSseRetries})`, 'warning');
                        setTimeout(() => {
                            if (currentJobId === jobId) startSSE(jobId);
                        }, 3000);
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
            case "HEARTBEAT": break;
            case "INFO":
                // State only, no log append (handled by VERBOSE)
                break;
            case "FOLDER_START":
                currentFolderLbl.textContent = ev.folder;
                currentProgressLbl.textContent = '0%';
                currentProgressBar.style.setProperty('--progress-width', '0%');
                break;
            case "PROGRESS":
                let p = 0;
                if (ev.total > 0) p = Math.round((ev.copied / ev.total) * 100);
                currentProgressLbl.textContent = `${p}%`;
                currentProgressBar.style.setProperty('--progress-width', `${p}%`);
                
                if (ev.totalCopied !== undefined) statCopied.textContent = ev.totalCopied;
                if (ev.totalSkipped !== undefined) statSkipped.textContent = ev.totalSkipped;
                if (ev.totalErrors !== undefined) statErrors.textContent = ev.totalErrors;
                if (ev.totalFolders !== undefined && ev.completedFolders !== undefined) {
                    statFolders.textContent = `${ev.completedFolders} / ${ev.totalFolders}`;
                }
                break;
            case "FOLDER_DONE":
            case "EMAIL_SKIPPED":
            case "EMAIL_ERROR":
                pollStatusSilent(currentJobId);
                break;
            case "COMPLETE":
            case "ERROR":
                if (sseSource) {
                    sseSource.close();
                    sseSource = null;
                }
                pollStatusSilent(currentJobId);
                break;
            case "VERBOSE":
                if (ev.offset && ev.offset <= lastLogOffset) return;
                if (ev.offset) lastLogOffset = ev.offset;
                appendLog(ev.message, 'verbose');
                break;
            case "VERBOSE_CHUNK":
                if (ev.offset) lastLogOffset = ev.offset;
                if (ev.message) {
                    const lines = ev.message.split('\n');
                    const frag = document.createDocumentFragment();
                    for (let line of lines) {
                        if (!line.trim()) continue;
                        const div = document.createElement('div');
                        div.className = `imap-log-entry imap-log-entry--verbose`;
                        div.textContent = line;
                        frag.appendChild(div);
                    }
                    if (logsConsole.innerHTML.includes('Đang tải lịch sử log...')) {
                        logsConsole.innerHTML = '';
                    }
                    logsConsole.appendChild(frag);
                    while (logsConsole.children.length > 500) {
                        logsConsole.removeChild(logsConsole.firstChild);
                    }
                    logsConsole.scrollTop = logsConsole.scrollHeight;
                }
                break;
        }
    }

    function appendLog(msg, type = 'info') {
        const div = document.createElement('div');
        div.className = `imap-log-entry imap-log-entry--${type}`;

        if (type === 'verbose') {
            div.textContent = msg.trim(); // Không thêm timestamp cho log raw, loại bỏ \n thừa
        } else {
            div.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
        }

        logsConsole.appendChild(div);

        // Limit DOM size to prevent freezing on large mailboxes (keep last 300 logs)
        while (logsConsole.children.length > 300) {
            logsConsole.removeChild(logsConsole.firstChild);
        }

        logsConsole.scrollTop = logsConsole.scrollHeight;
    }

    async function pollStatusSilent(jobId) {
        try {
            const res = await fetchWithSession(`${API_BASE_URL}/imap-migrator/status?jobId=${jobId}`);
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
        if (snap.currentFolder) currentFolderLbl.textContent = snap.currentFolder;

        let p = 0;
        if (snap.currentFolderTotal && snap.currentFolderTotal > 0) {
            p = Math.round((snap.currentFolderCopied / snap.currentFolderTotal) * 100);
            currentProgressLbl.textContent = `${p}%`;
            currentProgressBar.style.setProperty('--progress-width', `${p}%`);
        }
    }

    function resetStats() {
        statFolders.textContent = `0 / 0`;
        statCopied.textContent = `0`;
        statSkipped.textContent = `0`;
        statErrors.textContent = `0`;
        currentFolderLbl.textContent = `--`;
        currentProgressLbl.textContent = `0%`;
        currentProgressBar.style.setProperty('--progress-width', '0%');
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
        btnCancel.classList.add('d-none');

        if (snap.status === 'done') {
            updateJobBadge('done', 'Thành công');
            currentProgressBar.style.setProperty('--progress-width', '100%');
            currentProgressLbl.textContent = '100%';
        } else if (snap.status === 'cancelled') {
            updateJobBadge('cancelled', 'Đã hủy bỏ');
        } else if (snap.status === 'error') {
            updateJobBadge('error', 'Lỗi tiến trình');
            appendLog(`[FAIL] ${snap.lastError || 'Lỗi không xác định'}`, 'error');
        }
        pollQueue(); // Refresh queue to reflect final status
    }

    async function cancelJob() {
        if (!confirm('Bạn có chắc chắn muốn hủy bỏ tiến trình này? (Thư mục đã chuyển sẽ giữ nguyên, thư đang chuyển sẽ bị dừng)')) return;

        btnCancel.disabled = true;
        try {
            await fetchWithSession(`${API_BASE_URL}/imap-migrator/cancel?jobId=${currentJobId}`, { method: 'POST' });
            setTimeout(() => pollStatusSilent(currentJobId), 1000);
            pollQueue();
        } catch(e) {
            alert('Lỗi hủy tiến trình: ' + e.message);
            btnCancel.disabled = false;
        }
    }
});
