/**
 * IMAP Migrator - Admin Dashboard
 * Author: BaoChinh / Auto-rebuilt by Assistant
 */

document.addEventListener('DOMContentLoaded', initAdminDashboard);

function initAdminDashboard() {
    // 1. Quản lý trạng thái Authentication (Login Form vs Dashboard)
    const loginContainer = document.getElementById("admin-login-container");
    const dashboardContainer = document.getElementById("admin-dashboard-container");
    const loginForm = document.getElementById("adminLoginForm");
    const loginError = document.getElementById("login-error");
    
    let AUTH_HEADERS = null;
    let pollingInterval = null;

    // Toggle Password Visibility
    const togglePasswordBtn = document.getElementById("toggle-password");
    const passwordInput = document.getElementById("admin-pass");

    if (togglePasswordBtn && passwordInput) {
        togglePasswordBtn.addEventListener("click", function() {
            if (passwordInput.type === "password") {
                passwordInput.type = "text";
                togglePasswordBtn.classList.remove("fa-eye");
                togglePasswordBtn.classList.add("fa-eye-slash");
                togglePasswordBtn.title = "Ẩn mật khẩu";
            } else {
                passwordInput.type = "password";
                togglePasswordBtn.classList.remove("fa-eye-slash");
                togglePasswordBtn.classList.add("fa-eye");
                togglePasswordBtn.title = "Hiện mật khẩu";
            }
        });
    }

    function startDashboard() {
        loginContainer.classList.add("d-none");
        document.getElementById("common-header")?.classList.add("d-none"); // Ẩn Header gốc TienIchTool
        dashboardContainer.classList.remove("d-none");
        
        switchTab("tab-dashboard");
        
        // Bắt đầu Fetch (Clear interval cũ nếu có để tránh chạy trùng)
        fetchRunningJobs();
        fetchHistory();
        if (pollingInterval) clearInterval(pollingInterval);
        pollingInterval = setInterval(fetchRunningJobs, 5000);
    }

    // ==========================================
    // DOM ELEMENTS (SPA)
    // ==========================================
    const tableRunning = document.querySelector("#table-running tbody");
    const tableRunningDashboard = document.querySelector("#table-running-dashboard tbody");
    const tableHistory = document.querySelector("#table-history tbody");
    const btnRefreshHistory = document.getElementById("btn-refresh-history");
    
    const logModal = document.getElementById("log-modal");
    const logOutputContent = document.getElementById("log-output-content");
    const currentLogJob = document.getElementById("current-log-job");
    const logFilename = document.getElementById("log-filename");
    
    // Stats
    const statTotalSyncs = document.getElementById("stat-total-syncs");
    const statSuccessRate = document.getElementById("stat-success-rate");
    const statMessages = document.getElementById("stat-messages");
    const statData = document.getElementById("stat-data");

    // ==========================================
    // TAB ROUTING & ACTIONS
    // ==========================================
    const menuItems = document.querySelectorAll(".admin-menu-item[data-target]");
    const tabPanes = document.querySelectorAll(".admin-tab-pane");

    function switchTab(targetId) {
        // Update menu active
        menuItems.forEach(btn => {
            if (btn.getAttribute("data-target") === targetId) {
                btn.classList.add("active");
            } else {
                btn.classList.remove("active");
            }
        });
        
        // Update panes
        tabPanes.forEach(pane => {
            if (pane.id === targetId) {
                pane.classList.remove("d-none");
                pane.classList.add("active");
            } else {
                pane.classList.add("d-none");
                pane.classList.remove("active");
            }
        });
    }

    menuItems.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-target");
            if (targetId) switchTab(targetId);
        });
    });

    // Theme Toggle
    const btnThemeToggle = document.getElementById("btn-theme-toggle-admin");
    if (btnThemeToggle) {
        btnThemeToggle.addEventListener("click", () => {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const targetTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', targetTheme);
            localStorage.setItem('theme', targetTheme);
        });
    }

    // Logout
    const btnLogout = document.getElementById("btn-logout");
    if (btnLogout) {
        btnLogout.addEventListener("click", () => {
            if (confirm("Bạn có chắc chắn muốn đăng xuất khỏi Admin Dashboard?")) {
                sessionStorage.removeItem("imapAdminAuth");
                window.location.reload();
            }
        });
    }

    // Close Modal
    document.querySelectorAll(".btn-close-modal").forEach(btn => {
        btn.addEventListener("click", () => {
            logModal.classList.add("d-none");
        });
    });
    // Click outside modal to close
    logModal.addEventListener("click", (e) => {
        if (e.target === logModal) {
            logModal.classList.add("d-none");
        }
    });

    // ==========================================
    // CÁC HÀM TIỆN ÍCH
    // ==========================================
    function getStatusBadge(status) {
        if (status === 'running') return '<span class="text-info font-bold">running</span>';
        if (status === 'done' || status === 'completed') return '<span class="text-success font-bold">completed</span>';
        if (status === 'error' || status === 'failed') return '<span class="text-danger font-bold">failed</span>';
        if (status === 'cancelled') return '<span class="text-warning font-bold">cancelled</span>';
        return `<span class="text-secondary font-bold">${status}</span>`;
    }

    function formatDate(dateStr) {
        if (!dateStr || dateStr === "0001-01-01T00:00:00Z") return "-";
        const d = new Date(dateStr);
        return d.toLocaleDateString("en-US") + ", " + d.toLocaleTimeString("en-US", { hour12: true });
    }

    function parseLogLine(line) {
        if (!line.trim()) return "";
        let lineClass = "";
        if (line.includes("[ERROR]") || line.includes("[FATAL]")) lineClass = "text-danger font-bold";
        else if (line.includes("[INFO]")) lineClass = "text-info";
        else if (line.includes("[DONE]") || line.includes("[COMPLETE]")) lineClass = "text-success";
        else if (line.includes("[START]")) lineClass = "text-warning";
        return `<span class="log-line ${lineClass} log-line--block">${sanitizeHTML(line)}</span>`;
    }

    function sanitizeHTML(str) {
        const temp = document.createElement("div");
        temp.textContent = str;
        return temp.innerHTML;
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const dm = 2;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    // ==========================================
    // DASHBOARD CALCULATIONS
    // ==========================================
    function computeDashboardStats(historyList) {
        statTotalSyncs.textContent = historyList.length;
        
        if (historyList.length === 0) {
            statSuccessRate.textContent = "0.0%";
            statMessages.textContent = "0";
            statData.textContent = "0 B";
            return;
        }

        let successCount = 0;
        let totalMessages = 0;

        historyList.forEach(job => {
            if (job.status === 'done' || job.status === 'completed') successCount++;
            totalMessages += (job.total || 0);
        });

        const rate = (successCount / historyList.length) * 100;
        statSuccessRate.textContent = rate.toFixed(1) + "%";
        
        // Thêm màu sắc động cho rate
        if (rate < 50) {
            statSuccessRate.className = "font-display font-bold text-danger";
        } else if (rate < 80) {
            statSuccessRate.className = "font-display font-bold text-warning";
        } else {
            statSuccessRate.className = "font-display font-bold text-success";
        }

        statMessages.textContent = totalMessages.toLocaleString();
        
        // Cấu hình dung lượng ảo: 1 Email xấp xỉ 50KB (51200 bytes)
        const estimatedBytes = totalMessages * 51200;
        statData.textContent = formatBytes(estimatedBytes);
    }

    // ==========================================
    // FETCH DATA LOGIC
    // ==========================================

    let isFetchingRunning = false;
    async function fetchRunningJobs() {
        if (isFetchingRunning) return;
        isFetchingRunning = true;
        
        try {
            const response = await fetch("/api/imap-migrator/admin/running", { headers: AUTH_HEADERS });
            if (!response.ok) throw new Error("Unauthorized or Error");
            
            const jobs = await response.json();
            renderRunningJobs(jobs || []);
        } catch (error) {
            console.error("Lỗi khi tải Running Jobs:", error);
            const errHtml = `<tr><td colspan="7" class="text-center text-danger">⚠️ Lỗi: Không thể kết nối API bảo mật.</td></tr>`;
            if (tableRunning) tableRunning.innerHTML = errHtml;
            if (tableRunningDashboard) tableRunningDashboard.innerHTML = `<tr><td class="text-center text-danger">API Error</td></tr>`;
        } finally {
            isFetchingRunning = false;
        }
    }

    let isFetchingHistory = false;
    async function fetchHistory() {
        if (isFetchingHistory) return;
        isFetchingHistory = true;
        if (btnRefreshHistory) {
            btnRefreshHistory.disabled = true;
            btnRefreshHistory.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Loading...';
        }

        try {
            const response = await fetch("/api/imap-migrator/admin/history", { headers: AUTH_HEADERS });
            if (!response.ok) throw new Error("Unauthorized or Error");

            const history = await response.json();
            const data = history || [];
            renderHistory(data);
            computeDashboardStats(data);
        } catch (error) {
            console.error("Lỗi khi tải History:", error);
            if (tableHistory) tableHistory.innerHTML = `<tr><td colspan="9" class="text-center text-danger">⚠️ Lỗi: Không thể kết nối API bảo mật.</td></tr>`;
        } finally {
            isFetchingHistory = false;
            if (btnRefreshHistory) {
                btnRefreshHistory.disabled = false;
                btnRefreshHistory.innerHTML = '<i class="fa-solid fa-rotate-right"></i> Làm mới';
            }
        }
    }

    async function viewLog(jobId) {
        logModal.classList.remove("d-none"); // Bật Modal
        currentLogJob.textContent = "#" + jobId;
        logFilename.textContent = "job_" + jobId + ".log";
        logOutputContent.innerHTML = `<div class="p-4 text-muted"><i class="fa-solid fa-spinner fa-spin mr-2"></i> Đang truy xuất file log...</div>`;

        try {
            const response = await fetch(`/api/imap-migrator/admin/logs?id=${jobId}`, { headers: AUTH_HEADERS });
            if (!response.ok) {
                if (response.status === 404) {
                    throw new Error("File log không tồn tại hoặc đã bị dọn dẹp bằng Cronjob.");
                }
                throw new Error("HTTP Error " + response.status);
            }
            
            const text = await response.text();
            if (!text.trim()) {
                logOutputContent.innerHTML = `<div class="p-4 text-warning">File log trống. Có thể tiến trình chưa ghi dữ liệu.</div>`;
                return;
            }

            // Parse từng dòng để highlight
            const lines = text.split("\n");
            let htmlChunks = [];
            for (let line of lines) {
                htmlChunks.push(parseLogLine(line));
            }
            logOutputContent.innerHTML = `<div class="p-4 font-mono text-sm log-viewer__format-text">${htmlChunks.join("")}</div>`;
            
            // Cuộn xuống đáy
            const logBody = logModal.querySelector('.log-viewer__body');
            if (logBody) logBody.scrollTop = logBody.scrollHeight;
            
        } catch (error) {
            console.error("Lỗi xem log:", error);
            logOutputContent.innerHTML = `<div class="p-4 text-danger">⚠️ ${error.message}</div>`;
        }
    }

    // ==========================================
    // RENDER LOGIC
    // ==========================================

    function renderRunningJobs(jobs) {
        const noJobsHtml = `<tr><td colspan="7" class="text-center py-4 text-secondary">No jobs currently running.</td></tr>`;
        
        if (jobs.length === 0) {
            if (tableRunning) tableRunning.innerHTML = noJobsHtml;
            if (tableRunningDashboard) tableRunningDashboard.innerHTML = `<tr><td class="text-center py-4 text-secondary">No jobs currently running.</td></tr>`;
            return;
        }

        let html = "";
        let dbHtml = "";

        jobs.forEach(job => {
            const shortId = job.jobId.substring(0, 8);
            const totalMails = job.totalCopied + job.totalSkipped;
            
            const sourceHost = job.source || "-";
            const destHost = job.dest || "-";
            
            const currentFolderTruncated = job.currentFolder ? 
                `<div class="cell-truncate" title="${job.currentFolder}">${job.currentFolder}</div> <div class="text-xs text-muted">(${job.completedFolders}/${job.totalFolders})</div>` : 
                '-';

            const errClass = job.totalErrors > 0 ? 'text-danger font-bold' : '';

            html += `
                <tr>
                    <td><span class="text-primary font-mono text-bold">#${shortId}</span></td>
                    <td>${getStatusBadge(job.status)}</td>
                    <td>
                        <div class="cell-truncate text-secondary" title="${sourceHost}">${sourceHost}</div>
                    </td>
                    <td>
                        <div class="cell-truncate" title="${destHost}">${destHost}</div>
                    </td>
                    <td>${currentFolderTruncated}</td>
                    <td><span class="text-success font-bold">${totalMails}</span> emails</td>
                    <td class="${errClass}">${job.totalErrors}</td>
                </tr>
            `;

            // Rút gọn bớt cột cho bảng mini ở Dashboard
            dbHtml += `
                <tr>
                    <td><span class="text-primary font-mono text-bold">#${shortId}</span></td>
                    <td>${getStatusBadge(job.status)}</td>
                    <td><div class="cell-truncate" title="${sourceHost}">${sourceHost} → ${destHost}</div></td>
                    <td><span class="text-success font-bold">${totalMails}</span></td>
                </tr>
            `;
        });
        
        if (tableRunning) tableRunning.innerHTML = html;
        if (tableRunningDashboard) tableRunningDashboard.innerHTML = dbHtml;
    }

    function renderHistory(historyList) {
        if (!tableHistory) return;

        if (historyList.length === 0) {
            tableHistory.innerHTML = `<tr><td colspan="9" class="text-center py-4 text-secondary">No history records found.</td></tr>`;
            return;
        }

        let html = "";
        historyList.forEach(item => {
            const shortId = item.id.substring(0, 8);
            const timeDiffStr = item.ended_at && item.started_at ? formatDuration(item.started_at, item.ended_at) : '-';
            const dataEstBytes = (item.total || 0) * 51200;
            const statusColorText = getStatusBadge(item.status);
            
            html += `
                <tr class="bg-surface hover-bg-surface-hover transition-base">
                    <td><span class="text-secondary font-mono">#${shortId}</span></td>
                    <td>${statusColorText}</td>
                    <td>
                        <div class="cell-truncate text-secondary" title="${item.source || '-'} → ${item.dest || '-'}">
                            ${item.source || '-'} → ${item.dest || '-'}
                        </div>
                    </td>
                    <td><div class="text-xs text-muted">${formatDate(item.started_at)}</div></td>
                    <td><div class="text-xs">${timeDiffStr}</div></td>
                    <td><span class="font-bold">${item.total || 0}</span></td>
                    <td><span class="text-info">${formatBytes(dataEstBytes)}</span></td>
                    <td class="${item.errors > 0 ? 'text-danger font-bold' : ''}">${item.errors || 0}</td>
                    <td>
                        <button class="btn btn-outline btn-log text-secondary" style="" data-id="${item.id}">Log</button>
                    </td>
                </tr>
            `;
        });
        tableHistory.innerHTML = html;
        
        // Gán event Modal
        document.querySelectorAll(".btn-log").forEach(btn => {
            btn.addEventListener("click", function() {
                const id = this.getAttribute("data-id");
                viewLog(id);
            });
        });
    }

    function formatDuration(startTime, endTime) {
        const start = new Date(startTime);
        const end = new Date(endTime);
        const diffSeconds = Math.floor((end - start) / 1000);
        if (diffSeconds < 0) return "0s";
        if (diffSeconds < 60) return `${diffSeconds}s`;
        const mins = Math.floor(diffSeconds / 60);
        const secs = diffSeconds % 60;
        
        let hr = Math.floor(mins / 60);
        let remainMins = mins % 60;
        
        let str = "";
        if (hr > 0) str += `${hr}h `;
        if (remainMins > 0) str += `${remainMins}m `;
        if (secs > 0 && hr === 0) str += `${secs}s`; // Only show seconds if < 1h
        return str.trim() || '0s';
    }

    if (btnRefreshHistory) {
        btnRefreshHistory.addEventListener("click", fetchHistory);
    }

    // ==========================================
    // AUTHENTICATION LOGIC (Run Last)
    // ==========================================

    loginForm.addEventListener("submit", async function(e) {
        e.preventDefault();
        const user = document.getElementById("admin-user").value.trim();
        const pass = document.getElementById("admin-pass").value.trim();
        
        const credentials = btoa(`${user}:${pass}`);
        AUTH_HEADERS = {
            "Authorization": `Basic ${credentials}`,
            "Content-Type": "application/json"
        };
        
        // Disable nút login & tạo loading state
        const btn = loginForm.querySelector('button[type="submit"]');
        const oldText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Đang xác thực...';
        
        try {
            // Check credentials với backend
            const response = await fetch("/api/imap-migrator/admin/running", { headers: AUTH_HEADERS });
            if (response.ok) {
                // Thành công
                sessionStorage.setItem("imapAdminAuth", credentials);
                loginError.classList.add("d-none");
                startDashboard();
            } else {
                loginError.classList.remove("d-none");
            }
        } catch (error) {
            loginError.classList.remove("d-none");
        } finally {
            btn.disabled = false;
            btn.innerHTML = oldText;
        }
    });

    // Cố gắng tự login nếu đã có token
    const storedAuth = sessionStorage.getItem("imapAdminAuth");
    if (storedAuth) {
        AUTH_HEADERS = {
            "Authorization": `Basic ${storedAuth}`,
            "Content-Type": "application/json"
        };
        startDashboard();
    }
}
