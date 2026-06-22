export function initClock() {
    const clockEl = document.getElementById("real_time_clock");
    if (!clockEl) return;

    function updateClock() {
        const now = new Date();
        const days = ["Chủ Nhật", "Thứ Hai", "Thứ Ba", "Thứ Tư", "Thứ Năm", "Thứ Sáu", "Thứ Bảy"];
        
        const day = days[now.getDay()];
        const date = now.getDate();
        const month = now.getMonth() + 1;
        const year = now.getFullYear();
        const hours = now.getHours().toString().padStart(2, "0");
        const minutes = now.getMinutes().toString().padStart(2, "0");
        const seconds = now.getSeconds().toString().padStart(2, "0");

        const formattedTime = `${hours}:${minutes}:${seconds} ${day}, ${date} Tháng ${month} ${year}`;
        clockEl.textContent = formattedTime;
    }

    updateClock();
    setInterval(updateClock, 1000);
}
