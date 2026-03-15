import { API_BASE_URL } from '../config.js';

export async function trackVisit() {
    const elTotal = document.getElementById('visit-total');
    const elToday = document.getElementById('visit-today');

    if (!elTotal || !elToday) return; // If elements don't exist, ignore

    try {
        const res = await fetch(`${API_BASE_URL}/visits`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        });

        if (!res.ok) throw new Error('Failed to track visit');

        const data = await res.json();
        
        if (data.success) {
            elTotal.textContent = data.total_visits.toLocaleString();
            elToday.textContent = data.today_visits.toLocaleString();
        }
    } catch (err) {
        console.error("Visit tracking failed:", err);
    }
}
