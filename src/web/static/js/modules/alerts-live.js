/** Alertes temps réel via SSE */
import { API_BASE } from './api.js';

let eventSource = null;

export function startAlertsStream(onUpdate) {
    stopAlertsStream();
    if (typeof EventSource === 'undefined') return;
    eventSource = new EventSource(`${API_BASE}/events/alerts`);
    eventSource.onmessage = (event) => {
        try {
            const payload = JSON.parse(event.data);
            if (onUpdate) onUpdate(payload);
            const badge = document.getElementById('alerts-badge');
            if (badge && payload.count > 0) {
                badge.textContent = payload.count;
                badge.style.display = 'inline';
            }
        } catch (e) {
            console.warn('SSE parse error', e);
        }
    };
    eventSource.onerror = () => {
        if (typeof window.setLiveIndicator === 'function') window.setLiveIndicator(false);
        stopAlertsStream();
    };
}

export function stopAlertsStream() {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
}
