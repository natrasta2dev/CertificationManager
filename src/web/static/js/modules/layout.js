/** Layout sidebar mobile + overlay */
export function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    const toggle = document.getElementById('sidebar-toggle');

    function close() {
        sidebar?.classList.remove('open');
        overlay?.classList.remove('open');
    }

    toggle?.addEventListener('click', () => {
        sidebar?.classList.toggle('open');
        overlay?.classList.toggle('open');
    });

    overlay?.addEventListener('click', close);

    document.querySelectorAll('.sidebar-nav .nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            if (window.innerWidth <= 768) close();
        });
    });
}

export function setLiveIndicator(active) {
    const el = document.getElementById('alerts-live-indicator');
    if (!el) return;
    el.classList.toggle('offline', !active);
    const label = el.querySelector('.live-label');
    if (label) label.textContent = active ? 'Temps réel' : 'Hors ligne';
}
