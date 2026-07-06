/** Vue tableau des certificats */
let tableMode = localStorage.getItem('cert-view') === 'table';

export function isTableView() {
    return tableMode;
}

export function toggleCertView() {
    tableMode = !tableMode;
    localStorage.setItem('cert-view', tableMode ? 'table' : 'grid');
    return tableMode;
}

export function renderCertificatesTable(certs, container) {
    if (!container) return;
    if (!certs.length) {
        container.innerHTML = '<div class="empty-state"><i class="fas fa-certificate"></i><h3>Aucun certificat</h3></div>';
        return;
    }
    const badge = (c) => {
        if (c.is_expired) return '<span class="badge badge-expired">Expiré</span>';
        if ((c.days_until_expiry ?? 999) <= 7) return `<span class="badge badge-critical">Critique</span>`;
        if ((c.days_until_expiry ?? 999) <= 30) return `<span class="badge badge-expiring">Bientôt</span>`;
        return '<span class="badge badge-valid">Valide</span>';
    };
    container.innerHTML = `
        <table class="data-table" role="table" aria-label="Liste des certificats">
            <thead><tr>
                <th scope="col">CN</th><th scope="col">Organisation</th>
                <th scope="col">Expiration</th><th scope="col">Jours</th><th scope="col">Statut</th>
            </tr></thead>
            <tbody>
            ${certs.map(c => `
                <tr class="cert-table-row" data-cert-id="${c.id}" tabindex="0"
                    onclick="showCertificateDetails('${c.id}')"
                    onkeydown="if(event.key==='Enter')showCertificateDetails('${c.id}')">
                    <td><strong>${c.common_name || c.id.substring(0, 8)}</strong></td>
                    <td>${c.organization || '—'}</td>
                    <td>${c.not_valid_after ? new Date(c.not_valid_after).toLocaleDateString('fr-FR') : '—'}</td>
                    <td>${c.days_until_expiry ?? '—'}</td>
                    <td>${badge(c)}</td>
                </tr>
            `).join('')}
            </tbody>
        </table>
    `;
}
