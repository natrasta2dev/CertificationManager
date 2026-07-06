// API Base URL
const API_BASE = '/api';

// Auth helpers
function getAuthToken() {
    return localStorage.getItem('auth_token');
}

function getAuthHeaders(extra = {}) {
    const headers = { ...extra };
    const token = getAuthToken();
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }
    const csrf = localStorage.getItem('csrf_token');
    if (csrf) {
        headers['X-CSRF-Token'] = csrf;
    }
    return headers;
}

async function apiFetch(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: getAuthHeaders(options.headers || {}),
    });

    if (response.status === 401) {
        const statusRes = await fetch(`${API_BASE}/auth/status`);
        const statusData = await statusRes.json();
        if (statusData?.data?.auth_enabled) {
            localStorage.removeItem('auth_token');
            localStorage.removeItem('auth_user');
            window.location.href = '/api/login';
            return response;
        }
    }

    return response;
}

async function checkAuthOnLoad() {
    try {
        const response = await fetch(`${API_BASE}/auth/status`);
        const result = await response.json();
        if (result?.data?.auth_enabled && !getAuthToken()) {
            window.location.href = '/api/login';
            return;
        }
        if (getAuthToken()) {
            const meRes = await apiFetch(`${API_BASE}/auth/me`);
            const meData = await meRes.json();
            if (meData?.data?.role) {
                currentUserRole = meData.data.role;
            }
            if (meData?.data?.role === 'admin') {
                document.getElementById('nav-audit')?.style.setProperty('display', 'inline-flex');
                document.getElementById('nav-admin')?.style.setProperty('display', 'inline-flex');
            } else if (result?.data?.auth_enabled) {
                document.getElementById('nav-audit')?.style.setProperty('display', 'inline-flex');
            }
        }
        updateSettingsFormAccess();
    } catch (e) {
        console.warn('Auth check failed', e);
    }
}

// State
let certificates = [];
let filteredCertificates = [];
let currentTab = 'certificates';
let statusChart = null;
let timelineChart = null;
let selectedCertificates = new Set();
let currentUserRole = 'admin';
let certPage = 1;
let certLimit = 20;
let certPagination = null;
let searchDebounceTimer = null;
let currentFilters = {
    status: '',
    keyType: '',
    expiryDays: '',
    organization: ''
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initKeyboardShortcuts();
    checkAuthOnLoad();
    initializeTabs();
    initializeForms();
    loadCertificates();
    loadAlerts();
});

function parseSanField(value) {
    return value ? value.split(',').map(s => s.trim()).filter(Boolean) : null;
}

function initTheme() {
    const saved = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', saved);
    updateThemeIcon(saved);
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateThemeIcon(next);
}

function updateThemeIcon(theme) {
    const btn = document.getElementById('theme-toggle');
    if (!btn) return;
    btn.innerHTML = theme === 'dark'
        ? '<i class="fas fa-sun"></i>'
        : '<i class="fas fa-moon"></i>';
}

function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        if (e.target.matches('input, textarea, select') && e.key !== 'Escape') return;
        if (e.key === '/') {
            e.preventDefault();
            document.getElementById('search-input')?.focus();
        } else if (e.key === 'n' && !e.ctrlKey && !e.metaKey) {
            switchTab('generate');
        } else if (e.key === 'r' && !e.ctrlKey && !e.metaKey) {
            if (currentTab === 'certificates') loadCertificates();
            else if (currentTab === 'alerts') loadAlerts();
        } else if (e.key === 'Escape') {
            closeModal();
        }
    });
}

// Tab Management
function initializeTabs() {
    const navButtons = document.querySelectorAll('.nav-btn');
    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const tab = btn.dataset.tab;
            switchTab(tab);
        });
    });
}

function switchTab(tab) {
    // Update nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tab);
    });

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `${tab}-tab`);
    });

    currentTab = tab;

    // Reload data if switching to specific tabs
    if (tab === 'certificates') {
        loadCertificates();
    } else if (tab === 'alerts') {
        loadAlerts();
    } else if (tab === 'import-export') {
        loadCertificatesForExport();
    } else if (tab === 'ca') {
        loadCA();
    } else if (tab === 'letsencrypt') {
        checkCertbotAndLoadLE();
    } else if (tab === 'client') {
        loadClientCertificates();
    } else if (tab === 'audit') {
        loadAuditLogs();
    } else if (tab === 'admin') {
        loadUsers();
    } else if (tab === 'archives') {
        loadArchives();
    } else if (tab === 'settings') {
        loadSettings();
    } else if (tab === 'csr') {
        loadCSRList();
    }
}

// Load Certificates
async function loadCertificates() {
    const loading = document.getElementById('loading');
    const list = document.getElementById('certificates-list');
    
    loading.style.display = 'block';
    list.innerHTML = '';

    try {
        const params = new URLSearchParams({
            page: String(certPage),
            limit: String(certLimit),
            sort: 'common_name',
            order: 'asc',
        });
        const status = document.getElementById('filter-status')?.value;
        if (status) params.set('status', status);
        const search = document.getElementById('search-input')?.value?.trim();
        if (search) params.set('search', search);

        const response = await apiFetch(`${API_BASE}/certificates?${params}`);
        const data = await response.json();

        if (data.success) {
            certificates = data.data;
            certPagination = data.pagination || null;
            displayCertificates(certificates);
            renderCertPagination();
            loadDashboardFromStats();
            selectedCertificates.clear();
            updateBulkActionsBar();
        } else {
            showToast('Erreur lors du chargement des certificats', 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    } finally {
        loading.style.display = 'none';
    }
}

function renderCertPagination() {
    const bar = document.getElementById('certificates-pagination');
    if (!bar || !certPagination) {
        if (bar) bar.style.display = 'none';
        return;
    }
    bar.style.display = 'flex';
    const info = document.getElementById('cert-page-info');
    if (info) {
        info.textContent = `Page ${certPagination.page} / ${certPagination.pages} (${certPagination.total} total)`;
    }
    const prev = document.getElementById('cert-page-prev');
    const next = document.getElementById('cert-page-next');
    if (prev) prev.disabled = certPagination.page <= 1;
    if (next) next.disabled = certPagination.page >= certPagination.pages;
    const limitSelect = document.getElementById('cert-page-limit');
    if (limitSelect) limitSelect.value = String(certLimit);
}

function changeCertPage(delta) {
    if (!certPagination) return;
    const newPage = certPage + delta;
    if (newPage < 1 || newPage > certPagination.pages) return;
    certPage = newPage;
    loadCertificates();
}

function changeCertLimit() {
    const limitSelect = document.getElementById('cert-page-limit');
    certLimit = parseInt(limitSelect?.value || '20', 10);
    certPage = 1;
    loadCertificates();
}

async function loadDashboardFromStats() {
    try {
        const response = await apiFetch(`${API_BASE}/statistics`);
        const result = await response.json();
        if (result.success && result.data) {
            updateDashboardFromStats(result.data);
        }
    } catch (e) {
        console.warn('Stats dashboard', e);
    }
}

function updateDashboardFromStats(stats) {
    const dashboardSection = document.getElementById('dashboard-section');
    if (!dashboardSection) return;
    if (!stats || stats.total === 0) {
        dashboardSection.style.display = 'none';
        return;
    }
    dashboardSection.style.display = 'block';
    document.getElementById('stat-total').textContent = stats.total || 0;
    document.getElementById('stat-valid').textContent = stats.valid || 0;
    document.getElementById('stat-expiring').textContent = (stats.expiring_soon || 0) + (stats.critical || 0);
    document.getElementById('stat-expired').textContent = stats.expired || 0;
    updateStatusChart({
        valid: stats.valid || 0,
        expiring_soon: stats.expiring_soon || 0,
        critical: stats.critical || 0,
        expired: stats.expired || 0,
    });
}

function displayCertificates(certs) {
    const list = document.getElementById('certificates-list');
    
    // Appliquer les filtres
    filteredCertificates = applyFiltersToCertificates(certs);
    
    if (filteredCertificates.length === 0) {
        list.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-certificate"></i>
                <h3>Aucun certificat</h3>
                <p>${certs.length > 0 ? 'Aucun certificat ne correspond aux filtres' : 'Générez votre premier certificat pour commencer'}</p>
            </div>
        `;
        updateBulkActionsBar();
        return;
    }

    list.innerHTML = filteredCertificates.map(cert => createCertificateCard(cert)).join('');
    
    // Add event listeners
    document.querySelectorAll('.certificate-card').forEach(card => {
        card.addEventListener('click', (e) => {
            if (!e.target.closest('.certificate-actions') && !e.target.closest('.certificate-checkbox')) {
                const certId = card.dataset.certId;
                showCertificateDetails(certId);
            }
        });
    });

    // Add checkbox handlers
    document.querySelectorAll('.certificate-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', (e) => {
            e.stopPropagation();
            const certId = checkbox.dataset.certId;
            if (checkbox.checked) {
                selectedCertificates.add(certId);
            } else {
                selectedCertificates.delete(certId);
            }
            updateCardSelection(certId, checkbox.checked);
            updateBulkActionsBar();
        });
    });

    // Add delete handlers
    document.querySelectorAll('.btn-delete').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.stopPropagation();
            const certId = btn.dataset.certId;
            if (confirm('Êtes-vous sûr de vouloir supprimer ce certificat ?')) {
                await deleteCertificate(certId);
            }
        });
    });
}

function createCertificateCard(cert) {
    const isExpired = cert.is_expired || false;
    const daysLeft = cert.days_until_expiry || 0;
    const isSelected = selectedCertificates.has(cert.id);
    const isWildcard = cert.is_wildcard || (cert.common_name && cert.common_name.startsWith('*.'));
    const certType = cert.certificate_type || 'server';
    const isClient = certType === 'client';
    
    let statusClass = 'status-valid';
    let statusText = '✅ Valide';
    let statusIcon = 'fa-check-circle';

    if (isExpired) {
        statusClass = 'status-expired';
        statusText = '❌ Expiré';
        statusIcon = 'fa-times-circle';
    } else if (daysLeft <= 7) {
        statusClass = 'status-warning';
        statusText = `🔴 ${daysLeft} jours`;
        statusIcon = 'fa-exclamation-triangle';
    } else if (daysLeft <= 30) {
        statusClass = 'status-warning';
        statusText = `⚠️ ${daysLeft} jours`;
        statusIcon = 'fa-exclamation-triangle';
    }

    const expiresDate = cert.not_valid_after 
        ? new Date(cert.not_valid_after).toLocaleDateString('fr-FR')
        : 'N/A';

    return `
        <div class="certificate-card ${isSelected ? 'selected' : ''}" data-cert-id="${cert.id}">
            <input type="checkbox" class="certificate-checkbox" data-cert-id="${cert.id}" ${isSelected ? 'checked' : ''}>
            <div class="certificate-header">
                <div>
                    <div class="certificate-name">
                        ${cert.common_name || 'N/A'}
                        ${isWildcard ? ' <span class="badge" style="background: #3b82f6; margin-left: 0.5rem;">Wildcard</span>' : ''}
                        ${isClient ? ' <span class="badge" style="background: #8b5cf6; margin-left: 0.5rem;">Client</span>' : ''}
                    </div>
                    <div class="certificate-id">${cert.id.substring(0, 8)}...</div>
                </div>
                <span class="certificate-status ${statusClass}">
                    <i class="fas ${statusIcon}"></i>
                    ${statusText}
                </span>
            </div>
            <div class="certificate-info">
                <div class="info-item">
                    <span class="info-label">Expire le:</span>
                    <span class="info-value">${expiresDate}</span>
                </div>
                ${daysLeft > 0 && !isExpired ? `
                <div class="info-item">
                    <span class="info-label">Jours restants:</span>
                    <span class="info-value">${daysLeft}</span>
                </div>
                ` : ''}
                ${cert.organization ? `
                <div class="info-item">
                    <span class="info-label">Organisation:</span>
                    <span class="info-value">${cert.organization}</span>
                </div>
                ` : ''}
            </div>
            <div class="certificate-actions">
                <button class="btn btn-sm btn-icon" onclick="showCertificateDetails('${cert.id}')" title="Détails">
                    <i class="fas fa-info-circle"></i>
                </button>
                ${isClient ? `
                <button class="btn btn-sm btn-secondary" onclick="exportClientCertificateForBrowser('${cert.id}')" title="Exporter pour navigateur">
                    <i class="fas fa-download"></i>
                </button>
                ` : `
                <button class="btn btn-sm btn-icon" onclick="verifyCertificate('${cert.id}')" title="Vérifier">
                    <i class="fas fa-check"></i>
                </button>
                <button class="btn btn-sm btn-primary" onclick="renewCertificate('${cert.id}')" title="Renouveler">
                    <i class="fas fa-sync-alt"></i>
                </button>
                `}
                <button class="btn btn-sm btn-danger btn-delete" data-cert-id="${cert.id}" title="Supprimer">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>
    `;
}

// Search
document.getElementById('search-input')?.addEventListener('input', () => {
    clearTimeout(searchDebounceTimer);
    searchDebounceTimer = setTimeout(() => {
        certPage = 1;
        loadCertificates();
    }, 350);
});

// Forms
function initializeForms() {
    const generateForm = document.getElementById('generate-form');
    const csrForm = document.getElementById('csr-form');
    const importForm = document.getElementById('import-form');
    const exportForm = document.getElementById('export-form');

    generateForm?.addEventListener('submit', handleGenerateSubmit);
    csrForm?.addEventListener('submit', handleCSRSubmit);
    importForm?.addEventListener('submit', handleImportSubmit);
    exportForm?.addEventListener('submit', handleExportSubmit);
    
    const caImportForm = document.getElementById('ca-import-form');
    caImportForm?.addEventListener('submit', handleCAImportSubmit);
    
    const letsencryptObtainForm = document.getElementById('letsencrypt-obtain-form');
    letsencryptObtainForm?.addEventListener('submit', handleLetsEncryptObtainSubmit);
    
    const clientGenerateForm = document.getElementById('client-generate-form');
    clientGenerateForm?.addEventListener('submit', handleClientGenerateSubmit);

    // Gérer l'affichage du champ CA pour certificats client
    const clientUseCA = document.getElementById('client-use-ca');
    const clientCASection = document.getElementById('client-ca-section');
    if (clientUseCA && clientCASection) {
        clientUseCA.addEventListener('change', (e) => {
            clientCASection.style.display = e.target.checked ? 'block' : 'none';
        });
    }

    // Gérer l'affichage du champ clé selon le format
    const importFormat = document.getElementById('import-format');
    const importKeyGroup = document.getElementById('import-key-group');
    if (importFormat && importKeyGroup) {
        importFormat.addEventListener('change', (e) => {
            if (e.target.value === 'p12') {
                importKeyGroup.style.display = 'none';
            } else {
                importKeyGroup.style.display = 'block';
            }
        });
    }

    // Charger la liste des certificats pour l'export
    loadCertificatesForExport();
}

async function handleGenerateSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const data = {
        common_name: formData.get('common_name'),
        validity_days: parseInt(formData.get('validity_days')) || 365,
        key_type: formData.get('key_type') || 'RSA',
        key_size: parseInt(formData.get('key_size')) || 2048,
        country: formData.get('country') || null,
        state: formData.get('state') || null,
        locality: formData.get('locality') || null,
        organization: formData.get('organization') || null,
        organizational_unit: formData.get('organizational_unit') || null,
        email: formData.get('email') || null,
        san_dns: parseSanField(formData.get('san_dns')),
        san_ip: parseSanField(formData.get('san_ip')),
    };
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });

        const result = await response.json();

        if (result.success) {
            showToast('Certificat généré avec succès !', 'success');
            e.target.reset();
            switchTab('certificates');
            loadCertificates();
            loadCertificatesForExport();
        } else {
            showToast(result.detail || 'Erreur lors de la génération', 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}

async function handleCSRSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const data = {
        common_name: formData.get('common_name'),
        key_type: formData.get('key_type') || 'RSA',
        key_size: parseInt(formData.get('key_size')) || 2048,
        country: formData.get('country') || null,
        state: formData.get('state') || null,
        locality: formData.get('locality') || null,
        organization: formData.get('organization') || null,
        organizational_unit: formData.get('organizational_unit') || null,
        email: formData.get('email') || null,
        san_dns: parseSanField(formData.get('san_dns')),
        san_ip: parseSanField(formData.get('san_ip')),
    };

    try {
        const response = await apiFetch(`${API_BASE}/csr`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });

        const result = await response.json();

        if (result.success) {
            showToast('CSR générée avec succès !', 'success');
            e.target.reset();
            loadCSRList();
        } else {
            showToast(result.detail || 'Erreur lors de la génération', 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}

// Certificate Details
async function showCertificateDetails(certId) {
    const modal = document.getElementById('cert-modal');
    const modalBody = document.getElementById('modal-body');
    const modalTitle = document.getElementById('modal-title');

    modal.classList.add('active');
    modalBody.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Chargement...</div>';

    try {
        const response = await apiFetch(`${API_BASE}/certificates/${certId}`);
        const result = await response.json();

        if (result.success) {
            const cert = result.data;
            modalTitle.textContent = `Certificat: ${cert.common_name || certId}`;
            modalBody.innerHTML = createCertificateDetailsHTML(cert);
        } else {
            modalBody.innerHTML = '<p>Erreur lors du chargement des détails</p>';
        }
    } catch (error) {
        modalBody.innerHTML = '<p>Erreur de connexion</p>';
        console.error(error);
    }
}

function createCertificateDetailsHTML(cert) {
    const formatDate = (dateStr) => {
        if (!dateStr) return 'N/A';
        return new Date(dateStr).toLocaleString('fr-FR');
    };

    return `
        <div class="modal-info">
            <div class="modal-info-item">
                <div class="modal-info-label">Nom Commun</div>
                <div class="modal-info-value">${cert.common_name || 'N/A'}</div>
            </div>
            <div class="modal-info-item">
                <div class="modal-info-label">ID</div>
                <div class="modal-info-value" style="font-family: monospace; font-size: 0.75rem;">${cert.id}</div>
            </div>
            <div class="modal-info-item">
                <div class="modal-info-label">Numéro de série</div>
                <div class="modal-info-value" style="font-family: monospace; font-size: 0.75rem;">${cert.serial_number || 'N/A'}</div>
            </div>
            <div class="modal-info-item">
                <div class="modal-info-label">Valide du</div>
                <div class="modal-info-value">${formatDate(cert.not_valid_before)}</div>
            </div>
            <div class="modal-info-item">
                <div class="modal-info-label">Valide jusqu'au</div>
                <div class="modal-info-value">${formatDate(cert.not_valid_after)}</div>
            </div>
            <div class="modal-info-item">
                <div class="modal-info-label">Statut</div>
                <div class="modal-info-value">
                    ${cert.is_expired ? '❌ Expiré' : '✅ Valide'}
                    ${!cert.is_expired && cert.days_until_expiry ? ` (${cert.days_until_expiry} jours restants)` : ''}
                </div>
            </div>
            ${cert.subject ? `
            <div class="modal-info-item">
                <div class="modal-info-label">Sujet</div>
                <div class="modal-info-value">${JSON.stringify(cert.subject, null, 2)}</div>
            </div>
            ` : ''}
            ${cert.issuer ? `
            <div class="modal-info-item">
                <div class="modal-info-label">Émetteur</div>
                <div class="modal-info-value">${JSON.stringify(cert.issuer, null, 2)}</div>
            </div>
            ` : ''}
            ${cert.subject_alternative_names && cert.subject_alternative_names.length > 0 ? `
            <div class="modal-info-item">
                <div class="modal-info-label">Subject Alternative Names</div>
                <div class="modal-info-value">${cert.subject_alternative_names.join(', ')}</div>
            </div>
            ` : ''}
            ${cert.renewed_from ? `
            <div class="modal-info-item">
                <div class="modal-info-label">Renouvelé depuis</div>
                <div class="modal-info-value">${cert.renewed_from.substring(0, 8)}...</div>
            </div>
            ` : ''}
        </div>
        <div class="modal-actions" style="margin-top: 1.5rem; padding-top: 1.5rem; border-top: 1px solid var(--border-color); display: flex; gap: 1rem; flex-wrap: wrap;">
            <button class="btn btn-secondary" onclick="verifyCertificateChain('${cert.id}')">
                <i class="fas fa-link"></i> Vérifier chaîne CA
            </button>
            <button class="btn btn-primary" onclick="renewCertificate('${cert.id}'); closeModal();">
                <i class="fas fa-sync-alt"></i> Renouveler
            </button>
            <button class="btn btn-secondary" onclick="closeModal()">
                Fermer
            </button>
        </div>
    `;
}

function closeModal() {
    document.getElementById('cert-modal').classList.remove('active');
}

// Verify Certificate
async function verifyCertificate(certId) {
    try {
        const response = await apiFetch(`${API_BASE}/certificates/${certId}/verify`);
        const result = await response.json();

        if (result.success) {
            if (result.data.valid) {
                showToast('✅ Le certificat est valide', 'success');
            } else {
                showToast(`❌ Le certificat n'est pas valide: ${result.data.errors.join(', ')}`, 'error');
            }
        } else {
            showToast('Erreur lors de la vérification', 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}

// Delete Certificate
async function deleteCertificate(certId) {
    try {
        const response = await apiFetch(`${API_BASE}/certificates/${certId}`, {
            method: 'DELETE',
        });

        const result = await response.json();

        if (result.success) {
            showToast('Certificat supprimé avec succès', 'success');
            selectedCertificates.delete(certId);
            updateBulkActionsBar();
            loadCertificates();
            loadAlerts();
        } else {
            showToast('Erreur lors de la suppression', 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}

// Refresh
function refreshCertificates() {
    loadCertificates();
}

// Toast Notifications
function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icon = type === 'success' ? 'fa-check-circle' 
                : type === 'error' ? 'fa-exclamation-circle'
                : 'fa-exclamation-triangle';
    
    toast.innerHTML = `
        <i class="fas ${icon}"></i>
        <span>${message}</span>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.animation = 'slideInRight 0.3s reverse';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Close modal on outside click
document.getElementById('cert-modal')?.addEventListener('click', (e) => {
    if (e.target.id === 'cert-modal') {
        closeModal();
    }
});

// Alerts Management
async function loadAlerts() {
    const loading = document.getElementById('alerts-loading');
    const alertsList = document.getElementById('alerts-list');
    const statsContainer = document.getElementById('alerts-stats');
    
    if (loading) loading.style.display = 'block';
    if (alertsList) alertsList.innerHTML = '';
    if (statsContainer) statsContainer.innerHTML = '';

    try {
        // Load statistics
        const statsResponse = await apiFetch(`${API_BASE}/statistics`);
        const statsData = await statsResponse.json();
        
        if (statsData.success && statsContainer) {
            const stats = statsData.data;
            statsContainer.innerHTML = `
                <div class="stat-card valid">
                    <div class="stat-value">${stats.total}</div>
                    <div class="stat-label">Total</div>
                </div>
                <div class="stat-card valid">
                    <div class="stat-value">${stats.valid}</div>
                    <div class="stat-label">Valides</div>
                </div>
                <div class="stat-card warning">
                    <div class="stat-value">${stats.expiring_soon}</div>
                    <div class="stat-label">Expirant bientôt</div>
                </div>
                <div class="stat-card critical">
                    <div class="stat-value">${stats.critical}</div>
                    <div class="stat-label">Critique (≤7j)</div>
                </div>
                <div class="stat-card expired">
                    <div class="stat-value">${stats.expired}</div>
                    <div class="stat-label">Expirés</div>
                </div>
            `;
        }

        // Load alerts
        const alertsResponse = await apiFetch(`${API_BASE}/alerts?include_expired=true`);
        const alertsData = await alertsResponse.json();

        if (alertsData.success && alertsList) {
            const alerts = alertsData.data;
            
            // Update badge
            const badge = document.getElementById('alerts-badge');
            if (badge) {
                if (alerts.length > 0) {
                    badge.textContent = alerts.length;
                    badge.style.display = 'inline-block';
                } else {
                    badge.style.display = 'none';
                }
            }

            if (alerts.length === 0) {
                alertsList.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-check-circle"></i>
                        <h3>Aucune alerte</h3>
                        <p>Tous vos certificats sont en bon état</p>
                    </div>
                `;
            } else {
                alertsList.innerHTML = alerts.map(alert => createAlertHTML(alert)).join('');
            }
        }
    } catch (error) {
        if (alertsList) {
            alertsList.innerHTML = '<p>Erreur lors du chargement des alertes</p>';
        }
        console.error(error);
    } finally {
        if (loading) loading.style.display = 'none';
    }
}

function createAlertHTML(alert) {
    const levelIcons = {
        'info': 'fa-info-circle',
        'warning': 'fa-exclamation-triangle',
        'critical': 'fa-exclamation-circle',
        'error': 'fa-times-circle',
    };

    const icon = levelIcons[alert.level] || 'fa-bell';
    const daysText = alert.days_until_expiry === 0 
        ? 'Expiré' 
        : `${alert.days_until_expiry} jour(s) restant(s)`;

    return `
        <div class="alert-item ${alert.level}">
            <i class="fas ${icon} alert-icon"></i>
            <div class="alert-content">
                <div class="alert-message">${alert.message}</div>
                <div class="alert-details">
                    ${alert.common_name} • ${daysText}
                </div>
            </div>
            <div class="alert-actions">
                <button class="btn btn-sm btn-icon" onclick="showCertificateDetails('${alert.cert_id}')" title="Détails">
                    <i class="fas fa-info-circle"></i>
                </button>
                <button class="btn btn-sm btn-primary" onclick="renewCertificate('${alert.cert_id}')" title="Renouveler">
                    <i class="fas fa-sync-alt"></i>
                </button>
            </div>
        </div>
    `;
}

function refreshAlerts() {
    loadAlerts();
}

// Import/Export Functions
async function loadCertificatesForExport() {
    try {
        const response = await apiFetch(`${API_BASE}/certificates?limit=500&page=1`);
        const result = await response.json();
        
        if (result.success) {
            const select = document.getElementById('export-cert-id');
            if (select) {
                // Garder l'option par défaut
                const defaultOption = select.querySelector('option[value=""]');
                select.innerHTML = '';
                if (defaultOption) {
                    select.appendChild(defaultOption);
                }
                
                result.data.forEach(cert => {
                    const option = document.createElement('option');
                    option.value = cert.id;
                    option.textContent = `${cert.common_name || cert.id} (${cert.id.substring(0, 8)}...)`;
                    select.appendChild(option);
                });
            }
        }
    } catch (error) {
        console.error('Erreur lors du chargement des certificats:', error);
    }
}

async function handleImportSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const format = formData.get('format');
    const password = formData.get('password') || null;
    const validate = formData.get('validate') === 'on';
    
    const certFile = document.getElementById('import-cert-file').files[0];
    const keyFile = document.getElementById('import-key-file').files[0];
    
    if (!certFile) {
        showToast('Veuillez sélectionner un fichier certificat', 'error');
        return;
    }
    
    try {
        showToast('Import en cours...', 'info');
        
        const uploadData = new FormData();
        uploadData.append('cert_file', certFile);
        if (keyFile) {
            uploadData.append('key_file', keyFile);
        }
        uploadData.append('format', format);
        if (password) {
            uploadData.append('password', password);
        }
        uploadData.append('validate', validate);
        
        const response = await apiFetch(`${API_BASE}/certificates/import`, {
            method: 'POST',
            body: uploadData,
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast(`✅ Certificat importé avec succès ! ID: ${result.data.id.substring(0, 8)}...`, 'success');
            e.target.reset();
            loadCertificates();
            loadCertificatesForExport();
        } else {
            showToast(`❌ Erreur: ${result.detail || 'Erreur lors de l\'import'}`, 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}

async function handleExportSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const certId = formData.get('cert_id');
    const format = formData.get('format');
    const includeKey = formData.get('include_key') === 'on';
    const password = formData.get('password') || null;
    
    if (!certId) {
        showToast('Veuillez sélectionner un certificat', 'error');
        return;
    }
    
    try {
        showToast('Export en cours...', 'info');
        
        const params = new URLSearchParams({
            format: format,
            include_key: includeKey.toString(),
        });
        if (password) {
            params.append('password', password);
        }
        
        const response = await apiFetch(`${API_BASE}/certificates/${certId}/export?${params}`, {
            method: 'POST',
        });
        
        const result = await response.json();
        
        if (result.success) {
            const files = extractExportFiles(result.data);
            files.forEach((file, index) => {
                setTimeout(() => {
                    downloadFile(file.content, file.filename, file.mime_type);
                }, index * 500);
            });
            showToast('✅ Certificat exporté avec succès !', 'success');
        } else {
            showToast(`❌ Erreur: ${result.detail || 'Erreur lors de l\'export'}`, 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}

function extractExportFiles(data) {
    const files = [];
    if (!data) return files;

    if (data.certificate) {
        files.push({
            content: data.certificate.file_data || data.certificate.content,
            filename: data.certificate.filename,
            mime_type: data.certificate.mime_type,
        });
        if (data.private_key) {
            files.push({
                content: data.private_key.file_data || data.private_key.content,
                filename: data.private_key.filename,
                mime_type: data.private_key.mime_type,
            });
        }
        return files;
    }

    if (data.file_data && data.filename) {
        files.push({
            content: data.file_data,
            filename: data.filename,
            mime_type: data.mime_type,
        });
    } else if (data.content && data.filename) {
        files.push({
            content: data.content,
            filename: data.filename,
            mime_type: data.mime_type,
        });
    }

    return files;
}

function downloadFile(base64Content, filename, mimeType) {
    const byteCharacters = atob(base64Content);
    const byteNumbers = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    const blob = new Blob([byteArray], { type: mimeType });
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// CA Management Functions
async function loadCA() {
    const loading = document.getElementById('ca-loading');
    const list = document.getElementById('ca-list');
    
    if (loading) loading.style.display = 'block';
    if (list) list.innerHTML = '';

    try {
        const response = await apiFetch(`${API_BASE}/ca`);
        const result = await response.json();

        if (result.success) {
            const cas = result.data;
            if (cas.length === 0) {
                if (list) {
                    list.innerHTML = `
                        <div class="empty-state">
                            <i class="fas fa-shield-alt"></i>
                            <h3>Aucune CA</h3>
                            <p>Importez votre première autorité de certification</p>
                        </div>
                    `;
                }
            } else {
                if (list) {
                    list.innerHTML = cas.map(ca => createCACard(ca)).join('');
                }
                
                // Add delete handlers
                document.querySelectorAll('.ca-delete').forEach(btn => {
                    btn.addEventListener('click', async (e) => {
                        e.stopPropagation();
                        const caId = btn.dataset.caId;
                        if (confirm('Êtes-vous sûr de vouloir supprimer cette CA ?')) {
                            await deleteCA(caId);
                        }
                    });
                });
            }
        } else {
            showToast('Erreur lors du chargement des CA', 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    } finally {
        if (loading) loading.style.display = 'none';
    }
}

function createCACard(ca) {
    const formatDate = (dateStr) => {
        if (!dateStr) return 'N/A';
        return new Date(dateStr).toISOString().split('T')[0];
    };

    const caType = ca.is_root ? 'Racine' : 'Intermediaire';
    const trusted = ca.is_trusted ? '✅' : '❌';

    return `
        <div class="certificate-card" data-ca-id="${ca.id}">
            <div class="certificate-info">
                <div class="certificate-header">
                    <h3>${ca.name || ca.common_name}</h3>
                    <span class="certificate-status ${ca.is_trusted ? 'valid' : 'expired'}">
                        ${trusted}
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">CN:</span>
                    <span class="info-value">${ca.common_name || 'N/A'}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Type:</span>
                    <span class="info-value">${caType}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Expire le:</span>
                    <span class="info-value">${formatDate(ca.not_valid_after)}</span>
                </div>
            </div>
            <div class="certificate-actions">
                <button class="btn btn-sm btn-danger ca-delete" data-ca-id="${ca.id}" title="Supprimer">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>
    `;
}

async function handleCAImportSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const caFile = document.getElementById('ca-import-file').files[0];
    const name = formData.get('name') || null;
    const isRoot = formData.get('is_root') === 'on';
    const isTrusted = formData.get('is_trusted') === 'on';
    
    if (!caFile) {
        showToast('Veuillez sélectionner un fichier CA', 'error');
        return;
    }
    
    try {
        showToast('Import en cours...', 'info');
        
        const uploadData = new FormData();
        uploadData.append('ca_file', caFile);
        if (name) {
            uploadData.append('name', name);
        }
        uploadData.append('is_root', isRoot.toString());
        uploadData.append('is_trusted', isTrusted.toString());
        
        const response = await apiFetch(`${API_BASE}/ca/import`, {
            method: 'POST',
            body: uploadData,
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast(`✅ CA importée avec succès ! ID: ${result.data.id.substring(0, 8)}...`, 'success');
            e.target.reset();
            loadCA();
        } else {
            showToast(`❌ Erreur: ${result.detail || 'Erreur lors de l\'import'}`, 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}

async function deleteCA(caId) {
    try {
        const response = await apiFetch(`${API_BASE}/ca/${caId}`, {
            method: 'DELETE',
        });

        const result = await response.json();

        if (result.success) {
            showToast('CA supprimée avec succès', 'success');
            loadCA();
        } else {
            showToast('Erreur lors de la suppression', 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}

function refreshCA() {
    loadCA();
}

// Let's Encrypt Functions
async function checkCertbotAndLoadLE() {
    try {
        const response = await apiFetch(`${API_BASE}/letsencrypt/check-certbot`);
        const result = await response.json();
        
        const checkDiv = document.getElementById('letsencrypt-certbot-check');
        if (checkDiv) {
            if (!result.data.available) {
                checkDiv.style.display = 'block';
            } else {
                checkDiv.style.display = 'none';
            }
        }
        
        loadLetsEncrypt();
    } catch (error) {
        console.error('Erreur lors de la vérification de certbot:', error);
        loadLetsEncrypt();
    }
}

async function loadLetsEncrypt() {
    const loading = document.getElementById('letsencrypt-loading');
    const list = document.getElementById('letsencrypt-list');
    
    if (loading) loading.style.display = 'block';
    if (list) list.innerHTML = '';

    try {
        const response = await apiFetch(`${API_BASE}/letsencrypt`);
        const result = await response.json();

        if (result.success) {
            const certs = result.data;
            if (certs.length === 0) {
                if (list) {
                    list.innerHTML = `
                        <div class="empty-state">
                            <i class="fas fa-lock"></i>
                            <h3>Aucun certificat Let's Encrypt</h3>
                            <p>Obtenez votre premier certificat Let's Encrypt</p>
                        </div>
                    `;
                }
            } else {
                if (list) {
                    list.innerHTML = certs.map(cert => createLetsEncryptCard(cert)).join('');
                }
                
                // Add renew handlers
                document.querySelectorAll('.le-renew').forEach(btn => {
                    btn.addEventListener('click', async (e) => {
                        e.stopPropagation();
                        const certId = btn.dataset.certId;
                        await renewLetsEncryptCertificate(certId);
                    });
                });
            }
        } else {
            showToast('Erreur lors du chargement des certificats Let\'s Encrypt', 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    } finally {
        if (loading) loading.style.display = 'none';
    }
}

function createLetsEncryptCard(cert) {
    const formatDate = (dateStr) => {
        if (!dateStr) return 'N/A';
        return new Date(dateStr).toISOString().split('T')[0];
    };

    const domains = cert.letsencrypt_domains || [];
    const domainsStr = domains.length > 0 ? domains.join(', ') : cert.common_name || 'N/A';
    const staging = cert.letsencrypt_staging ? '⚠️ Staging' : '✅ Production';

    return `
        <div class="certificate-card" data-cert-id="${cert.id}">
            <div class="certificate-info">
                <div class="certificate-header">
                    <h3>${cert.common_name || 'N/A'}</h3>
                    <span class="certificate-status valid">
                        ${staging}
                    </span>
                </div>
                <div class="info-item">
                    <span class="info-label">Domaines:</span>
                    <span class="info-value">${domainsStr.length > 50 ? domainsStr.substring(0, 50) + '...' : domainsStr}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Expire le:</span>
                    <span class="info-value">${formatDate(cert.not_valid_after)}</span>
                </div>
            </div>
            <div class="certificate-actions">
                <button class="btn btn-sm btn-primary le-renew" data-cert-id="${cert.id}" title="Renouveler">
                    <i class="fas fa-sync-alt"></i>
                </button>
                <button class="btn btn-sm btn-icon" onclick="showCertificateDetails('${cert.id}')" title="Détails">
                    <i class="fas fa-info-circle"></i>
                </button>
            </div>
        </div>
    `;
}

async function handleLetsEncryptObtainSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const domainsStr = formData.get('domains');
    const email = formData.get('email') || null;
    const staging = formData.get('staging') === 'on';
    const standalone = formData.get('standalone') === 'on';
    const webroot = formData.get('webroot') || null;
    
    if (!domainsStr) {
        showToast('Veuillez entrer au moins un domaine', 'error');
        return;
    }
    
    const domains = domainsStr.split(',').map(d => d.trim()).filter(d => d);
    
    if (domains.length === 0) {
        showToast('Veuillez entrer au moins un domaine valide', 'error');
        return;
    }
    
    try {
        showToast('Obtention du certificat Let\'s Encrypt en cours... Cela peut prendre quelques minutes.', 'info');
        
        const data = {
            domains: domains,
            staging: staging,
            standalone: standalone,
        };
        
        if (email) {
            data.email = email;
        }
        if (webroot) {
            data.webroot = webroot;
        }
        
        const response = await apiFetch(`${API_BASE}/letsencrypt/obtain`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast(`✅ Certificat Let's Encrypt obtenu avec succès ! ID: ${result.data.id.substring(0, 8)}...`, 'success');
            e.target.reset();
            loadLetsEncrypt();
            loadCertificates();
        } else {
            showToast(`❌ Erreur: ${result.detail || 'Erreur lors de l\'obtention du certificat'}`, 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}

async function renewLetsEncryptCertificate(certId) {
    if (!confirm('Êtes-vous sûr de vouloir renouveler ce certificat Let\'s Encrypt ?')) {
        return;
    }

    try {
        showToast('Renouvellement en cours...', 'info');
        
        const response = await apiFetch(`${API_BASE}/letsencrypt/${certId}/renew`, {
            method: 'POST',
        });

        const result = await response.json();

        if (result.success) {
            showToast(`✅ Certificat renouvelé avec succès ! Nouveau ID: ${result.data.new_cert_id.substring(0, 8)}...`, 'success');
            loadLetsEncrypt();
            loadCertificates();
        } else {
            showToast(`❌ Erreur: ${result.detail || 'Erreur lors du renouvellement'}`, 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}

function refreshLetsEncrypt() {
    checkCertbotAndLoadLE();
}

// Client Certificates Functions
async function loadClientCertificates() {
    const loading = document.getElementById('client-loading');
    const list = document.getElementById('client-list');
    
    if (loading) loading.style.display = 'block';
    if (list) list.innerHTML = '';

    try {
        const response = await apiFetch(`${API_BASE}/client-certificates`);
        const result = await response.json();

        if (result.success) {
            const certs = result.data;
            if (certs.length === 0) {
                if (list) {
                    list.innerHTML = `
                        <div class="empty-state">
                            <i class="fas fa-user-shield"></i>
                            <h3>Aucun certificat client</h3>
                            <p>Générez votre premier certificat client pour mutual TLS</p>
                        </div>
                    `;
                }
            } else {
                if (list) {
                    list.innerHTML = certs.map(cert => createCertificateCard(cert)).join('');
                }
                
                // Add event listeners
                document.querySelectorAll('#client-list .certificate-card').forEach(card => {
                    card.addEventListener('click', (e) => {
                        if (!e.target.closest('.certificate-actions') && !e.target.closest('.certificate-checkbox')) {
                            const certId = card.dataset.certId;
                            showCertificateDetails(certId);
                        }
                    });
                });
            }
        } else {
            showToast('Erreur lors du chargement des certificats client', 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    } finally {
        if (loading) loading.style.display = 'none';
    }
}

async function handleClientGenerateSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const useCA = formData.get('use_ca') === 'on';
    
    const data = new FormData();
    data.append('common_name', formData.get('common_name'));
    data.append('validity_days', formData.get('validity_days') || '365');
    data.append('key_type', formData.get('key_type') || 'RSA');
    data.append('key_size', formData.get('key_size') || '2048');
    
    if (formData.get('country')) data.append('country', formData.get('country'));
    if (formData.get('state')) data.append('state', formData.get('state'));
    if (formData.get('locality')) data.append('locality', formData.get('locality'));
    if (formData.get('organization')) data.append('organization', formData.get('organization'));
    if (formData.get('organizational_unit')) data.append('organizational_unit', formData.get('organizational_unit'));
    if (formData.get('email')) data.append('email', formData.get('email'));
    
    if (useCA) {
        const caCertFile = document.getElementById('client-ca-cert').files[0];
        const caKeyFile = document.getElementById('client-ca-key').files[0];
        
        if (!caCertFile || !caKeyFile) {
            showToast('Veuillez fournir le certificat CA et la clé privée CA', 'error');
            return;
        }
        
        data.append('ca_cert_file', caCertFile);
        data.append('ca_key_file', caKeyFile);
        
        const caPassword = formData.get('ca_password');
        if (caPassword) {
            data.append('ca_password', caPassword);
        }
    }
    
    try {
        showToast('Génération du certificat client en cours...', 'info');
        
        const response = await apiFetch(`${API_BASE}/client-certificates`, {
            method: 'POST',
            body: data,
        });
        
        const result = await response.json();
        
        if (result.success) {
            showToast(`✅ Certificat client généré avec succès ! ID: ${result.data.id.substring(0, 8)}...`, 'success');
            e.target.reset();
            document.getElementById('client-ca-section').style.display = 'none';
            loadClientCertificates();
            loadCertificates();
        } else {
            showToast(`❌ Erreur: ${result.detail || 'Erreur lors de la génération'}`, 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}

async function exportClientCertificateForBrowser(certId) {
    const password = prompt('Mot de passe pour protéger le fichier PKCS#12 (optionnel, laissez vide pour aucun):');
    
    try {
        showToast('Export en cours...', 'info');
        
        const params = new URLSearchParams();
        if (password) {
            params.append('password', password);
        }
        
        const response = await apiFetch(`${API_BASE}/client-certificates/${certId}/export-browser?${params}`, {
            method: 'POST',
        });
        
        const result = await response.json();
        
        if (result.success && result.data) {
            const files = extractExportFiles(result.data);
            if (files.length > 0) {
                const file = files[0];
                downloadFile(file.content, file.filename, file.mime_type);
            }
            showToast('✅ Certificat exporté avec succès !', 'success');
            showToast('Vous pouvez maintenant l\'importer dans votre navigateur', 'info');
        } else {
            showToast(`❌ Erreur: ${result.detail || 'Erreur lors de l\'export'}`, 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}

function refreshClientCertificates() {
    loadClientCertificates();
}

// Bulk Actions Functions
function toggleSelectAll() {
    const allSelected = filteredCertificates.every(cert => selectedCertificates.has(cert.id));
    
    if (allSelected) {
        // Désélectionner tout
        filteredCertificates.forEach(cert => {
            selectedCertificates.delete(cert.id);
            const checkbox = document.querySelector(`.certificate-checkbox[data-cert-id="${cert.id}"]`);
            if (checkbox) checkbox.checked = false;
            updateCardSelection(cert.id, false);
        });
    } else {
        // Sélectionner tout
        filteredCertificates.forEach(cert => {
            selectedCertificates.add(cert.id);
            const checkbox = document.querySelector(`.certificate-checkbox[data-cert-id="${cert.id}"]`);
            if (checkbox) checkbox.checked = true;
            updateCardSelection(cert.id, true);
        });
    }
    
    updateBulkActionsBar();
}

function updateCardSelection(certId, isSelected) {
    const card = document.querySelector(`.certificate-card[data-cert-id="${certId}"]`);
    if (card) {
        if (isSelected) {
            card.classList.add('selected');
        } else {
            card.classList.remove('selected');
        }
    }
}

function clearSelection() {
    selectedCertificates.clear();
    document.querySelectorAll('.certificate-checkbox').forEach(checkbox => {
        checkbox.checked = false;
    });
    document.querySelectorAll('.certificate-card').forEach(card => {
        card.classList.remove('selected');
    });
    updateBulkActionsBar();
}

function updateBulkActionsBar() {
    const bulkBar = document.getElementById('bulk-actions-bar');
    const selectAllBtn = document.getElementById('select-all-btn');
    const countSpan = document.getElementById('bulk-selection-count');
    
    const count = selectedCertificates.size;
    
    if (count > 0) {
        bulkBar.style.display = 'flex';
        if (selectAllBtn) selectAllBtn.style.display = 'inline-flex';
        if (countSpan) countSpan.textContent = count;
    } else {
        bulkBar.style.display = 'none';
        if (selectAllBtn) selectAllBtn.style.display = 'none';
    }
}

async function bulkRenew() {
    const certIds = Array.from(selectedCertificates);
    if (certIds.length === 0) return;
    
    if (!confirm(`Êtes-vous sûr de vouloir renouveler ${certIds.length} certificat(s) ?`)) {
        return;
    }
    
    try {
        showToast(`Renouvellement de ${certIds.length} certificat(s) en cours...`, 'info');
        
        const results = await Promise.allSettled(
            certIds.map(certId => 
                fetch(`${API_BASE}/certificates/${certId}/renew`, { method: 'POST' })
                    .then(res => res.json())
            )
        );
        
        const success = results.filter(r => r.status === 'fulfilled' && r.value.success).length;
        const failed = results.length - success;
        
        if (success > 0) {
            showToast(`✅ ${success} certificat(s) renouvelé(s) avec succès${failed > 0 ? `, ${failed} échec(s)` : ''}`, 'success');
        } else {
            showToast(`❌ Échec du renouvellement de tous les certificats`, 'error');
        }
        
        clearSelection();
        loadCertificates();
        loadAlerts();
    } catch (error) {
        showToast('Erreur lors du renouvellement en masse', 'error');
        console.error(error);
    }
}

async function bulkExport() {
    const certIds = Array.from(selectedCertificates);
    if (certIds.length === 0) return;
    
    const format = prompt('Format d\'export (PEM, DER, PKCS12) :', 'PEM');
    if (!format || !['PEM', 'DER', 'PKCS12'].includes(format.toUpperCase())) {
        showToast('Format invalide', 'error');
        return;
    }
    
    try {
        showToast(`Export de ${certIds.length} certificat(s) en cours...`, 'info');
        
        // Exporter chaque certificat individuellement
        for (const certId of certIds) {
            try {
                const response = await apiFetch(`${API_BASE}/certificates/${certId}/export?format=${format.toUpperCase()}&include_key=true`);
                const result = await response.json();
                
                if (result.success) {
                    const files = extractExportFiles(result.data);
                    const cert = certificates.find(c => c.id === certId);
                    files.forEach((file, index) => {
                        const defaultName = `${cert?.common_name || certId}_${format.toLowerCase()}.${format === 'PKCS12' ? 'p12' : format.toLowerCase()}`;
                        setTimeout(() => {
                            downloadFile(
                                file.content,
                                file.filename || defaultName,
                                file.mime_type
                            );
                        }, index * 300);
                    });
                }
            } catch (error) {
                console.error(`Erreur lors de l'export du certificat ${certId}:`, error);
            }
        }
        
        showToast(`✅ Export de ${certIds.length} certificat(s) terminé`, 'success');
        clearSelection();
    } catch (error) {
        showToast('Erreur lors de l\'export en masse', 'error');
        console.error(error);
    }
}

async function bulkDelete() {
    const certIds = Array.from(selectedCertificates);
    if (certIds.length === 0) return;
    
    if (!confirm(`⚠️ Êtes-vous sûr de vouloir supprimer définitivement ${certIds.length} certificat(s) ? Cette action est irréversible.`)) {
        return;
    }
    
    try {
        showToast(`Suppression de ${certIds.length} certificat(s) en cours...`, 'info');
        
        const results = await Promise.allSettled(
            certIds.map(certId => 
                fetch(`${API_BASE}/certificates/${certId}`, { method: 'DELETE' })
                    .then(res => res.json())
            )
        );
        
        const success = results.filter(r => r.status === 'fulfilled' && r.value.success).length;
        const failed = results.length - success;
        
        if (success > 0) {
            showToast(`✅ ${success} certificat(s) supprimé(s)${failed > 0 ? `, ${failed} échec(s)` : ''}`, 'success');
        } else {
            showToast(`❌ Échec de la suppression de tous les certificats`, 'error');
        }
        
        clearSelection();
        loadCertificates();
        loadAlerts();
    } catch (error) {
        showToast('Erreur lors de la suppression en masse', 'error');
        console.error(error);
    }
}

// Filters Functions
function toggleFilters() {
    const filtersContent = document.getElementById('filters-content');
    const filtersHeader = document.querySelector('.filters-header');
    const chevron = document.getElementById('filters-chevron');
    
    if (filtersContent.style.display === 'none') {
        filtersContent.style.display = 'block';
        filtersHeader.classList.add('active');
    } else {
        filtersContent.style.display = 'none';
        filtersHeader.classList.remove('active');
    }
}

function applyFilters() {
    currentFilters.status = document.getElementById('filter-status')?.value || '';
    currentFilters.keyType = document.getElementById('filter-key-type')?.value || '';
    currentFilters.expiryDays = document.getElementById('filter-expiry-days')?.value || '';
    currentFilters.organization = document.getElementById('filter-organization')?.value || '';
    
    certPage = 1;
    if (currentFilters.keyType || currentFilters.expiryDays || currentFilters.organization) {
        displayCertificates(certificates);
    } else {
        loadCertificates();
    }
}

function applyFiltersToCertificates(certs) {
    return certs.filter(cert => {
        // Filtre par statut
        if (currentFilters.status) {
            const isExpired = cert.is_expired || false;
            const daysLeft = cert.days_until_expiry || 0;
            
            if (currentFilters.status === 'valid' && (isExpired || daysLeft <= 30)) return false;
            if (currentFilters.status === 'expiring' && (isExpired || daysLeft > 30)) return false;
            if (currentFilters.status === 'critical' && (isExpired || daysLeft > 7)) return false;
            if (currentFilters.status === 'expired' && !isExpired) return false;
        }
        
        // Filtre par type de clé
        if (currentFilters.keyType && cert.key_type !== currentFilters.keyType) {
            return false;
        }
        
        // Filtre par jours jusqu'à expiration
        if (currentFilters.expiryDays) {
            const daysLeft = cert.days_until_expiry || 0;
            const maxDays = parseInt(currentFilters.expiryDays);
            if (daysLeft > maxDays || cert.is_expired) {
                return false;
            }
        }
        
        // Filtre par organisation
        if (currentFilters.organization) {
            const org = (cert.organization || '').toLowerCase();
            const filterOrg = currentFilters.organization.toLowerCase();
            if (!org.includes(filterOrg)) {
                return false;
            }
        }
        
        return true;
    });
}

function clearFilters() {
    document.getElementById('filter-status').value = '';
    document.getElementById('filter-key-type').value = '';
    document.getElementById('filter-expiry-days').value = '';
    document.getElementById('filter-organization').value = '';
    
    currentFilters = {
        status: '',
        keyType: '',
        expiryDays: '',
        organization: ''
    };
    
    displayCertificates(certificates);
}

// Dashboard Functions
function updateDashboard(certs) {
    if (!certs || certs.length === 0) {
        document.getElementById('dashboard-section').style.display = 'none';
        return;
    }

    const dashboardSection = document.getElementById('dashboard-section');
    if (dashboardSection) {
        dashboardSection.style.display = 'block';
    }

    // Calculer les statistiques
    const now = new Date();
    const stats = {
        total: certs.length,
        valid: 0,
        expiring: 0,
        expired: 0,
        critical: 0,
        warning: 0
    };

    const statusCounts = {
        valid: 0,
        expiring_soon: 0,
        critical: 0,
        expired: 0
    };

    const timelineData = [];

    certs.forEach(cert => {
        if (cert.is_expired) {
            stats.expired++;
            statusCounts.expired++;
        } else {
            const daysUntilExpiry = cert.days_until_expiry || 0;
            if (daysUntilExpiry <= 7) {
                stats.critical++;
                statusCounts.critical++;
            } else if (daysUntilExpiry <= 30) {
                stats.expiring++;
                statusCounts.expiring_soon++;
            } else {
                stats.valid++;
            }
        }

        // Données pour timeline
        if (cert.not_valid_after) {
            timelineData.push({
                date: new Date(cert.not_valid_after),
                name: cert.common_name || cert.id.substring(0, 8),
                days: cert.days_until_expiry || 0
            });
        }
    });

    // Mettre à jour les statistiques
    document.getElementById('stat-total').textContent = stats.total;
    document.getElementById('stat-valid').textContent = stats.valid;
    document.getElementById('stat-expiring').textContent = stats.expiring + stats.critical;
    document.getElementById('stat-expired').textContent = stats.expired;

    // Créer/mettre à jour le graphique de répartition
    updateStatusChart(statusCounts);

    // Créer/mettre à jour le graphique timeline
    updateTimelineChart(timelineData);
}

function updateStatusChart(statusCounts) {
    const ctx = document.getElementById('status-chart');
    if (!ctx) return;

    if (statusChart) {
        statusChart.destroy();
    }

    const data = [
        statusCounts.valid,
        statusCounts.expiring_soon,
        statusCounts.critical,
        statusCounts.expired
    ].filter(v => v > 0);

    const labels = [];
    const colors = [];
    const backgroundColors = [];

    if (statusCounts.valid > 0) {
        labels.push('Valides');
        colors.push('#10b981');
        backgroundColors.push('rgba(16, 185, 129, 0.8)');
    }
    if (statusCounts.expiring_soon > 0) {
        labels.push('Expirent bientôt');
        colors.push('#f59e0b');
        backgroundColors.push('rgba(245, 158, 11, 0.8)');
    }
    if (statusCounts.critical > 0) {
        labels.push('Critiques');
        colors.push('#ef4444');
        backgroundColors.push('rgba(239, 68, 68, 0.8)');
    }
    if (statusCounts.expired > 0) {
        labels.push('Expirés');
        colors.push('#6b7280');
        backgroundColors.push('rgba(107, 114, 128, 0.8)');
    }

    statusChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: backgroundColors,
                borderColor: colors,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

function updateTimelineChart(timelineData) {
    const ctx = document.getElementById('timeline-chart');
    if (!ctx) return;

    if (timelineChart) {
        timelineChart.destroy();
    }

    // Trier par date d'expiration
    timelineData.sort((a, b) => a.date - b.date);

    // Grouper par mois pour les 12 prochains mois
    const now = new Date();
    const months = [];
    const monthLabels = [];
    const monthCounts = {};

    for (let i = 0; i < 12; i++) {
        const monthDate = new Date(now.getFullYear(), now.getMonth() + i, 1);
        const monthKey = `${monthDate.getFullYear()}-${String(monthDate.getMonth() + 1).padStart(2, '0')}`;
        monthLabels.push(monthDate.toLocaleDateString('fr-FR', { month: 'short', year: 'numeric' }));
        monthCounts[monthKey] = 0;
    }

    timelineData.forEach(item => {
        const monthKey = `${item.date.getFullYear()}-${String(item.date.getMonth() + 1).padStart(2, '0')}`;
        if (monthCounts.hasOwnProperty(monthKey)) {
            monthCounts[monthKey]++;
        }
    });

    const counts = Object.values(monthCounts);

    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: monthLabels,
            datasets: [{
                label: 'Certificats expirant',
                data: counts,
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return `${context.parsed.y} certificat(s) expirant`;
                        }
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        stepSize: 1
                    }
                }
            }
        }
    });
}

// Renew Certificate
async function renewCertificate(certId) {
    if (!confirm('Êtes-vous sûr de vouloir renouveler ce certificat ?\n\nL\'ancien certificat sera archivé.')) {
        return;
    }

    try {
        showToast('Renouvellement en cours...', 'info');
        
        const response = await apiFetch(`${API_BASE}/certificates/${certId}/renew`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
        });

        const result = await response.json();

        if (result.success) {
            showToast(`✅ Certificat renouvelé avec succès ! Nouveau ID: ${result.data.new_cert_id.substring(0, 8)}...`, 'success');
            // Recharger les certificats et les alertes
            selectedCertificates.delete(certId);
            loadCertificates();
            loadAlerts();
        } else {
            showToast(`❌ Erreur: ${result.detail || 'Erreur lors du renouvellement'}`, 'error');
        }
    } catch (error) {
        showToast('Erreur de connexion', 'error');
        console.error(error);
    }
}


// --- Audit & Admin ---

async function loadAuditLogs() {
    const container = document.getElementById('audit-logs-container');
    if (!container) return;
    container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Chargement...</div>';
    try {
        const response = await apiFetch(`${API_BASE}/audit?limit=200`);
        const result = await response.json();
        if (!result.success || !result.data.length) {
            container.innerHTML = '<p class="empty-state">Aucune entrée d\'audit</p>';
            return;
        }
        container.innerHTML = result.data.map(log => `
            <div class="alert-card ${log.success ? '' : 'alert-critical'}">
                <div class="alert-header">
                    <span class="alert-level">${log.action}</span>
                    <span class="alert-date">${new Date(log.timestamp).toLocaleString('fr-FR')}</span>
                </div>
                <p><strong>${log.username}</strong> — ${log.resource_type || ''} ${log.resource_id || ''}</p>
            </div>
        `).join('');
    } catch (e) {
        container.innerHTML = '<p class="empty-state">Erreur</p>';
    }
}

function exportAuditLogs(format) {
    apiFetch(`${API_BASE}/audit/export?format=${format}&limit=5000`)
        .then(r => r.text())
        .then(text => {
            const blob = new Blob([text], { type: format === 'csv' ? 'text/csv' : 'application/json' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = `audit.${format}`;
            a.click();
        });
}

async function loadUsers() {
    const container = document.getElementById('users-list-container');
    if (!container) return;
    try {
        const response = await apiFetch(`${API_BASE}/auth/users`);
        const result = await response.json();
        if (!result.success) { container.innerHTML = '<p>Accès refusé</p>'; return; }
        container.innerHTML = `<table class="data-table"><thead><tr><th>Utilisateur</th><th>Rôle</th><th></th></tr></thead><tbody>
            ${result.data.map(u => `<tr><td>${u.username}</td><td>${u.role}</td>
            <td><button class="btn btn-sm btn-danger" onclick="deleteUser('${u.id}')">Supprimer</button></td></tr>`).join('')}
        </tbody></table>`;
    } catch (e) { container.innerHTML = '<p>Erreur</p>'; }
}

async function createUser(event) {
    event.preventDefault();
    const body = {
        username: document.getElementById('new-username').value,
        password: document.getElementById('new-password').value,
        role: document.getElementById('new-role').value,
    };
    const response = await apiFetch(`${API_BASE}/auth/users`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
    });
    const result = await response.json();
    if (result.success) { showToast('Utilisateur créé', 'success'); loadUsers(); }
    else showToast(result.detail || 'Erreur', 'error');
}

async function deleteUser(userId) {
    if (!confirm('Supprimer cet utilisateur ?')) return;
    const response = await apiFetch(`${API_BASE}/auth/users/${userId}`, { method: 'DELETE' });
    const result = await response.json();
    if (result.success) { showToast('Supprimé', 'success'); loadUsers(); }
}

// --- Archives, CSR list, Settings ---

async function loadArchives() {
    const container = document.getElementById('archives-list');
    if (!container) return;
    container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Chargement...</div>';
    try {
        const response = await apiFetch(`${API_BASE}/archives`);
        const result = await response.json();
        if (!result.success || !result.data?.length) {
            container.innerHTML = '<p class="empty-state">Aucun certificat archivé</p>';
            return;
        }
        container.innerHTML = result.data.map(arch => `
            <div class="certificate-card">
                <div class="certificate-header">
                    <h3>${arch.common_name || arch.id}</h3>
                    <span class="cert-status expired">Archivé</span>
                </div>
                <div class="certificate-info">
                    <p><i class="fas fa-calendar"></i> Archivé le ${arch.archived_at ? new Date(arch.archived_at).toLocaleString('fr-FR') : 'N/A'}</p>
                    <p><i class="fas fa-building"></i> ${arch.organization || '—'}</p>
                    <p><i class="fas fa-fingerprint"></i> ${arch.id?.substring(0, 12)}...</p>
                </div>
            </div>
        `).join('');
    } catch (e) {
        container.innerHTML = '<p class="empty-state">Erreur de chargement</p>';
    }
}

async function loadCSRList() {
    const container = document.getElementById('csr-list-container');
    if (!container) return;
    container.innerHTML = '<div class="loading"><i class="fas fa-spinner fa-spin"></i> Chargement...</div>';
    try {
        const [csrRes, caRes] = await Promise.all([
            apiFetch(`${API_BASE}/csr`),
            apiFetch(`${API_BASE}/ca`),
        ]);
        const csrData = await csrRes.json();
        const caData = await caRes.json();
        const cas = caData.success ? (caData.data || []) : [];

        if (!csrData.success || !csrData.data?.length) {
            container.innerHTML = '<p class="empty-state">Aucune CSR en attente</p>';
            return;
        }

        const caOptions = cas.map(ca =>
            `<option value="${ca.id}">${ca.common_name || ca.id}</option>`
        ).join('');

        container.innerHTML = csrData.data.map(csr => `
            <div class="csr-item" data-csr-id="${csr.id}">
                <div class="csr-item-info">
                    <h4>${csr.common_name || csr.id}</h4>
                    <small>${csr.organization || ''} — ${csr.key_type || 'RSA'} ${csr.key_size || ''} bits</small>
                </div>
                <div class="csr-item-actions">
                    <button class="btn btn-sm btn-secondary" onclick="downloadCSR('${csr.id}')" title="Télécharger PEM">
                        <i class="fas fa-download"></i>
                    </button>
                    ${cas.length ? `
                    <select id="ca-select-${csr.id}" class="pagination-limit">
                        ${caOptions}
                    </select>
                    <button class="btn btn-sm btn-primary" onclick="signCSR('${csr.id}')">
                        <i class="fas fa-signature"></i> Signer
                    </button>` : ''}
                    <button class="btn btn-sm btn-danger" onclick="deleteCSR('${csr.id}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        `).join('');
    } catch (e) {
        container.innerHTML = '<p class="empty-state">Erreur de chargement</p>';
    }
}

async function downloadCSR(csrId) {
    try {
        const response = await apiFetch(`${API_BASE}/csr/${csrId}`);
        const result = await response.json();
        if (!result.success) {
            showToast('CSR introuvable', 'error');
            return;
        }
        const blob = new Blob([result.data.csr_pem], { type: 'application/x-pem-file' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `${result.data.common_name || csrId}.csr.pem`;
        a.click();
    } catch (e) {
        showToast('Erreur téléchargement', 'error');
    }
}

async function signCSR(csrId) {
    const caSelect = document.getElementById(`ca-select-${csrId}`);
    const caId = caSelect?.value;
    if (!caId) {
        showToast('Sélectionnez une CA', 'warning');
        return;
    }
    try {
        const response = await apiFetch(`${API_BASE}/ca/${caId}/sign-csr`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ csr_id: csrId, validity_days: 365 }),
        });
        const result = await response.json();
        if (result.success) {
            showToast('Certificat signé avec succès', 'success');
            loadCSRList();
            loadCertificates();
        } else {
            showToast(result.detail || 'Erreur de signature', 'error');
        }
    } catch (e) {
        showToast('Erreur de connexion', 'error');
    }
}

async function deleteCSR(csrId) {
    if (!confirm('Supprimer cette CSR ?')) return;
    try {
        const response = await apiFetch(`${API_BASE}/csr/${csrId}`, { method: 'DELETE' });
        const result = await response.json();
        if (result.success) {
            showToast('CSR supprimée', 'success');
            loadCSRList();
        } else {
            showToast(result.detail || 'Erreur', 'error');
        }
    } catch (e) {
        showToast('Erreur de connexion', 'error');
    }
}

function updateSettingsFormAccess() {
    const isAdmin = currentUserRole === 'admin';
    const saveBtn = document.getElementById('settings-save-btn');
    if (saveBtn) saveBtn.style.display = isAdmin ? '' : 'none';
    document.querySelectorAll('#settings-tab input, #settings-tab textarea, #settings-tab select').forEach(el => {
        if (el.type !== 'button') el.disabled = !isAdmin;
    });
}

async function loadSettings() {
    updateSettingsFormAccess();
    try {
        const [notifRes, whRes, schedRes] = await Promise.all([
            apiFetch(`${API_BASE}/notifications/config`),
            apiFetch(`${API_BASE}/webhooks/config`),
            apiFetch(`${API_BASE}/scheduler/status`),
        ]);
        const notif = await notifRes.json();
        const wh = await whRes.json();
        const sched = await schedRes.json();

        if (notif.success) {
            const c = notif.data;
            document.getElementById('smtp-enabled').checked = !!c.enabled;
            document.getElementById('smtp-host').value = c.smtp_host || '';
            document.getElementById('smtp-port').value = c.smtp_port || 587;
            document.getElementById('smtp-user').value = c.smtp_user || '';
            document.getElementById('smtp-from').value = c.from_email || '';
            document.getElementById('smtp-to').value = (c.to_emails || []).join(', ');
            document.getElementById('smtp-use-tls').checked = c.use_tls !== false;
        }

        if (wh.success) {
            const c = wh.data;
            document.getElementById('webhook-enabled').checked = !!c.enabled;
            document.getElementById('webhook-endpoints').value = (c.endpoints || []).join('\n');
            const hint = document.getElementById('webhook-events-hint');
            if (hint && wh.events) {
                hint.textContent = `Événements : ${wh.events.join(', ')}`;
            }
        }

        if (sched.success) {
            const cfg = sched.data.config || {};
            document.getElementById('sched-interval').value = cfg.interval_minutes || 60;
            document.getElementById('sched-auto-renew').checked = !!cfg.auto_renew_enabled;
            document.getElementById('sched-renew-days').value = cfg.auto_renew_days || 30;
            document.getElementById('sched-alert-email').checked = !!cfg.alert_email_enabled;
            document.getElementById('sched-alert-webhook').checked = !!cfg.alert_webhook_enabled;
            const statusEl = document.getElementById('scheduler-status');
            if (statusEl) {
                statusEl.textContent = sched.data.running
                    ? `Planificateur actif (PID ${sched.data.pid})`
                    : 'Planificateur inactif';
            }
        }
    } catch (e) {
        showToast('Erreur chargement paramètres', 'error');
    }
}

async function saveSettings() {
    if (currentUserRole !== 'admin') {
        showToast('Accès réservé aux administrateurs', 'error');
        return;
    }
    try {
        const notifBody = {
            enabled: document.getElementById('smtp-enabled').checked,
            smtp_host: document.getElementById('smtp-host').value || null,
            smtp_port: parseInt(document.getElementById('smtp-port').value, 10) || 587,
            smtp_user: document.getElementById('smtp-user').value || null,
            from_email: document.getElementById('smtp-from').value || null,
            to_emails: document.getElementById('smtp-to').value
                .split(',').map(s => s.trim()).filter(Boolean),
            use_tls: document.getElementById('smtp-use-tls').checked,
        };
        const pwd = document.getElementById('smtp-password').value;
        if (pwd) notifBody.smtp_password = pwd;

        const whBody = {
            enabled: document.getElementById('webhook-enabled').checked,
            endpoints: document.getElementById('webhook-endpoints').value
                .split('\n').map(s => s.trim()).filter(Boolean),
        };
        const secret = document.getElementById('webhook-secret').value;
        if (secret) whBody.secret = secret;

        const schedBody = {
            interval_minutes: parseInt(document.getElementById('sched-interval').value, 10),
            auto_renew_enabled: document.getElementById('sched-auto-renew').checked,
            auto_renew_days: parseInt(document.getElementById('sched-renew-days').value, 10),
            alert_email_enabled: document.getElementById('sched-alert-email').checked,
            alert_webhook_enabled: document.getElementById('sched-alert-webhook').checked,
        };

        const [nRes, wRes, sRes] = await Promise.all([
            apiFetch(`${API_BASE}/notifications/config`, {
                method: 'PUT', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(notifBody),
            }),
            apiFetch(`${API_BASE}/webhooks/config`, {
                method: 'PUT', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(whBody),
            }),
            apiFetch(`${API_BASE}/scheduler/config`, {
                method: 'PUT', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(schedBody),
            }),
        ]);
        const nData = await nRes.json();
        const wData = await wRes.json();
        const sData = await sRes.json();
        if (nData.success && wData.success && sData.success) {
            showToast('Paramètres enregistrés', 'success');
            document.getElementById('smtp-password').value = '';
            document.getElementById('webhook-secret').value = '';
            loadSettings();
        } else {
            showToast('Erreur lors de la sauvegarde', 'error');
        }
    } catch (e) {
        showToast('Erreur de connexion', 'error');
    }
}

async function runSchedulerJob(jobName) {
    try {
        const response = await apiFetch(`${API_BASE}/scheduler/run/${jobName}`, { method: 'POST' });
        const result = await response.json();
        if (result.success) {
            showToast(`Job ${jobName} exécuté`, 'success');
        } else {
            showToast(result.detail || 'Erreur', 'error');
        }
    } catch (e) {
        showToast('Erreur de connexion', 'error');
    }
}

async function verifyCertificateChain(certId) {
    try {
        const response = await apiFetch(`${API_BASE}/certificates/${certId}/verify-chain`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        });
        const result = await response.json();
        if (result.success) {
            const { valid, errors } = result.data;
            if (valid) {
                showToast('Chaîne CA valide', 'success');
            } else {
                showToast(`Chaîne invalide: ${(errors || []).join('; ')}`, 'error');
            }
        } else {
            showToast(result.detail || 'Erreur', 'error');
        }
    } catch (e) {
        showToast('Erreur de vérification', 'error');
    }
}

async function runComplianceScan() {
    const container = document.getElementById('compliance-results');
    if (container) container.textContent = 'Scan en cours...';
    try {
        const response = await apiFetch(`${API_BASE}/compliance/scan`);
        const result = await response.json();
        if (!result.success || !container) return;
        const d = result.data;
        container.innerHTML = `
            <strong>${d.compliance_rate}% conformes</strong> —
            ${d.compliant}/${d.total} OK, ${d.issues_count} problème(s)
            ${d.issues?.length ? `<ul style="margin-top:0.5rem;">${d.issues.slice(0, 10).map(i =>
                `<li>${i.common_name || i.cert_id}: ${i.errors.join(', ')}</li>`
            ).join('')}</ul>` : ''}
        `;
    } catch (e) {
        if (container) container.textContent = 'Erreur de scan';
    }
}
