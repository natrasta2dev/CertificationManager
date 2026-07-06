/** Client API et authentification */
export const API_BASE = '/api';

export function getAuthToken() {
    return localStorage.getItem('auth_token');
}

export function getAuthHeaders(extra = {}) {
    const headers = { ...extra };
    const token = getAuthToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const csrf = localStorage.getItem('csrf_token');
    if (csrf) headers['X-CSRF-Token'] = csrf;
    return headers;
}

export async function apiFetch(url, options = {}) {
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
        }
    }
    return response;
}
