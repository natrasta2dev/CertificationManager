/**
 * Point d'entrée ES modules — charge les modules puis l'application legacy.
 */
import { API_BASE, apiFetch, getAuthToken, getAuthHeaders } from './modules/api.js';
import { initI18n, toggleLang, t } from './modules/i18n.js';
import { startAlertsStream, stopAlertsStream } from './modules/alerts-live.js';
import { initImportDropZone } from './modules/import-drop.js';
import { initGenerateWizard } from './modules/wizard.js';
import { isTableView, toggleCertView, renderCertificatesTable } from './modules/table-view.js';
import { initSidebar, setLiveIndicator } from './modules/layout.js';

Object.assign(window, {
    API_BASE, apiFetch, getAuthToken, getAuthHeaders,
    toggleLang, t, isTableView, toggleCertView, renderCertificatesTable,
    setLiveIndicator,
});

initI18n();
initSidebar();
initImportDropZone();
initGenerateWizard();

startAlertsStream((payload) => {
    setLiveIndicator(true);
    if (typeof window.onLiveAlerts === 'function') {
        window.onLiveAlerts(payload);
    }
});
