/** Internationalisation FR/EN */
const MESSAGES = {
    fr: {
        'nav.certificates': 'Certificats',
        'nav.generate': 'Générer',
        'nav.alerts': 'Alertes',
        'nav.settings': 'Paramètres',
        'cert.empty': 'Aucun certificat',
        'cert.refresh': 'Actualiser',
        'theme.dark': 'Mode sombre',
        'import.drop': 'Déposez vos fichiers ici',
        'wizard.next': 'Suivant',
        'wizard.prev': 'Précédent',
    },
    en: {
        'nav.certificates': 'Certificates',
        'nav.generate': 'Generate',
        'nav.alerts': 'Alerts',
        'nav.settings': 'Settings',
        'cert.empty': 'No certificates',
        'cert.refresh': 'Refresh',
        'theme.dark': 'Dark mode',
        'import.drop': 'Drop files here',
        'wizard.next': 'Next',
        'wizard.prev': 'Previous',
    },
};

let lang = localStorage.getItem('lang') || 'fr';

export function t(key) {
    return MESSAGES[lang]?.[key] || MESSAGES.fr[key] || key;
}

export function getLang() {
    return lang;
}

export function setLang(next) {
    lang = next === 'en' ? 'en' : 'fr';
    localStorage.setItem('lang', lang);
    applyI18n();
}

export function toggleLang() {
    setLang(lang === 'fr' ? 'en' : 'fr');
}

export function applyI18n() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        const text = t(key);
        if (text) el.textContent = text;
    });
    document.documentElement.lang = lang;
}

export function initI18n() {
    applyI18n();
}
