/** Wizard création certificat (étapes) */
let wizardStep = 0;

export function initGenerateWizard() {
    const form = document.getElementById('generate-form');
    if (!form) return;
    const steps = form.querySelectorAll('.wizard-step');
    if (!steps.length) return;
    showWizardStep(0, steps);
    const nextBtn = document.getElementById('wizard-next');
    const prevBtn = document.getElementById('wizard-prev');
    nextBtn?.addEventListener('click', () => {
        if (wizardStep < steps.length - 1) showWizardStep(++wizardStep, steps);
    });
    prevBtn?.addEventListener('click', () => {
        if (wizardStep > 0) showWizardStep(--wizardStep, steps);
    });
}

function showWizardStep(step, steps) {
    const form = document.getElementById('generate-form');
    steps.forEach((el, i) => {
        el.style.display = i === step ? 'block' : 'none';
    });
    document.querySelectorAll('#generate-stepper .step').forEach((el, i) => {
        el.classList.toggle('active', i === step);
        el.classList.toggle('done', i < step);
    });
    const prev = document.getElementById('wizard-prev');
    const next = document.getElementById('wizard-next');
    const submit = form?.querySelector('button[type="submit"]');
    if (prev) prev.style.display = step > 0 ? '' : 'none';
    if (next) next.style.display = step < steps.length - 1 ? '' : 'none';
    if (submit) submit.style.display = step === steps.length - 1 ? '' : 'none';
}
