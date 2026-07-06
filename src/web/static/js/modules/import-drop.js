/** Drag & drop import certificats */
export function initImportDropZone() {
    const zone = document.getElementById('import-drop-zone');
    const fileInput = document.getElementById('import-cert-file');
    if (!zone || !fileInput) return;

    ['dragenter', 'dragover'].forEach(evt => {
        zone.addEventListener(evt, (e) => {
            e.preventDefault();
            zone.classList.add('drag-over');
        });
    });
    ['dragleave', 'drop'].forEach(evt => {
        zone.addEventListener(evt, (e) => {
            e.preventDefault();
            zone.classList.remove('drag-over');
        });
    });
    zone.addEventListener('drop', (e) => {
        const files = e.dataTransfer?.files;
        if (files?.length) {
            fileInput.files = files;
            zone.querySelector('p')?.replaceChildren(
                document.createTextNode(files[0].name)
            );
        }
    });
}
