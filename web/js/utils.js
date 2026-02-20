/** HTML-escape for safe insertion into innerHTML */
export function esc(str) {
    if (str == null) return '';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}

export function formatTime(iso) {
    if (!iso) return '--';
    const d = new Date(iso);
    return d.toLocaleTimeString('en-US', { hour12: false });
}

export function formatDate(iso) {
    if (!iso) return '--';
    const d = new Date(iso);
    return d.toLocaleDateString('en-CA');
}

export function formatTimestamp(iso) {
    if (!iso) return '--';
    const d = new Date(iso);
    return d.toISOString().replace('T', ' ').substring(0, 19);
}

export function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    let val = bytes;
    while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
    return val.toFixed(1) + ' ' + units[i];
}

export function calcDuration(startISO, endISO) {
    if (!startISO) return '--';
    const start = new Date(startISO);
    const end = endISO ? new Date(endISO) : new Date();
    let seconds = Math.floor((end - start) / 1000);
    if (seconds < 0) seconds = 0;
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${h}h ${String(m).padStart(2, '0')}m ${String(s).padStart(2, '0')}s`;
}

export function closeModal(id) {
    document.getElementById(id)?.classList.remove('active');
}

/**
 * Set a submit button into loading state (disabled + label) or restore it.
 * @param {HTMLButtonElement} btn - The button element
 * @param {boolean} loading - True to show loading state
 * @param {string} [loadingText='Saving...'] - Text while loading
 */
export function setSubmitButtonLoading(btn, loading, loadingText = 'Saving...') {
    if (!btn) return;
    if (loading) {
        btn.dataset.originalText = btn.textContent;
        btn.textContent = loadingText;
        btn.disabled = true;
    } else {
        btn.textContent = btn.dataset.originalText || btn.textContent || 'Save';
        btn.disabled = false;
    }
}
