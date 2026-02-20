import { esc } from './utils.js';

export function toast(type, title, message, duration = 4000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const icons = { success: '✓', error: '✗', info: 'ℹ', warning: '⚠' };
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.innerHTML = `
        <div class="toast-icon">${icons[type] || 'ℹ'}</div>
        <div class="toast-body">
            <div class="toast-title">${esc(title)}</div>
            ${message ? `<div class="toast-message">${esc(message)}</div>` : ''}
        </div>
        <button type="button" class="toast-close">✕</button>`;
    container.appendChild(el);
    const closeBtn = el.querySelector('.toast-close');
    if (closeBtn) closeBtn.addEventListener('click', () => el.remove());

    setTimeout(() => {
        el.classList.add('removing');
        setTimeout(() => el.remove(), 300);
    }, duration);
}
