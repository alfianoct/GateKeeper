import { get, post, del } from './api.js';
import { state } from './state.js';
import { toast } from './toast.js';
import { esc, formatDate, closeModal, setSubmitButtonLoading } from './utils.js';

export async function loadKeys() {
    try {
        state.sshKeys = await get('/keys') || [];
        renderKeys();
    } catch (e) {
        console.error('Failed to load SSH keys:', e);
    }
}

export function renderKeys() {
    const body = document.getElementById('ssh-keys-body');
    if (!body) return;
    const badge = document.getElementById('access-tab-keys-count');
    if (badge) badge.textContent = state.sshKeys.length;

    if (state.sshKeys.length === 0) {
        body.innerHTML = '<tr><td colspan="6"><div class="empty-state-box"><svg viewBox="0 0 24 24"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg><div class="empty-msg">No SSH keys registered</div><div class="empty-hint">Add keys for key-based host authentication</div></div></td></tr>';
        return;
    }

    body.innerHTML = state.sshKeys.map(k => `
        <tr>
            <td><span style="color: ${k.is_system ? 'var(--accent-cyan)' : 'var(--accent-green)'}; font-weight: 600;">${esc(k.name)}</span></td>
            <td><span class="badge badge-ssh">${esc(k.key_type)}</span></td>
            <td style="font-size: 0.7rem; color: var(--text-dim);">${esc(k.fingerprint)}</td>
            <td style="font-variant-numeric: tabular-nums;">${formatDate(k.added_at)}</td>
            <td style="font-variant-numeric: tabular-nums;">${k.last_used_at ? formatDate(k.last_used_at) : 'Never'}</td>
            <td>${k.is_system
                ? '<span style="font-size: 0.65rem; color: var(--text-dim);">System key</span>'
                : `<button class="btn btn-sm btn-danger" data-action="delete-key" data-id="${esc(k.id)}">Revoke</button>`}
            </td>
        </tr>`).join('');
}

export async function deleteKey(id) {
    if (!confirm('Revoke this SSH key?')) return;
    try {
        await del('/keys/' + id);
        toast('success', 'Key revoked', 'SSH key has been revoked');
        loadKeys();
    } catch (_) {}
}

export function showAddKeyModal() {
    document.getElementById('modal-add-key')?.classList.add('active');
}

export async function submitAddKey(e) {
    e.preventDefault();
    const form = e.target;
    const data = {
        name: form.name.value.trim(),
        key_type: form.key_type.value,
        public_key: form.public_key.value.trim(),
    };
    const btn = form.querySelector('button[type="submit"]');
    setSubmitButtonLoading(btn, true, 'Adding...');
    try {
        await post('/keys', data);
        closeModal('modal-add-key');
        form.reset();
        toast('success', 'Key added', `SSH key "${data.name}" registered`);
        loadKeys();
    } catch (_) {}
    finally {
        setSubmitButtonLoading(btn, false);
    }
}
