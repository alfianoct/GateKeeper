import { get, post, put, del } from './api.js';
import { state } from './state.js';
import { toast } from './toast.js';
import { esc, formatTimestamp, closeModal, setSubmitButtonLoading } from './utils.js';

export async function loadUsers() {
    try {
        state.allUsers = await get('/users') || [];
        renderUsers();
    } catch (e) {
        console.error('Failed to load users:', e);
    }
}

export function initUsersFilter() {
    const input = document.getElementById('filter-users');
    if (input) {
        let timer;
        input.addEventListener('input', () => {
            clearTimeout(timer);
            timer = setTimeout(renderUsers, 200);
        });
    }
}

export function renderUsers() {
    const tbody = document.getElementById('users-body');
    if (!tbody) return;
    const badge = document.getElementById('access-tab-users-count');
    if (badge) badge.textContent = state.allUsers.length;

    const query = (document.getElementById('filter-users')?.value || '').toLowerCase().trim();
    const filtered = query
        ? state.allUsers.filter(u => `${u.username} ${u.display_name} ${u.role} ${u.groups} ${u.auth_provider}`.toLowerCase().includes(query))
        : state.allUsers;

    const countEl = document.getElementById('filter-users-count');
    if (countEl) {
        const total = state.allUsers.length;
        countEl.textContent = filtered.length === total ? `${total} users` : `${filtered.length} / ${total} users`;
    }

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8"><div class="empty-state-box"><svg viewBox="0 0 24 24"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="8.5" cy="7" r="4"/><line x1="20" y1="8" x2="20" y2="14"/><line x1="23" y1="11" x2="17" y2="11"/></svg><div class="empty-msg">No matching users</div><div class="empty-hint">Try a different search or add a new user</div></div></td></tr>';
        return;
    }
    tbody.innerHTML = filtered.map(u => {
        const mfaBadge = u.mfa_enabled ? '<span class="badge badge-success" title="MFA Enabled" style="margin-left:0.25rem;">2FA</span>' : '';
        return `<tr>
        <td><code>${esc(u.username)}</code>${mfaBadge}</td>
        <td>${esc(u.display_name) || '--'}</td>
        <td><span class="badge ${u.role === 'platform-admin' ? 'badge-warning' : 'badge-success'}">${esc(u.role)}</span></td>
        <td>${esc(u.groups) || '--'}</td>
        <td><span class="badge badge-info">${esc(u.auth_provider) || 'local'}</span></td>
        <td style="font-variant-numeric: tabular-nums;">${formatTimestamp(u.last_login_at)}</td>
        <td><span class="badge ${u.disabled ? 'badge-danger' : 'badge-success'}">${u.disabled ? 'Disabled' : 'Active'}</span></td>
        <td>
            <div class="row-actions" style="display:flex; gap:0.25rem; flex-wrap:wrap;">
                <button class="btn btn-sm" data-action="edit-user" data-id="${esc(u.id)}" title="Edit">Edit</button>
                ${u.mfa_enabled ? `<button class="btn btn-sm btn-warning" data-action="reset-user-mfa" data-id="${esc(u.id)}" data-name="${esc(u.username)}" title="Reset MFA">Reset 2FA</button>` : ''}
                <button class="btn btn-sm ${u.disabled ? 'btn-primary' : 'btn-warning'}" data-action="toggle-user-disabled" data-id="${esc(u.id)}" data-disabled="${!u.disabled}" ${u.id === state.currentUser?.id ? 'disabled' : ''}>${u.disabled ? 'Enable' : 'Disable'}</button>
                <button class="btn btn-sm btn-danger" data-action="delete-user" data-id="${esc(u.id)}" ${u.id === state.currentUser?.id ? 'disabled title="Cannot delete yourself"' : ''}>Delete</button>
            </div>
        </td>
    </tr>`;
    }).join('');
}

export function showAddUserModal() {
    document.getElementById('form-add-user').reset();
    document.getElementById('modal-add-user').classList.add('active');
}

export async function submitAddUser(e) {
    e.preventDefault();
    const form = e.target;
    const data = {
        username: form.username.value.trim(),
        display_name: form.display_name.value.trim(),
        password: form.password.value,
        role: form.role.value,
        groups: form.groups.value.trim(),
    };
    const btn = form.querySelector('button[type="submit"]');
    setSubmitButtonLoading(btn, true, 'Creating...');
    try {
        await post('/users', data);
        closeModal('modal-add-user');
        toast('success', 'User created', `Account "${data.username}" created`);
        loadUsers();
    } catch (_) {}
    finally {
        setSubmitButtonLoading(btn, false);
    }
}

export function showEditUserModal(userId) {
    const user = state.allUsers.find(u => u.id === userId);
    if (!user) return;
    const form = document.getElementById('form-edit-user');
    document.getElementById('edit-user-id').value = user.id;
    form.username.value = user.username;
    form.display_name.value = user.display_name || '';
    form.role.value = user.role || 'user';
    form.groups.value = user.groups || '';
    form.password.value = '';
    document.getElementById('edit-user-disabled').checked = !!user.disabled;
    document.getElementById('modal-edit-user').classList.add('active');
}

export async function submitEditUser(e) {
    e.preventDefault();
    const form = e.target;
    const userId = document.getElementById('edit-user-id').value;
    const data = {
        display_name: form.display_name.value.trim(),
        role: form.role.value,
        groups: form.groups.value.trim(),
        disabled: document.getElementById('edit-user-disabled').checked,
    };
    const pw = form.password.value;
    if (pw) data.password = pw;
    const btn = form.querySelector('button[type="submit"]');
    setSubmitButtonLoading(btn, true, 'Saving...');
    try {
        await put('/users/' + userId, data);
        closeModal('modal-edit-user');
        toast('success', 'User updated', 'Account changes saved');
        loadUsers();
    } catch (_) {}
    finally {
        setSubmitButtonLoading(btn, false);
    }
}

export async function toggleUserDisabled(userId, disable) {
    try {
        await put('/users/' + userId, { disabled: disable });
        toast('success', disable ? 'User disabled' : 'User enabled', '');
        loadUsers();
    } catch (_) {}
}

export async function deleteUser(userId) {
    if (!confirm('Delete this user? This cannot be undone.')) return;
    try {
        await del('/users/' + userId);
        toast('success', 'User deleted', 'User account has been removed');
        loadUsers();
    } catch (_) {}
}

export async function resetUserMFA(userId, username) {
    if (!confirm(`Reset MFA for "${username}"? They will need to re-enroll.`)) return;
    try {
        await del('/users/' + userId + '/mfa');
        toast('success', 'MFA Reset', `Two-factor authentication has been reset for ${username}`);
        loadUsers();
    } catch (_) {}
}
