import { get, post, put, del } from './api.js';
import { state } from './state.js';
import { toast } from './toast.js';
import { esc, closeModal, setSubmitButtonLoading } from './utils.js';
import { openSSHTerminal } from './terminal.js';

export { closeModal };

export function initHostsTabs() {
    document.querySelectorAll('[data-hosts-tab]').forEach(btn => {
        btn.addEventListener('click', () => switchHostsTab(btn.dataset.hostsTab));
    });
}

export function switchHostsTab(key) {
    document.querySelectorAll('[data-hosts-tab]').forEach(t => t.classList.toggle('active', t.dataset.hostsTab === key));
    document.querySelectorAll('#view-hosts .view-tab-pane').forEach(p => p.classList.remove('active'));
    const pane = document.getElementById('hosts-pane-' + key);
    if (pane) pane.classList.add('active');
    if (key === 'manage') loadManageHosts();
}

export async function loadHosts() {
    try {
        state.hosts = await get('/hosts') || [];
        renderHosts();
    } catch (_) {}
}

export function renderHosts() {
    const container = document.getElementById('hosts-container');
    if (!container) return;

    const visibleHosts = state.hosts.filter(h => !h.disabled);
    const vlans = {};
    visibleHosts.forEach(h => {
        const vlan = h.vlan || 'Ungrouped';
        if (!vlans[vlan]) vlans[vlan] = [];
        vlans[vlan].push(h);
    });

    const vlanMeta = {
        'DMZ': { label: 'DMZ', subnet: '' },
        'MGMT': { label: 'Management', subnet: '' },
        'HOME': { label: 'Home', subnet: '' },
    };

    let html = '';
    for (const [vlan, vlanHosts] of Object.entries(vlans)) {
        const meta = vlanMeta[vlan] || { label: vlan, subnet: '' };
        const subnet = vlanHosts[0]?.subnet || '';
        const label = `${meta.label}${subnet ? ' — ' + subnet : ''}`;

        html += `
            <div class="vlan-header">
                <span class="vlan-header-label">${esc(label)}</span>
                <div class="vlan-header-line"></div>
            </div>
            <div class="host-grid">`;

        vlanHosts.forEach(h => {
            const badgeClass = vlan === 'DMZ' ? 'badge-vlan' :
                vlan === 'MGMT' ? 'badge-mgmt' :
                    vlan === 'HOME' ? 'badge-home' : 'badge-vlan';

            const protoBadges = (h.protocols || []).map(p => {
                const cls = p === 'SSH' ? 'badge-ssh' : p === 'RDP' ? 'badge-rdp' : p === 'VNC' ? 'badge-vnc' : 'badge-ssh';
                return `<span class="badge ${cls}">${esc(p)}</span>`;
            }).join('');

            const inUse = h.in_use_by || '';
            const isAdmin = state.currentUser && state.currentUser.role === 'platform-admin';
            const canConnect = h.online && (!inUse || isAdmin);
            const btnLabel = !h.online ? 'Offline' : inUse && isAdmin ? 'Take over' : inUse ? 'In use' : 'Connect';
            const policyBadges = [];
            if (h.require_reason) policyBadges.push('<span class="badge badge-policy">Requires reason</span>');
            if (h.requires_approval) policyBadges.push('<span class="badge badge-policy">Requires approval</span>');

            html += `
                <div class="host-card" data-action="connect-host" data-id="${esc(h.id)}">
                    <div class="host-card-top">
                        <div>
                            <div class="host-name">${esc(h.name)}</div>
                            <div class="host-ip">${esc(h.hostname)}</div>
                        </div>
                        <div class="host-status-dot ${h.online ? '' : 'offline'}"></div>
                    </div>
                    <div class="host-tags">
                        <span class="badge ${badgeClass}">${esc(vlan)}</span>
                        ${protoBadges}
                        ${policyBadges.join(' ')}
                        ${inUse ? `<span class="badge badge-warning" style="margin-left:0.25rem;">In use by ${esc(inUse)}</span>` : ''}
                    </div>
                    <div class="host-meta">
                        <div class="host-meta-item">OS: <span>${esc(h.os || 'Unknown')}</span></div>
                        ${h.requires_approval ? `<button class="btn btn-sm" style="margin-right:0.5rem;" data-action="request-access" data-id="${esc(h.id)}">Request access</button>` : ''}
                        <button class="host-connect-btn ${canConnect ? '' : 'offline'}"
                                data-action="connect-host" data-id="${esc(h.id)}"
                                ${canConnect ? '' : 'disabled'}>
                            ${btnLabel}
                        </button>
                    </div>
                </div>`;
        });

        html += '</div>';
    }

    if (visibleHosts.length === 0) {
        const isAdmin = state.currentUser && state.currentUser.role === 'platform-admin';
        html = `<div class="empty-state" style="padding:3rem 1rem; text-align:center;">
            <div style="font-size:2rem; margin-bottom:0.75rem; opacity:0.4;">🖥</div>
            <div style="color:var(--text-secondary); margin-bottom:0.5rem;">No hosts available</div>
            ${isAdmin ? '<div style="font-size:0.75rem; color:var(--text-dim);">Switch to the <strong>Manage</strong> tab to add your first host.</div>' : '<div style="font-size:0.75rem; color:var(--text-dim);">Ask an administrator to add hosts.</div>'}
        </div>`;
    }

    container.innerHTML = html;

    const groupCount = Object.keys(vlans).length;
    const subtitle = document.getElementById('hosts-subtitle');
    if (subtitle) subtitle.textContent = `Infrastructure access • ${visibleHosts.length} hosts across ${groupCount} groups`;

    const badge = document.getElementById('nav-hosts-count');
    if (badge) badge.textContent = state.hosts.length;
    const tabBadge = document.getElementById('hosts-tab-total-count');
    if (tabBadge) tabBadge.textContent = visibleHosts.length;
}

export function updateStats() {
    const totalEl = document.getElementById('stat-total-hosts');
    const detailEl = document.getElementById('stat-hosts-detail');
    if (totalEl) totalEl.textContent = state.hosts.length;
    const online = state.hosts.filter(h => h.online).length;
    const offline = state.hosts.length - online;
    if (detailEl) detailEl.textContent = `${online} online • ${offline} offline`;
}

export async function loadManageHosts() {
    try {
        state.hosts = await get('/hosts') || [];
        renderManageHosts();
    } catch (e) {
        console.error('Failed to load hosts for management:', e);
    }
}

export function initManageHostsFilter() {
    const input = document.getElementById('filter-manage-hosts');
    if (input) {
        let timer;
        input.addEventListener('input', () => {
            clearTimeout(timer);
            timer = setTimeout(renderManageHosts, 200);
        });
    }
}

export function renderManageHosts() {
    const tbody = document.getElementById('manage-hosts-body');
    if (!tbody) return;

    const query = (document.getElementById('filter-manage-hosts')?.value || '').toLowerCase().trim();
    const filtered = query
        ? state.hosts.filter(h => `${h.name} ${h.hostname} ${h.os}`.toLowerCase().includes(query))
        : state.hosts;

    const countEl = document.getElementById('filter-manage-hosts-count');
    if (countEl) {
        const total = state.hosts.length;
        countEl.textContent = filtered.length === total ? `${total} hosts` : `${filtered.length} / ${total} hosts`;
    }

    if (filtered.length === 0) {
        const msg = state.hosts.length === 0
            ? '<div class="empty-state-box"><svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><circle cx="6" cy="6" r="1"/><circle cx="6" cy="18" r="1"/></svg><div class="empty-msg">No hosts configured</div><div class="empty-hint">Click "Add Host" to create your first host</div></div>'
            : '<div class="empty-state-box"><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg><div class="empty-msg">No matching hosts</div><div class="empty-hint">Adjust your search filter</div></div>';
        tbody.innerHTML = `<tr><td colspan="6">${msg}</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(h => {
        const statusBadge = h.disabled
            ? '<span class="badge badge-disabled">Disabled</span>'
            : h.online
                ? '<span class="badge badge-online">Online</span>'
                : '<span class="badge badge-offline">Offline</span>';
        const toggleLabel = h.disabled ? 'Enable' : 'Disable';
        const toggleClass = h.disabled ? 'btn-success' : 'btn-warning';
        return `<tr class="${h.disabled ? 'row-disabled' : ''}">
            <td><strong>${esc(h.name)}</strong></td>
            <td>${esc(h.hostname)}</td>
            <td>${h.port}</td>
            <td>${esc(h.os || '—')}</td>
            <td>${statusBadge}</td>
            <td>
                <div class="row-actions" style="display:flex;gap:0.35rem;flex-wrap:wrap;">
                    <button class="btn btn-sm" data-action="edit-host" data-id="${esc(h.id)}">Edit</button>
                    <button class="btn btn-sm ${toggleClass}" data-action="toggle-host-disabled" data-id="${esc(h.id)}">${toggleLabel}</button>
                    <button class="btn btn-sm btn-danger" data-action="delete-host-manage" data-id="${esc(h.id)}" data-name="${esc(h.name)}">Delete</button>
                </div>
            </td>
        </tr>`;
    }).join('');
}

export async function toggleHostDisabled(hostId) {
    try {
        const result = await post('/hosts/' + hostId + '/toggle-disabled');
        const label = result.disabled ? 'disabled' : 'enabled';
        toast('success', 'Host ' + label, `${result.name} has been ${label}`);
        loadManageHosts();
    } catch (_) {}
}

export async function deleteHostFromManage(hostId, hostName) {
    if (!confirm(`Delete host "${hostName}"? This cannot be undone.`)) return;
    try {
        await del('/hosts/' + hostId);
        toast('success', 'Host deleted', `${hostName} has been removed`);
        loadManageHosts();
    } catch (_) {}
}

export async function loadDashboardStats() {
    try {
        const [active, history] = await Promise.all([
            get('/sessions').catch(() => []),
            get('/sessions/history').catch(() => []),
        ]);
        const allActive = active || [];
        const allHistory = history || [];

        const statActive = document.getElementById('stat-active-sessions');
        if (statActive) statActive.textContent = allActive.length;
        const statDetail = document.getElementById('stat-sessions-detail');
        if (statDetail) {
            const myActive = allActive.filter(s => s.user_id === state.currentUser?.id).length;
            statDetail.textContent = `${myActive} yours • ${allActive.length} total`;
        }

        const today = new Date().toDateString();
        const todayCount = allHistory.filter(s => new Date(s.connected_at).toDateString() === today).length
            + allActive.filter(s => new Date(s.connected_at).toDateString() === today).length;
        const statToday = document.getElementById('stat-today-connections');
        if (statToday) statToday.textContent = todayCount;
        const statConnDetail = document.getElementById('stat-connections-detail');
        if (statConnDetail) statConnDetail.textContent = `${allHistory.length} total historical`;

        const statSecurity = document.getElementById('stat-security-events');
        if (statSecurity) statSecurity.textContent = '0';
        const statSecDetail = document.getElementById('stat-security-detail');
        if (statSecDetail) statSecDetail.textContent = 'No denied events';
    } catch (_) {}
}

export function showRequestAccessModal(hostId) {
    const host = state.hosts.find(h => h.id === hostId);
    if (!host) return;
    const modal = document.getElementById('modal-request-access');
    const hid = document.getElementById('request-access-host-id');
    const reasonInput = document.getElementById('request-access-reason');
    if (!modal || !hid) return;
    hid.value = hostId;
    if (reasonInput) reasonInput.value = '';
    modal.classList.add('active');
}

export async function submitRequestAccess() {
    const hid = document.getElementById('request-access-host-id');
    const reasonInput = document.getElementById('request-access-reason');
    if (!hid || !hid.value) return;
    const reason = reasonInput ? reasonInput.value.trim() : '';
    try {
        await post('/access-requests', { host_id: hid.value, reason });
        toast('success', 'Request submitted', 'An approver will review your request.');
        document.getElementById('modal-request-access')?.classList.remove('active');
    } catch (e) {
        toast('error', 'Error', e.message || 'Failed to submit request');
    }
}

export function connectHost(hostId) {
    const host = state.hosts.find(h => h.id === hostId);
    if (!host || !host.online) return;
    if (host.require_reason) {
        showConnectReasonModal(hostId, host);
        return;
    }
    openSSHTerminal(hostId, host.ssh_user || '', '', '', '');
}

function showConnectReasonModal(hostId, host) {
    const modal = document.getElementById('modal-connect-reason');
    if (!modal) return;
    const input = document.getElementById('connect-reason-input');
    const err = document.getElementById('connect-reason-error');
    if (input) input.value = '';
    if (err) err.textContent = '';
    modal.dataset.connectHostId = hostId;
    modal.classList.add('active');
    const submit = () => {
        const reason = input ? input.value.trim() : '';
        if (!reason) {
            if (err) err.textContent = 'Reason for access is required.';
            return;
        }
        modal.classList.remove('active');
        openSSHTerminal(hostId, host.ssh_user || '', '', '', reason);
    };
    const btn = document.getElementById('connect-reason-submit');
    const cancel = document.getElementById('connect-reason-cancel');
    if (btn) btn.onclick = submit;
    if (cancel) cancel.onclick = () => modal.classList.remove('active');
    if (input) input.onkeydown = (e) => { if (e.key === 'Enter') submit(); };
}

export function onAddHostAuthChange(el) {
    document.getElementById('add-host-password-group').style.display = el.value === 'password' ? '' : 'none';
    document.getElementById('add-host-key-group').style.display = el.value === 'key' ? '' : 'none';
    if (el.value === 'key') populateKeySelect('add-host-key-select');
}

export function onEditHostAuthChange(el) {
    document.getElementById('edit-host-password-group').style.display = el.value === 'password' ? '' : 'none';
    document.getElementById('edit-host-key-group').style.display = el.value === 'key' ? '' : 'none';
    if (el.value === 'key') populateKeySelect('edit-host-key-select');
}

export function populateKeySelect(selectId) {
    const sel = document.getElementById(selectId);
    if (!sel) return;
    if (state.sshKeys.length > 0) {
        sel.innerHTML = '<option value="">Select a key...</option>' + state.sshKeys.map(k => `<option value="${esc(k.id)}">${esc(k.name)} (${esc(k.key_type)})</option>`).join('');
    } else {
        sel.innerHTML = '<option value="">Loading...</option>';
        get('/keys').then(keys => {
            state.sshKeys = keys || [];
            sel.innerHTML = '<option value="">Select a key...</option>' + state.sshKeys.map(k => `<option value="${esc(k.id)}">${esc(k.name)} (${esc(k.key_type)})</option>`).join('');
        }).catch(() => {
            sel.innerHTML = '<option value="">No keys available</option>';
        });
    }
}

export function showAddHostModal() {
    document.getElementById('modal-add-host')?.classList.add('active');
}

export async function submitAddHost(e) {
    e.preventDefault();
    const form = e.target;
    const data = {
        name: form.name.value.trim(),
        hostname: form.hostname.value.trim(),
        port: parseInt(form.port.value) || 22,
        os: form.os.value.trim(),
        protocols: form.protocols.value.split(',').map(s => s.trim()).filter(Boolean),
        ssh_user: form.ssh_user.value.trim(),
        ssh_auth_method: form.ssh_auth_method.value,
        ssh_password: form.ssh_password?.value || '',
        ssh_key_id: form.ssh_key_id?.value || '',
        require_reason: form.require_reason?.checked ?? false,
        requires_approval: form.requires_approval?.checked ?? false,
    };

    const btn = form.querySelector('button[type="submit"]');
    setSubmitButtonLoading(btn, true, 'Adding...');
    try {
        await post('/hosts', data);
        closeModal('modal-add-host');
        form.reset();
        form.port.value = '22';
        form.protocols.value = 'SSH';
        toast('success', 'Host added', `${data.name} has been added`);
        loadHosts();
        if (document.getElementById('hosts-pane-manage')?.classList.contains('active')) loadManageHosts();
    } catch (_) {}
    finally {
        setSubmitButtonLoading(btn, false);
    }
}

export function showEditHostModal(hostId) {
    const host = state.hosts.find(h => h.id === hostId);
    if (!host) return;
    state.editingHostId = hostId;

    const form = document.getElementById('form-edit-host');
    form.name.value = host.name || '';
    form.hostname.value = host.hostname || '';
    form.port.value = host.port || 22;
    form.os.value = host.os || '';
    form.protocols.value = (host.protocols || []).join(', ');
    form.ssh_user.value = host.ssh_user || '';
    form.ssh_auth_method.value = host.ssh_auth_method || 'password';
    form.ssh_password.value = '';
    if (form.ssh_key_id) form.ssh_key_id.value = host.ssh_key_id || '';
    if (form.require_reason) form.require_reason.checked = !!host.require_reason;
    if (form.requires_approval) form.requires_approval.checked = !!host.requires_approval;

    const method = host.ssh_auth_method || 'password';
    document.getElementById('edit-host-password-group').style.display = method === 'password' ? '' : 'none';
    document.getElementById('edit-host-key-group').style.display = method === 'key' ? '' : 'none';
    if (method === 'key') populateKeySelect('edit-host-key-select');

    document.getElementById('modal-edit-host').classList.add('active');
}

export async function submitEditHost(e) {
    e.preventDefault();
    if (!state.editingHostId) return;
    const form = e.target;
    const data = {
        name: form.name.value.trim(),
        hostname: form.hostname.value.trim(),
        port: parseInt(form.port.value) || 22,
        os: form.os.value.trim(),
        protocols: form.protocols.value.split(',').map(s => s.trim()).filter(Boolean),
        ssh_user: form.ssh_user.value.trim(),
        ssh_auth_method: form.ssh_auth_method.value,
        ssh_password: form.ssh_password?.value || '',
        ssh_key_id: form.ssh_key_id?.value || '',
        require_reason: form.require_reason?.checked ?? false,
        requires_approval: form.requires_approval?.checked ?? false,
    };

    const btn = form.querySelector('button[type="submit"]');
    setSubmitButtonLoading(btn, true, 'Saving...');
    try {
        await put('/hosts/' + state.editingHostId, { ...data, id: state.editingHostId });
        closeModal('modal-edit-host');
        toast('success', 'Host updated', `${data.name} has been updated`);
        loadHosts();
        if (document.getElementById('hosts-pane-manage')?.classList.contains('active')) loadManageHosts();
    } catch (_) {}
    finally {
        setSubmitButtonLoading(btn, false);
    }
}

export async function deleteHostFromModal() {
    if (!state.editingHostId) return;
    const host = state.hosts.find(h => h.id === state.editingHostId);
    if (!confirm(`Delete host "${host?.name || state.editingHostId}"? This cannot be undone.`)) return;
    try {
        await del('/hosts/' + state.editingHostId);
        closeModal('modal-edit-host');
        toast('success', 'Host deleted', `${host?.name || 'Host'} has been removed`);
        loadHosts();
        if (document.getElementById('hosts-pane-manage')?.classList.contains('active')) loadManageHosts();
    } catch (_) {}
}
