import { get, post, put, del } from './api.js';
import { state } from './state.js';
import { toast } from './toast.js';
import { esc, closeModal, setSubmitButtonLoading } from './utils.js';

export async function loadGroups() {
    try {
        const groups = await get('/groups');
        state.allGroups = groups || [];
        renderGroups();
    } catch (e) {
        console.error('Failed to load groups:', e);
    }
}

export function renderGroups() {
    const tbody = document.getElementById('groups-body');
    if (!tbody) return;
    const badge = document.getElementById('access-tab-groups-count');
    if (badge) badge.textContent = state.allGroups.length;
    if (state.allGroups.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state-box"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M8 12h8"/><path d="M12 8v8"/></svg><div class="empty-msg">No groups defined</div><div class="empty-hint">Groups control which hosts users can access</div></div></td></tr>';
        return;
    }
    const permLabels = {
        connect_hosts: 'Connect', view_sessions: 'Sessions', view_audit: 'Audit',
        manage_sessions: 'Kill', manage_hosts: 'Hosts', manage_users: 'Users', manage_keys: 'Keys',
        manage_groups: 'Groups', manage_settings: 'Settings'
    };
    tbody.innerHTML = state.allGroups.map(g => {
        const hostDisplay = g.allowed_hosts === '*'
            ? '<span class="badge badge-success">All Hosts</span>'
            : (g.allowed_hosts || '').split(',').map(id => {
                const h = state.hosts.find(h => h.id === id.trim());
                return `<span class="badge badge-info" style="margin:0.1rem;">${esc(h ? h.name : id.trim())}</span>`;
            }).join(' ');
        const perms = (g.permissions || []).map(p =>
            `<span class="badge badge-info" style="margin:0.1rem;">${esc(permLabels[p] || p)}</span>`
        ).join(' ') || '<span style="color:var(--text-dim);">\u2014</span>';
        const maxSess = g.max_sessions ? g.max_sessions : '<span style="color:var(--text-dim);">Global</span>';
        return `<tr>
            <td><code>${esc(g.name)}</code></td>
            <td>${esc(g.description) || '<span style="color:var(--text-dim)">\u2014</span>'}</td>
            <td>${perms}</td>
            <td>${hostDisplay}</td>
            <td>${maxSess}</td>
            <td>
                <div class="row-actions" style="display:flex;gap:0.25rem;">
                    <button class="btn btn-sm" data-action="edit-group" data-id="${esc(g.id)}">Edit</button>
                    <button class="btn btn-sm btn-danger" data-action="delete-group" data-id="${esc(g.id)}">Delete</button>
                </div>
            </td>
        </tr>`;
    }).join('');
}

export function populateGroupModal(group) {
    const form = document.getElementById('form-add-group');
    const titleEl = document.getElementById('group-modal-title');
    const submitBtn = document.getElementById('group-submit-btn');
    const editIdEl = document.getElementById('group-edit-id');

    if (group) {
        titleEl.textContent = 'Edit Group';
        submitBtn.textContent = 'Save Changes';
        editIdEl.value = group.id;
        form.name.value = group.name || '';
        form.description.value = group.description || '';
        const msField = document.getElementById('group-max-sessions');
        if (msField) msField.value = group.max_sessions || 0;
    } else {
        titleEl.textContent = 'Add Group';
        submitBtn.textContent = 'Create Group';
        editIdEl.value = '';
        form.reset();
        const msField = document.getElementById('group-max-sessions');
        if (msField) msField.value = 0;
    }

    const permCBs = document.querySelectorAll('#group-permissions-grid input[name="perm"]');
    const groupPerms = (group && group.permissions) ? group.permissions : [];
    permCBs.forEach(cb => { cb.checked = groupPerms.includes(cb.value); });

    const allHostsCb = document.getElementById('group-all-hosts');
    const isAll = !group || group.allowed_hosts === '*' || !group.allowed_hosts;
    const selectedHosts = (!isAll && group) ? group.allowed_hosts.split(',').map(s => s.trim()) : [];
    state.msSelectedHosts = new Set(isAll ? state.hosts.map(h => h.id) : selectedHosts);

    if (allHostsCb) allHostsCb.checked = isAll;
    state.msDropdownOpen = false;

    renderHostMultiSelect();
}

export function renderHostMultiSelect() {
    const isAll = document.getElementById('group-all-hosts')?.checked;
    const container = document.getElementById('group-hosts-dropdown');
    const selectedDiv = document.getElementById('group-selected-hosts');
    const searchInput = document.getElementById('group-host-search');
    const optionsDiv = document.getElementById('group-host-options');

    if (!container || !selectedDiv) return;

    if (isAll) {
        selectedDiv.innerHTML = '<span class="gk-ms-placeholder">All hosts selected (wildcard)</span>';
        selectedDiv.style.opacity = '0.5';
        selectedDiv.style.pointerEvents = 'none';
        if (searchInput) searchInput.style.display = 'none';
        if (optionsDiv) optionsDiv.style.display = 'none';
        state.msDropdownOpen = false;
        return;
    }

    selectedDiv.style.opacity = '';
    selectedDiv.style.pointerEvents = '';

    if (state.msSelectedHosts.size === 0) {
        selectedDiv.innerHTML = '<span class="gk-ms-placeholder">Click to select hosts...</span>';
    } else {
        selectedDiv.innerHTML = Array.from(state.msSelectedHosts).map(hid => {
            const h = state.hosts.find(x => x.id === hid);
            const name = h ? h.name : hid;
            return `<span class="gk-ms-tag">${esc(name)}<span class="gk-ms-remove" data-action="remove-host-from-select" data-id="${esc(hid)}">&times;</span></span>`;
        }).join('');
    }

    renderHostOptions('');
}

export function renderHostOptions(filter) {
    const optionsDiv = document.getElementById('group-host-options');
    if (!optionsDiv) return;
    const lower = (filter || '').toLowerCase();
    const filtered = state.hosts.filter(h => {
        if (!lower) return true;
        return h.name.toLowerCase().includes(lower) || h.hostname.toLowerCase().includes(lower);
    });
    if (filtered.length === 0) {
        optionsDiv.innerHTML = '<div style="padding:0.5rem;font-size:0.75rem;color:var(--text-dim);">No hosts match</div>';
    } else {
        optionsDiv.innerHTML = filtered.map(h => {
            const sel = state.msSelectedHosts.has(h.id) ? ' selected' : '';
            return `<div class="gk-ms-option${sel}" data-action="toggle-host-in-select" data-id="${esc(h.id)}">
                <span class="gk-ms-check"></span>
                <span class="gk-ms-label">${esc(h.name)} <span class="gk-ms-sublabel">(${esc(h.hostname)})</span></span>
            </div>`;
        }).join('');
    }
}

export function toggleHostDropdown() {
    if (document.getElementById('group-all-hosts')?.checked) return;
    state.msDropdownOpen = !state.msDropdownOpen;
    const searchInput = document.getElementById('group-host-search');
    const optionsDiv = document.getElementById('group-host-options');
    if (searchInput) { searchInput.style.display = state.msDropdownOpen ? '' : 'none'; if (state.msDropdownOpen) { searchInput.value = ''; searchInput.focus(); } }
    if (optionsDiv) optionsDiv.style.display = state.msDropdownOpen ? '' : 'none';
    if (state.msDropdownOpen) renderHostOptions('');
}

export function filterHostDropdown(val) {
    renderHostOptions(val);
}

export function toggleHostInSelect(hostId) {
    if (state.msSelectedHosts.has(hostId)) {
        state.msSelectedHosts.delete(hostId);
    } else {
        state.msSelectedHosts.add(hostId);
    }
    renderHostMultiSelect();
    const searchInput = document.getElementById('group-host-search');
    const optionsDiv = document.getElementById('group-host-options');
    if (searchInput) searchInput.style.display = '';
    if (optionsDiv) optionsDiv.style.display = '';
    state.msDropdownOpen = true;
    renderHostOptions(searchInput?.value || '');
}

export function removeHostFromSelect(hostId) {
    state.msSelectedHosts.delete(hostId);
    renderHostMultiSelect();
}

export function showAddGroupModal() {
    const loadH = state.hosts.length ? Promise.resolve() : get('/hosts').then(h => { state.hosts = h || []; });
    loadH.then(() => {
        populateGroupModal(null);
        document.getElementById('modal-add-group').classList.add('active');
    });
}

export function showEditGroupModal(groupId) {
    const group = state.allGroups.find(g => g.id === groupId);
    if (!group) return;
    const loadH = state.hosts.length ? Promise.resolve() : get('/hosts').then(h => { state.hosts = h || []; });
    loadH.then(() => {
        populateGroupModal(group);
        document.getElementById('modal-add-group').classList.add('active');
    });
}

export function onGroupAllHostsToggle(cb) {
    if (cb.checked) {
        state.msSelectedHosts = new Set(state.hosts.map(h => h.id));
    }
    renderHostMultiSelect();
}

export async function submitAddGroup(e) {
    e.preventDefault();
    const form = e.target;
    const editId = document.getElementById('group-edit-id').value;
    const allHosts = document.getElementById('group-all-hosts').checked;
    const selectedHosts = allHosts ? '*' : Array.from(state.msSelectedHosts).join(',');
    const selectedPerms = Array.from(document.querySelectorAll('#group-permissions-grid input[name="perm"]:checked')).map(cb => cb.value);
    const msField = document.getElementById('group-max-sessions');
    const data = {
        name: form.name.value.trim(),
        description: form.description.value.trim(),
        permissions: selectedPerms,
        allowed_hosts: selectedHosts || '*',
        max_sessions: msField ? parseInt(msField.value, 10) || 0 : 0,
    };
    const btn = form.querySelector('button[type="submit"]');
    setSubmitButtonLoading(btn, true, editId ? 'Saving...' : 'Creating...');
    try {
        if (editId) {
            await put('/groups/' + editId, data);
            closeModal('modal-add-group');
            toast('success', 'Group updated', `Group "${data.name}" saved`);
        } else {
            await post('/groups', data);
            closeModal('modal-add-group');
            toast('success', 'Group created', `Group "${data.name}" created`);
        }
        loadGroups();
    } catch (_) {}
    finally {
        setSubmitButtonLoading(btn, false);
    }
}

export async function deleteGroup(groupId) {
    if (!confirm('Delete this group? This cannot be undone.')) return;
    try {
        await del('/groups/' + groupId);
        toast('success', 'Group deleted', 'Group has been removed');
        loadGroups();
    } catch (_) {}
}

export async function loadGroupMappings() {
    try {
        const [mappings, groups] = await Promise.all([
            get('/group-mappings'),
            get('/groups'),
        ]);
        state.allGroupMappings = mappings || [];
        state.allGroups = groups || [];
        renderGroupMappings();
        populateMappingSelect();
    } catch (e) {
        console.error('Failed to load group mappings:', e);
    }
}

export function renderGroupMappings() {
    const container = document.getElementById('group-mappings-list');
    if (!container) return;
    if (state.allGroupMappings.length === 0) {
        container.innerHTML = '<div style="font-size: 0.75rem; color: var(--text-dim); padding: 0.5rem 0;">No mappings configured — external groups pass through as-is.</div>';
        return;
    }
    container.innerHTML = `<table class="sessions-table" style="margin-bottom:0.5rem;"><thead><tr>
        <th>External Group (OIDC)</th><th>→</th><th>GateKeeper Group</th><th></th>
    </tr></thead><tbody>${state.allGroupMappings.map(m => `<tr>
        <td><code>${esc(m.external_group)}</code></td>
        <td style="text-align:center;color:var(--accent-cyan);">→</td>
        <td><code>${esc(m.gatekeeper_group)}</code></td>
        <td><button class="btn btn-sm btn-danger" data-action="delete-group-mapping" data-id="${esc(m.id)}">Remove</button></td>
    </tr>`).join('')}</tbody></table>`;
}

export function populateMappingSelect() {
    const sel = document.getElementById('mapping-gatekeeper');
    if (!sel) return;
    sel.innerHTML = '<option value="">— select group —</option>' +
        state.allGroups.map(g => `<option value="${esc(g.name)}">${esc(g.name)}</option>`).join('');
}

export async function addGroupMapping() {
    const extInput = document.getElementById('mapping-external');
    const gkSelect = document.getElementById('mapping-gatekeeper');
    const ext = extInput ? extInput.value.trim() : '';
    const gk = gkSelect ? gkSelect.value : '';
    if (!ext || !gk) {
        toast('error', 'Missing fields', 'Both external group and GateKeeper group are required');
        return;
    }
    try {
        await post('/group-mappings', { external_group: ext, gatekeeper_group: gk });
        if (extInput) extInput.value = '';
        toast('success', 'Mapping added', `${ext} → ${gk}`);
        loadGroupMappings();
    } catch (_) {}
}

export async function deleteGroupMapping(id) {
    try {
        await del('/group-mappings/' + id);
        toast('success', 'Mapping removed', '');
        loadGroupMappings();
    } catch (_) {}
}
