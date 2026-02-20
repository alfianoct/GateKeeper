// gatekeeper spa — main entry point
import { API } from './config.js';
import { setOnUnauth, setOnApiError } from './api.js';
import { loadPartials } from './loader.js';
import * as auth from './auth.js';
import * as nav from './nav.js';
import * as hosts from './hosts.js';
import * as terminal from './terminal.js';
import * as sessions from './sessions.js';
import * as groups from './groups.js';
import * as settings from './settings.js';
import { initSettingsTabs, initIPRulesFilter } from './settings.js';
import { initHostsTabs, initManageHostsFilter } from './hosts.js';
import * as audit from './audit.js';
import { initAuditFilter } from './audit.js';
import * as dashboard from './dashboard.js';
import { initDashboard } from './dashboard.js';
import * as keys from './keys.js';
import * as users from './users.js';
import { initUsersFilter } from './users.js';
import * as security from './security.js';
import { state } from './state.js';
import { calcDuration } from './utils.js';
import { closeSessionViewer, initSessionsTabs, initSessionsFilter } from './sessions.js';
import { toast } from './toast.js';

// 401 → redirect to login
setOnUnauth(auth.showLogin);
auth.setOnLoginSuccess(bootApp);

// Centralized API error display (toast + console)
setOnApiError((e) => {
    toast('error', 'Error', e.message || 'Something went wrong');
    console.error(e);
});

function loadAccess() {
    users.loadUsers();
    groups.loadGroups();
    keys.loadKeys();
}

function initAccessTabs() {
    document.querySelectorAll('[data-access-tab]').forEach(btn => {
        btn.addEventListener('click', () => switchAccessTab(btn.dataset.accessTab));
    });
}

function switchAccessTab(key) {
    document.querySelectorAll('[data-access-tab]').forEach(t => t.classList.toggle('active', t.dataset.accessTab === key));
    document.querySelectorAll('#view-access .view-tab-pane').forEach(p => p.classList.remove('active'));
    const pane = document.getElementById('access-pane-' + key);
    if (pane) pane.classList.add('active');

    const btnMap = { users: 'access-btn-add-user', groups: 'access-btn-add-group', keys: 'access-btn-add-key' };
    Object.entries(btnMap).forEach(([tab, id]) => {
        const el = document.getElementById(id);
        if (el) el.style.display = tab === key ? '' : 'none';
    });
}

const loaders = {
    hosts: hosts.loadHosts,
    dashboard: dashboard.loadDashboard,
    sessions: sessions.loadSessions,
    audit: audit.loadAuditLog,
    access: loadAccess,
    settings: settings.loadSettings,
    security: security.loadSecurity,
};

export async function bootApp() {
    auth.showApp();
    await auth.loadCurrentUser();
    hosts.loadHosts();
}

async function init() {
    if (window.location.search) {
        window.history.replaceState({}, '', window.location.pathname);
    }

    nav.initNavigation(loaders);

    try {
        const res = await fetch(API + '/me', { credentials: 'same-origin' });
        if (res.ok) {
            await bootApp();
        } else {
            auth.showLogin();
        }
    } catch (_) {
        auth.showLogin();
    }
}

// Live duration ticker for session rows
setInterval(() => {
    document.querySelectorAll('.session-duration-live').forEach(el => {
        const start = el.dataset.start;
        if (start) el.textContent = calcDuration(start);
    });
}, 1000);

// Escape key closes the topmost open modal
document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const modal = document.querySelector('.modal-overlay.active');
    if (!modal) return;
    if (modal.id === 'modal-session-viewer') {
        closeSessionViewer();
    } else {
        modal.classList.remove('active');
    }
});

// Modal overlay click — close modal or session viewer
document.querySelectorAll('.modal-overlay').forEach(overlay => {
    overlay.addEventListener('click', (e) => {
        if (e.target === overlay) {
            if (overlay.id === 'modal-session-viewer') {
                closeSessionViewer();
            } else {
                overlay.classList.remove('active');
            }
        }
    });
});

// Group host multi-select: close dropdown when clicking outside
document.addEventListener('click', function (e) {
    if (!state.msDropdownOpen) return;
    const dropdown = document.getElementById('group-hosts-dropdown');
    if (dropdown && !dropdown.contains(e.target)) {
        state.msDropdownOpen = false;
        const searchInput = document.getElementById('group-host-search');
        const optionsDiv = document.getElementById('group-host-options');
        if (searchInput) searchInput.style.display = 'none';
        if (optionsDiv) optionsDiv.style.display = 'none';
    }
});

function initSidebarCollapse() {
    const sidebar = document.querySelector('.sidebar');
    const btn = document.getElementById('btn-sidebar-collapse');
    if (!sidebar || !btn) return;
    if (localStorage.getItem('gk-sidebar-collapsed') === '1') {
        sidebar.classList.add('collapsed');
    }
    btn.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
        localStorage.setItem('gk-sidebar-collapsed', sidebar.classList.contains('collapsed') ? '1' : '0');
    });
}

// Bind all event handlers from JS (CSP: no inline scripts)
function bindEventHandlers() {
    const el = (id) => document.getElementById(id);
    const on = (id, ev, fn) => { const e = el(id); if (e) e.addEventListener(ev, fn); };

    on('login-form', 'submit', (e) => { e.preventDefault(); GK.handleLogin(e); });
    on('login-oidc-btn', 'click', () => {
        const url = document.getElementById('login-oidc-btn')?.dataset?.ssoUrl || '/auth/oidc';
        window.location.href = url;
    });
    on('login-saml-btn', 'click', () => {
        window.location.href = '/auth/saml';
    });
    on('btn-logout', 'click', () => GK.handleLogout());

    on('btn-save-settings', 'click', () => GK.saveSettings());
    on('set-auth-mode', 'change', () => GK.onAuthModeChange());
    on('btn-test-webhook', 'click', () => GK.testAuditWebhook());
    on('btn-export-audit-json', 'click', () => GK.exportAudit('json'));
    on('btn-export-audit-csv', 'click', () => GK.exportAudit('csv'));
    on('btn-add-ip-rule', 'click', () => GK.addIPRule());

    on('form-add-host', 'submit', (e) => GK.submitAddHost(e));
    on('form-edit-host', 'submit', (e) => GK.submitEditHost(e));
    on('form-add-key', 'submit', (e) => GK.submitAddKey(e));
    on('form-add-user', 'submit', (e) => GK.submitAddUser(e));
    on('form-edit-user', 'submit', (e) => GK.submitEditUser(e));
    on('form-add-group', 'submit', (e) => GK.submitAddGroup(e));

    const hostAuthAdd = document.querySelector('#form-add-host select[name="ssh_auth_method"]');
    if (hostAuthAdd) hostAuthAdd.addEventListener('change', (e) => GK.onAddHostAuthChange(e.target));
    const hostAuthEdit = document.querySelector('#form-edit-host select[name="ssh_auth_method"]');
    if (hostAuthEdit) hostAuthEdit.addEventListener('change', (e) => GK.onEditHostAuthChange(e.target));
    on('group-all-hosts', 'change', (e) => GK.onGroupAllHostsToggle(e.target));
    on('group-selected-hosts', 'click', () => GK.toggleHostDropdown());
    on('group-host-search', 'input', (e) => GK.filterHostDropdown(e.target.value));

    on('ip-rule-scope', 'change', (e) => {
        const wrap = document.getElementById('ip-rule-scope-id-wrap');
        if (wrap) wrap.style.display = e.target.value === 'host' ? '' : 'none';
    });

    initSettingsTabs();
    initSessionsTabs();
    initHostsTabs();
    initAccessTabs();
    initDashboard();
    initAuditFilter();
    initSessionsFilter();
    initUsersFilter();
    initManageHostsFilter();
    initIPRulesFilter();
    initSidebarCollapse();

    on('sv-play-btn', 'click', () => GK.svTogglePlay());
    on('sv-speed', 'change', (e) => GK.svSetSpeed(e.target.value));
    on('sv-progress', 'input', (e) => GK.svSeek(e.target.value));
    on('sv-close-btn', 'click', () => GK.closeSessionViewer());

    document.querySelectorAll('[data-gk-close]').forEach(node => {
        node.addEventListener('click', () => GK.closeModal(node.getAttribute('data-gk-close')));
    });
    document.querySelectorAll('[data-gk-action]').forEach(node => {
        const action = node.getAttribute('data-gk-action');
        node.addEventListener('click', () => { if (typeof GK[action] === 'function') GK[action](); });
    });
}

// Delegated click for dynamic buttons (data-action, data-id)
document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-action]');
    if (!t || !window.GK) return;
    const action = t.getAttribute('data-action');
    const id = t.getAttribute('data-id');
    if (action === 'load-hosts') GK.loadHosts();
    else if (action === 'load-dashboard') GK.loadDashboard();
    else if (action === 'load-sessions') GK.loadSessions();
    else if (action === 'load-audit') GK.loadAuditLog();
    else if (action === 'load-manage-hosts') GK.loadManageHosts();
    else if (action === 'load-access') { GK.loadUsers(); GK.loadGroups(); GK.loadKeys(); }
    else if (action === 'kill-all-sessions') GK.killAllSessions();
    else if (action === 'show-add-key') GK.showAddKeyModal();
    else if (action === 'show-add-group') GK.showAddGroupModal();
    else if (action === 'show-add-user') GK.showAddUserModal();
    else if (action === 'show-add-host') GK.showAddHostModal();
    else if (action === 'add-group-mapping') GK.addGroupMapping();
    else if (action === 'edit-group' && id) GK.showEditGroupModal(id);
    else if (action === 'delete-group' && id) GK.deleteGroup(id);
    else if (action === 'delete-group-mapping' && id) GK.deleteGroupMapping(id);
    else if (action === 'edit-user' && id) GK.showEditUserModal(id);
    else if (action === 'delete-user' && id) GK.deleteUser(id);
    else if (action === 'toggle-user-disabled' && id) GK.toggleUserDisabled(id);
    else if (action === 'delete-key' && id) GK.deleteKey(id);
    else if (action === 'edit-host' && id) GK.showEditHostModal(id);
    else if (action === 'delete-host') GK.deleteHostFromModal();
    else if (action === 'delete-host-manage' && id) GK.deleteHostFromManage(id, t.getAttribute('data-name') || '');
    else if (action === 'toggle-host-disabled' && id) GK.toggleHostDisabled(id);
    else if (action === 'kill-session' && id) GK.killSession(id);
    else if (action === 'approve-request' && id) GK.approveAccessRequest(id);
    else if (action === 'reject-request' && id) GK.rejectAccessRequest(id);
    else if (action === 'replay-session' && id) GK.replaySession(id, t.getAttribute('data-host-name') || '');
    else if (action === 'watch-session' && id) GK.watchSession(id, t.getAttribute('data-host-name') || '', t.getAttribute('data-username') || '');
    else if (action === 'close-modal' && id) GK.closeModal(id);
    else if (action === 'remove-host-from-select' && id) { e.stopPropagation(); GK.removeHostFromSelect(id); }
    else if (action === 'toggle-host-in-select' && id) GK.toggleHostInSelect(id);
    else if (action === 'connect-host' && id) GK.connectHost(id);
    else if (action === 'request-access' && id) { e.stopPropagation(); GK.showRequestAccessModal(id); }
    else if (action === 'submit-request-access') GK.submitRequestAccess();
    else if (action === 'toggle-user-disabled' && id) GK.toggleUserDisabled(id, t.getAttribute('data-disabled') === 'true');
    else if (action === 'reset-user-mfa' && id) GK.resetUserMFA(id, t.getAttribute('data-name') || '')
    else if (action === 'delete-ip-rule' && id) GK.deleteIPRule(id)
    else if (action === 'close-terminal-tab' && id) { e.stopPropagation(); GK.closeTerminalTab(id); }
});

async function boot() {
    await loadPartials();
    init();
    bindEventHandlers();
    security.bindPasswordChange();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
} else {
    boot();
}

// Public API for HTML (GK.*) and data-action handlers
window.GK = {
    loadHosts: hosts.loadHosts,
    loadManageHosts: hosts.loadManageHosts,
    loadSessions: sessions.loadSessions,
    loadAuditLog: audit.loadAuditLog,
    loadDashboard: dashboard.loadDashboard,
    loadGroups: groups.loadGroups,
    loadKeys: keys.loadKeys,
    loadUsers: users.loadUsers,
    connectHost: hosts.connectHost,
    showRequestAccessModal: hosts.showRequestAccessModal,
    submitRequestAccess: hosts.submitRequestAccess,
    onAddHostAuthChange: hosts.onAddHostAuthChange,
    onEditHostAuthChange: hosts.onEditHostAuthChange,
    closeTerminalTab: terminal.closeTerminalTab,
    switchTab: terminal.switchTab,
    killSession: sessions.killSession,
    killAllSessions: sessions.killAllSessions,
    approveAccessRequest: sessions.approveAccessRequest,
    rejectAccessRequest: sessions.rejectAccessRequest,
    replaySession: sessions.replaySession,
    watchSession: sessions.watchSession,
    svTogglePlay: sessions.svTogglePlay,
    svSetSpeed: sessions.svSetSpeed,
    svSeek: sessions.svSeek,
    closeSessionViewer: sessions.closeSessionViewer,
    deleteKey: keys.deleteKey,
    deleteUser: users.deleteUser,
    showEditUserModal: users.showEditUserModal,
    submitEditUser: users.submitEditUser,
    toggleUserDisabled: users.toggleUserDisabled,
    resetUserMFA: users.resetUserMFA,
    deleteGroup: groups.deleteGroup,
    saveSettings: settings.saveSettings,
    onAuthModeChange: settings.onAuthModeChange,
    testAuditWebhook: settings.testAuditWebhook,
    exportAudit: settings.exportAudit,
    addIPRule: settings.addIPRule,
    deleteIPRule: settings.deleteIPRule,
    showAddHostModal: hosts.showAddHostModal,
    showEditHostModal: hosts.showEditHostModal,
    showAddKeyModal: keys.showAddKeyModal,
    showAddUserModal: users.showAddUserModal,
    showAddGroupModal: groups.showAddGroupModal,
    showEditGroupModal: groups.showEditGroupModal,
    onGroupAllHostsToggle: groups.onGroupAllHostsToggle,
    toggleHostDropdown: groups.toggleHostDropdown,
    filterHostDropdown: groups.filterHostDropdown,
    toggleHostInSelect: groups.toggleHostInSelect,
    removeHostFromSelect: groups.removeHostFromSelect,
    closeModal: hosts.closeModal,
    submitAddHost: hosts.submitAddHost,
    submitEditHost: hosts.submitEditHost,
    deleteHostFromModal: hosts.deleteHostFromModal,
    deleteHostFromManage: hosts.deleteHostFromManage,
    toggleHostDisabled: hosts.toggleHostDisabled,
    submitAddKey: keys.submitAddKey,
    submitAddUser: users.submitAddUser,
    submitAddGroup: groups.submitAddGroup,
    addGroupMapping: groups.addGroupMapping,
    deleteGroupMapping: groups.deleteGroupMapping,
    handleLogin: auth.handleLogin,
    handleLogout: auth.handleLogout,
};
