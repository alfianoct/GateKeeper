import { state } from './state.js';

let viewLoaders = {};

export function initNavigation(loaders) {
    viewLoaders = loaders || {};
    document.querySelectorAll('.nav-item[data-view]').forEach(item => {
        item.addEventListener('click', () => {
            navigateTo(item.dataset.view);
        });
    });
}

export function navigateTo(view) {
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

    const navItem = document.querySelector(`[data-view="${view}"]`);
    const viewEl = document.getElementById('view-' + view);
    if (navItem) navItem.classList.add('active');
    if (viewEl) viewEl.classList.add('active');

    const load = viewLoaders[view];
    if (load && typeof load === 'function') load();
}

export function applyRoleNav() {
    const adminNav = document.getElementById('admin-nav');
    if (!adminNav) return;
    const isAdmin = state.currentUser && state.currentUser.role === 'platform-admin';
    const perms = (state.currentUser && state.currentUser.permissions) || [];
    const hasPerm = p => isAdmin || perms.includes(p);

    if (isAdmin || perms.length > 0) {
        adminNav.style.display = '';
    } else {
        adminNav.style.display = 'none';
    }

    const navPermMap = {
        'dashboard': 'view_audit',
        'sessions': 'view_sessions',
        'audit': 'view_audit',
        'access': 'manage_users',
        'settings': 'manage_settings',
    };
    adminNav.querySelectorAll('.nav-item[data-view]').forEach(el => {
        const view = el.getAttribute('data-view');
        const requiredPerm = navPermMap[view];
        if (requiredPerm) {
            el.style.display = hasPerm(requiredPerm) ? '' : 'none';
        }
    });

    document.querySelectorAll('.admin-only').forEach(el => {
        el.style.display = isAdmin ? '' : 'none';
    });
}
