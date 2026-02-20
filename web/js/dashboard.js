import { get } from './api.js';
import { navigateTo } from './nav.js';
import { calcDuration } from './utils.js';

function formatUptime(seconds) {
    if (!seconds && seconds !== 0) return '—';
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
}

function actionClass(action) {
    if (!action) return 'action-default';
    const a = action.toLowerCase();
    if (a.includes('login') && a.includes('fail')) return 'action-fail';
    if (a.includes('login')) return 'action-login';
    if (a.includes('logout')) return 'action-logout';
    if (a.includes('ssh') || a.includes('session') || a.includes('connect')) return 'action-ssh';
    if (a.includes('denied') || a.includes('reject') || a.includes('fail')) return 'action-fail';
    if (a.includes('create') || a.includes('update') || a.includes('delete') || a.includes('setting') || a.includes('host') || a.includes('user') || a.includes('group') || a.includes('key')) return 'action-admin';
    return 'action-default';
}

function actionLabel(action) {
    if (!action) return '—';
    return action.replace(/[_.]/g, ' ');
}

function shortTime(ts) {
    if (!ts) return '';
    try {
        const d = new Date(ts);
        const now = new Date();
        const sameDay = d.toDateString() === now.toDateString();
        if (sameDay) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        return d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (_) {
        return ts;
    }
}

function esc(s) {
    const d = document.createElement('div');
    d.textContent = s || '';
    return d.innerHTML;
}

function certExpiryLabel(expiresStr) {
    if (!expiresStr) return 'N/A';
    try {
        const exp = new Date(expiresStr);
        const now = new Date();
        const days = Math.floor((exp - now) / 86400000);
        if (days < 0) return `<span class="health-bad">Expired</span>`;
        if (days < 30) return `<span class="health-warn">${days}d remaining</span>`;
        return `<span class="health-ok">${days}d remaining</span>`;
    } catch (_) {
        return expiresStr;
    }
}

let refreshTimer = null;
let firstLoad = true;

function showSkeletons() {
    const ids = ['metric-hosts-online', 'metric-sessions-active', 'metric-users-active', 'metric-logins-success', 'metric-logins-failed', 'metric-audit-events'];
    ids.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '<div class="skeleton-line skeleton-line-lg"></div>';
    });
}

export async function loadDashboard() {
    if (refreshTimer) clearInterval(refreshTimer);

    if (firstLoad) {
        showSkeletons();
        firstLoad = false;
    }

    await renderDashboard();

    refreshTimer = setInterval(renderDashboard, 30000);
}

async function renderDashboard() {
    const updatedEl = document.getElementById('dashboard-updated-at');
    try {
        const data = await get('/dashboard');
        if (!data) return;

        renderMetrics(data);
        renderActivity(data.recent_activity || []);
        renderSessions(data.active_sessions || []);
        renderHealth(data);
        renderInstanceFooter(data);

        if (updatedEl && data.at) {
            try {
                updatedEl.textContent = 'Updated ' + new Date(data.at).toLocaleString();
            } catch (_) {
                updatedEl.textContent = 'Updated just now';
            }
        }
    } catch (e) {
        console.error('Failed to load dashboard:', e);
        if (updatedEl) updatedEl.textContent = 'Failed to load metrics';
    }
}

function renderMetrics(data) {
    const setText = (id, val) => {
        const el = document.getElementById(id);
        if (el) el.textContent = val ?? '—';
    };

    setText('metric-hosts-online', `${data.hosts_online ?? 0} / ${data.hosts_total ?? 0}`);
    setText('metric-sessions-active', String(data.sessions_active ?? 0));
    setText('metric-users-active', `${data.users_active_24h ?? 0} / ${data.users_total ?? 0}`);
    setText('metric-logins-success', String(data.logins_success ?? 0));
    setText('metric-logins-failed', String(data.logins_failed ?? 0));
    setText('metric-audit-events', String(data.audit_events ?? 0));
}

function renderActivity(entries) {
    const list = document.getElementById('dash-activity-list');
    if (!list) return;

    if (!entries.length) {
        list.innerHTML = '<div class="empty-state" style="padding:2rem; text-align:center; font-size:0.75rem; color:var(--text-dim);">No recent activity</div>';
        return;
    }

    list.innerHTML = entries.map(e => {
        const ip = e.source_ip ? `<span class="activity-ip">${esc(e.source_ip)}</span>` : '';
        return `<div class="dash-activity-item">
            <span class="dash-activity-time">${shortTime(e.timestamp)}</span>
            <span class="dash-activity-action ${actionClass(e.action)}">${esc(actionLabel(e.action))}</span>
            <span class="dash-activity-detail"><span class="activity-user">${esc(e.username)}</span> ${esc(e.detail)} ${ip}</span>
        </div>`;
    }).join('');
}

function renderSessions(sessions) {
    const container = document.getElementById('dash-sessions-list');
    if (!container) return;

    if (!sessions.length) {
        container.innerHTML = '<div class="empty-state" style="padding:1.5rem; text-align:center; font-size:0.75rem; color:var(--text-dim);">No active sessions</div>';
        return;
    }

    container.innerHTML = sessions.map(s => {
        const dur = calcDuration(s.connected_at);
        return `<div class="dash-session-row">
            <span class="dash-session-user">${esc(s.username)}</span>
            <span class="dash-session-host">${esc(s.host_name)}</span>
            <span class="dash-session-duration session-duration-live" data-start="${esc(s.connected_at)}">${dur}</span>
        </div>`;
    }).join('');
}

function renderHealth(data) {
    const setText = (id, html) => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = html;
    };

    const mode = (data.deployment_mode || 'single').toUpperCase();
    setText('health-deployment', `<span class="health-ok">${esc(mode)}</span>`);

    const driver = (data.db_driver || 'unknown').toUpperCase();
    setText('health-db', `<span class="health-ok">${esc(driver)}</span>`);

    const health = data.health || {};
    if (health.tls_enabled) {
        setText('health-tls', certExpiryLabel(health.tls_cert_expires));
    } else {
        setText('health-tls', '<span class="health-warn">Disabled</span>');
    }

    setText('health-encryption', health.encryption_enabled
        ? '<span class="health-ok">Enabled</span>'
        : '<span class="health-warn">Disabled</span>'
    );

    setText('health-uptime', `<span class="health-ok">${formatUptime(data.uptime_seconds)}</span>`);
}

function renderInstanceFooter(data) {
    const idEl = document.getElementById('dash-instance-id');
    if (idEl) idEl.textContent = data.instance_id ? `Instance: ${data.instance_id}` : '';
}

export function initDashboard() {
    document.querySelectorAll('[data-view-link]').forEach(btn => {
        btn.addEventListener('click', () => navigateTo(btn.dataset.viewLink));
    });
}
