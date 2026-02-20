import { get } from './api.js';
import { state } from './state.js';
import { esc, formatTimestamp } from './utils.js';

let filterTimer = null;

function auditActionClass(action) {
    if (!action) return 'action-connect';
    const a = action.toLowerCase();
    if (a.includes('denied') || a.includes('reject') || a.includes('fail')) return 'action-denied';
    if (a.includes('connect') && !a.includes('disconnect')) return 'action-connect';
    if (a.includes('disconnect')) return 'action-disconnect';
    if (a.includes('login') || a.includes('auth') || a.includes('logout')) return 'action-auth';
    if (a.includes('ssh') || a.includes('session')) return 'action-session';
    if (a.includes('create') || a.includes('update') || a.includes('delete') || a.includes('setting') || a.includes('host') || a.includes('user') || a.includes('group') || a.includes('key')) return 'action-admin-op';
    return 'action-connect';
}

export async function loadAuditLog() {
    try {
        state.auditEntries = await get('/audit?limit=200') || [];
        renderAuditLog();
    } catch (e) {
        console.error('Failed to load audit log:', e);
    }
}

export function renderAuditLog() {
    const tbody = document.getElementById('audit-log-body');
    if (!tbody) return;

    const filtered = getFilteredAudit();

    const countEl = document.getElementById('filter-audit-count');
    if (countEl) {
        const total = state.auditEntries.length;
        countEl.textContent = filtered.length === total ? `${total} entries` : `${filtered.length} / ${total} entries`;
    }

    const subtitle = document.getElementById('audit-subtitle');
    if (subtitle) subtitle.textContent = `Complete access trail \u2022 ${state.auditEntries.length} entries`;

    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6"><div class="empty-state-box"><svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg><div class="empty-msg">No matching audit entries</div><div class="empty-hint">Adjust your search or date range filters</div></div></td></tr>';
        return;
    }

    tbody.innerHTML = filtered.map(e => {
        const cls = auditActionClass(e.action);
        return `<tr>
            <td style="font-variant-numeric:tabular-nums; font-size:0.7rem; white-space:nowrap; color:var(--text-dim);">${formatTimestamp(e.timestamp)}</td>
            <td><span class="audit-action-badge ${cls}">${esc(e.action)}</span></td>
            <td><span class="audit-user">${esc(e.username)}</span></td>
            <td style="font-size:0.75rem; color:var(--text-secondary);">${esc(e.detail)}${e.target ? ' on <span class="audit-target">' + esc(e.target) + '</span>' : ''}${e.reason ? '<br><span style="font-size:0.65rem;color:var(--text-dim);">Reason: ' + esc(e.reason) + '</span>' : ''}</td>
            <td style="font-size:0.7rem; color:var(--text-dim);">${esc(e.source_ip || '—')}</td>
            <td style="font-size:0.65rem; color:var(--text-dim);">${esc(e.session_id || '—')}</td>
        </tr>`;
    }).join('');
}

function getFilteredAudit() {
    const query = (document.getElementById('filter-audit')?.value || '').toLowerCase().trim();
    const fromStr = document.getElementById('filter-audit-from')?.value || '';
    const toStr = document.getElementById('filter-audit-to')?.value || '';

    let from = null, to = null;
    if (fromStr) from = new Date(fromStr + 'T00:00:00');
    if (toStr) to = new Date(toStr + 'T23:59:59');

    return (state.auditEntries || []).filter(e => {
        if (query) {
            const haystack = `${e.action} ${e.username} ${e.detail} ${e.source_ip} ${e.target} ${e.session_id} ${e.reason || ''}`.toLowerCase();
            if (!haystack.includes(query)) return false;
        }
        if (from || to) {
            try {
                const ts = new Date(e.timestamp);
                if (from && ts < from) return false;
                if (to && ts > to) return false;
            } catch (_) {}
        }
        return true;
    });
}

export function initAuditFilter() {
    const input = document.getElementById('filter-audit');
    if (input) {
        input.addEventListener('input', () => {
            clearTimeout(filterTimer);
            filterTimer = setTimeout(renderAuditLog, 200);
        });
    }
    const fromEl = document.getElementById('filter-audit-from');
    const toEl = document.getElementById('filter-audit-to');
    if (fromEl) fromEl.addEventListener('change', renderAuditLog);
    if (toEl) toEl.addEventListener('change', renderAuditLog);
}
