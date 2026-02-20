import { get, put, post, del } from './api.js';
import { API } from './config.js';
import { toast } from './toast.js';
import { esc, setSubmitButtonLoading } from './utils.js';
import { loadGroupMappings } from './groups.js';
import { state } from './state.js';

// ─── Settings tab switching ─────────────────────────────
export function initSettingsTabs() {
    const tabBar = document.getElementById('settings-tabs');
    if (!tabBar) return;
    tabBar.querySelectorAll('.view-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const key = tab.getAttribute('data-settings-tab');
            switchSettingsTab(key);
        });
    });
    const saved = sessionStorage.getItem('gk-settings-tab');
    if (saved) switchSettingsTab(saved);
}

export function switchSettingsTab(key) {
    document.querySelectorAll('#settings-tabs .view-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('[data-settings-pane]').forEach(p => p.classList.remove('active'));
    const tab = document.querySelector(`[data-settings-tab="${key}"]`);
    const pane = document.querySelector(`[data-settings-pane="${key}"]`);
    if (tab) tab.classList.add('active');
    if (pane) pane.classList.add('active');
    sessionStorage.setItem('gk-settings-tab', key);
}

export async function loadSettings() {
    try {
        const s = await get('/settings');
        if (!s) return;
        document.getElementById('set-instance-name').value = s.instance_name || '';
        document.getElementById('set-auth-mode').value = s.auth_mode || 'local';
        document.getElementById('set-session-ttl').value = s.session_ttl || '24h';
        document.getElementById('set-session-recording').value = s.session_recording ? 'true' : 'false';
        document.getElementById('set-oidc-issuer').value = s.oidc_issuer || '';
        document.getElementById('set-oidc-client-id').value = s.oidc_client_id || '';
        document.getElementById('set-oidc-client-secret').value = s.oidc_client_secret || '';
        document.getElementById('set-oidc-redirect-url').value = s.oidc_redirect_url || '';
        document.getElementById('set-oidc-auto-provision').value = s.oidc_auto_provision ? 'true' : 'false';
        document.getElementById('set-oidc-default-role').value = s.oidc_default_role || 'user';
        document.getElementById('set-ldap-url').value = s.ldap_url || '';
        document.getElementById('set-ldap-bind-dn').value = s.ldap_bind_dn || '';
        document.getElementById('set-ldap-bind-password').value = s.ldap_bind_password || '';
        document.getElementById('set-ldap-user-base').value = s.ldap_user_base || '';
        document.getElementById('set-ldap-user-filter').value = s.ldap_user_filter || '(uid=%s)';
        document.getElementById('set-ldap-username-attr').value = s.ldap_username_attr || 'uid';
        document.getElementById('set-ldap-display-name-attr').value = s.ldap_display_name_attr || 'displayName';
        document.getElementById('set-ldap-group-attr').value = s.ldap_group_attr || 'memberOf';
        document.getElementById('set-ldap-auto-provision').value = s.ldap_auto_provision ? 'true' : 'false';
        document.getElementById('set-ldap-default-role').value = s.ldap_default_role || 'user';
        document.getElementById('set-saml-idp-metadata-url').value = s.saml_idp_metadata_url || '';
        document.getElementById('set-saml-entity-id').value = s.saml_entity_id || '';
        document.getElementById('set-saml-acs-url').value = s.saml_acs_url || '';
        document.getElementById('set-saml-username-attr').value = s.saml_username_attr || '';
        document.getElementById('set-saml-display-name-attr').value = s.saml_display_name_attr || '';
        document.getElementById('set-saml-groups-attr').value = s.saml_groups_attr || '';
        document.getElementById('set-saml-auto-provision').value = s.saml_auto_provision ? 'true' : 'false';
        document.getElementById('set-saml-default-role').value = s.saml_default_role || 'user';
        const modeLabels = { 'local': 'Local', 'oidc': 'OIDC', 'local+oidc': 'Local + OIDC', 'ldap': 'LDAP', 'local+ldap': 'Local + LDAP', 'saml': 'SAML', 'local+saml': 'Local + SAML' };
        document.getElementById('stat-auth-mode').textContent = modeLabels[s.auth_mode] || s.auth_mode;
        document.getElementById('stat-session-ttl').textContent = s.session_ttl || '24h';

        const u = state.currentUser || {};
        const instanceIdEl = document.getElementById('set-instance-id');
        if (instanceIdEl) instanceIdEl.value = u.instance_id || '—';
        const deployModeEl = document.getElementById('set-deployment-mode');
        if (deployModeEl) deployModeEl.value = (u.deployment_mode === 'ha' ? 'HA (High Availability)' : 'Single Instance');

        // MFA Policy
        document.getElementById('set-mfa-policy').value = s.mfa_policy || 'optional';
        // Password Policy
        document.getElementById('set-password-min-length').value = s.password_min_length || 12;
        document.getElementById('set-password-require-uppercase').value = s.password_require_uppercase !== false ? 'true' : 'false';
        document.getElementById('set-password-require-number').value = s.password_require_number !== false ? 'true' : 'false';
        document.getElementById('set-password-require-special').value = s.password_require_special !== false ? 'true' : 'false';
        document.getElementById('set-password-max-age-days').value = s.password_max_age_days || 0;
        document.getElementById('set-password-history-count').value = s.password_history_count || 0;
        // Session limits
        document.getElementById('set-max-sessions-per-user').value = s.max_sessions_per_user || 0;
        // Audit export
        document.getElementById('set-audit-webhook-url').value = s.audit_webhook_url || '';
        document.getElementById('set-audit-webhook-secret').value = s.audit_webhook_secret || '';
        document.getElementById('set-audit-syslog-addr').value = s.audit_syslog_addr || '';
        document.getElementById('set-audit-syslog-facility').value = s.audit_syslog_facility || 1;

        onAuthModeChange();
        loadIPRules();
    } catch (e) {
        console.error('Failed to load settings:', e);
    }
}

export async function saveSettings() {
    const payload = {
        instance_name: document.getElementById('set-instance-name').value.trim(),
        auth_mode: document.getElementById('set-auth-mode').value,
        session_ttl: document.getElementById('set-session-ttl').value.trim(),
        session_recording: document.getElementById('set-session-recording').value === 'true',
        oidc_issuer: document.getElementById('set-oidc-issuer').value.trim(),
        oidc_client_id: document.getElementById('set-oidc-client-id').value.trim(),
        oidc_client_secret: document.getElementById('set-oidc-client-secret').value,
        oidc_redirect_url: document.getElementById('set-oidc-redirect-url').value.trim(),
        oidc_auto_provision: document.getElementById('set-oidc-auto-provision').value === 'true',
        oidc_default_role: document.getElementById('set-oidc-default-role').value,
        ldap_url: document.getElementById('set-ldap-url').value.trim(),
        ldap_bind_dn: document.getElementById('set-ldap-bind-dn').value.trim(),
        ldap_bind_password: document.getElementById('set-ldap-bind-password').value,
        ldap_user_base: document.getElementById('set-ldap-user-base').value.trim(),
        ldap_user_filter: document.getElementById('set-ldap-user-filter').value.trim() || '(uid=%s)',
        ldap_username_attr: document.getElementById('set-ldap-username-attr').value.trim() || 'uid',
        ldap_display_name_attr: document.getElementById('set-ldap-display-name-attr').value.trim() || 'displayName',
        ldap_group_attr: document.getElementById('set-ldap-group-attr').value.trim() || 'memberOf',
        ldap_auto_provision: document.getElementById('set-ldap-auto-provision').value === 'true',
        ldap_default_role: document.getElementById('set-ldap-default-role').value,
        saml_idp_metadata_url: document.getElementById('set-saml-idp-metadata-url').value.trim(),
        saml_entity_id: document.getElementById('set-saml-entity-id').value.trim(),
        saml_acs_url: document.getElementById('set-saml-acs-url').value.trim(),
        saml_username_attr: document.getElementById('set-saml-username-attr').value.trim(),
        saml_display_name_attr: document.getElementById('set-saml-display-name-attr').value.trim(),
        saml_groups_attr: document.getElementById('set-saml-groups-attr').value.trim(),
        saml_auto_provision: document.getElementById('set-saml-auto-provision').value === 'true',
        saml_default_role: document.getElementById('set-saml-default-role').value,
        mfa_policy: document.getElementById('set-mfa-policy').value,
        password_min_length: parseInt(document.getElementById('set-password-min-length').value, 10) || 12,
        password_require_uppercase: document.getElementById('set-password-require-uppercase').value === 'true',
        password_require_number: document.getElementById('set-password-require-number').value === 'true',
        password_require_special: document.getElementById('set-password-require-special').value === 'true',
        password_max_age_days: parseInt(document.getElementById('set-password-max-age-days').value, 10) || 0,
        password_history_count: parseInt(document.getElementById('set-password-history-count').value, 10) || 0,
        max_sessions_per_user: parseInt(document.getElementById('set-max-sessions-per-user').value, 10) || 0,
        audit_webhook_url: document.getElementById('set-audit-webhook-url').value.trim(),
        audit_webhook_secret: document.getElementById('set-audit-webhook-secret').value,
        audit_syslog_addr: document.getElementById('set-audit-syslog-addr').value.trim(),
        audit_syslog_facility: parseInt(document.getElementById('set-audit-syslog-facility').value, 10) || 1,
    };
    const btn = document.getElementById('btn-save-settings');
    setSubmitButtonLoading(btn, true, 'Saving...');
    try {
        await put('/settings', payload);
        toast('success', 'Settings saved', 'Platform settings updated successfully');
        loadSettings();
    } catch (_) {}
    finally {
        setSubmitButtonLoading(btn, false);
    }
}

export async function testAuditWebhook() {
    const resultEl = document.getElementById('webhook-test-result');
    const btn = document.getElementById('btn-test-webhook');
    resultEl.textContent = 'Sending...';
    resultEl.style.color = 'var(--text-dim)';
    btn.disabled = true;
    try {
        await post('/audit/test-webhook', {});
        resultEl.textContent = 'Success — test event sent';
        resultEl.style.color = 'var(--accent-green)';
    } catch (e) {
        resultEl.textContent = e.message || 'Failed';
        resultEl.style.color = 'var(--accent-red, #ff5555)';
    } finally {
        btn.disabled = false;
    }
}

export function exportAudit(format) {
    const url = API + '/audit/export?format=' + format + '&limit=50000';
    window.open(url, '_blank');
}

// ─── IP Rules management ────────────────────────────────
let ipRulesCache = [];

export function initIPRulesFilter() {
    const input = document.getElementById('filter-ip-rules');
    if (input) {
        let timer;
        input.addEventListener('input', () => {
            clearTimeout(timer);
            timer = setTimeout(renderIPRules, 200);
        });
    }
}

export async function loadIPRules() {
    const container = document.getElementById('ip-rules-list');
    if (!container) return;
    try {
        const result = await get('/ip-rules');
        ipRulesCache = Array.isArray(result) ? result : [];
        renderIPRules();
    } catch (e) {
        ipRulesCache = [];
        container.innerHTML = '<p style="font-size:0.75rem; color:var(--text-dim);">No IP rules configured — all IPs are permitted.</p>';
    }
}

function renderIPRules() {
    const container = document.getElementById('ip-rules-list');
    if (!container) return;

    const query = (document.getElementById('filter-ip-rules')?.value || '').toLowerCase().trim();
    const filtered = query
        ? ipRulesCache.filter(r => `${r.cidr} ${r.description} ${r.rule_type} ${r.scope} ${r.created_by}`.toLowerCase().includes(query))
        : ipRulesCache;

    const countEl = document.getElementById('filter-ip-rules-count');
    if (countEl) {
        const total = ipRulesCache.length;
        countEl.textContent = total === 0 ? '' : (filtered.length === total ? `${total} rules` : `${filtered.length} / ${total} rules`);
    }

    if (ipRulesCache.length === 0) {
        container.innerHTML = '<p style="font-size:0.75rem; color:var(--text-dim);">No IP rules configured — all IPs are permitted.</p>';
        return;
    }
    if (filtered.length === 0) {
        container.innerHTML = '<p style="font-size:0.75rem; color:var(--text-dim);">No matching rules.</p>';
        return;
    }
    container.innerHTML = `<table class="sessions-table" style="margin-bottom:0;">
        <thead><tr><th>Type</th><th>CIDR</th><th>Scope</th><th>Description</th><th>Created By</th><th></th></tr></thead>
        <tbody>${filtered.map(r => `<tr>
            <td><span class="badge ${r.rule_type === 'deny' ? 'badge-danger' : 'badge-success'}">${esc(r.rule_type)}</span></td>
            <td><code>${esc(r.cidr)}</code></td>
            <td>${esc(r.scope)}${r.scope_id ? ' <code>' + esc(r.scope_id) + '</code>' : ''}</td>
            <td>${esc(r.description) || '—'}</td>
            <td>${esc(r.created_by) || '—'}</td>
            <td><button class="btn btn-sm btn-danger" data-action="delete-ip-rule" data-id="${esc(r.id)}">Remove</button></td>
        </tr>`).join('')}</tbody></table>`;
}

export async function addIPRule() {
    const ruleType = document.getElementById('ip-rule-type').value;
    const cidr = document.getElementById('ip-rule-cidr').value.trim();
    const scope = document.getElementById('ip-rule-scope').value;
    const scopeId = document.getElementById('ip-rule-scope-id').value.trim();
    const description = document.getElementById('ip-rule-description').value.trim();
    if (!cidr) { toast('error', 'Missing CIDR', 'Enter a CIDR or IP address'); return; }
    if (scope === 'host' && !scopeId) { toast('error', 'Missing Host ID', 'Enter a host ID for per-host rules'); return; }
    try {
        await post('/ip-rules', { rule_type: ruleType, cidr, scope, scope_id: scopeId, description });
        toast('success', 'IP rule created', `${ruleType} rule for ${cidr}`);
        document.getElementById('ip-rule-cidr').value = '';
        document.getElementById('ip-rule-scope-id').value = '';
        document.getElementById('ip-rule-description').value = '';
        loadIPRules();
    } catch (e) {
        toast('error', 'Failed', e.message || 'Could not create IP rule');
    }
}

export async function deleteIPRule(ruleId) {
    if (!confirm('Remove this IP rule?')) return;
    try {
        await del('/ip-rules/' + ruleId);
        toast('success', 'IP rule removed', '');
        loadIPRules();
    } catch (_) {}
}

export function onAuthModeChange() {
    const mode = document.getElementById('set-auth-mode').value;
    const oidcCard = document.getElementById('oidc-settings-card');
    const ldapCard = document.getElementById('ldap-settings-card');
    const samlCard = document.getElementById('saml-settings-card');
    const mappingCard = document.getElementById('oidc-mapping-card');
    const showOIDC = (mode === 'oidc' || mode === 'local+oidc');
    const showLDAP = (mode === 'ldap' || mode === 'local+ldap');
    const showSAML = (mode === 'saml' || mode === 'local+saml');
    const showMapping = showOIDC || showLDAP || showSAML;
    if (oidcCard) oidcCard.style.display = showOIDC ? '' : 'none';
    if (ldapCard) ldapCard.style.display = showLDAP ? '' : 'none';
    if (samlCard) samlCard.style.display = showSAML ? '' : 'none';
    if (mappingCard) {
        mappingCard.style.display = showMapping ? '' : 'none';
        if (showMapping) loadGroupMappings();
    }
}
