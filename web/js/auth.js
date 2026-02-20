import { get } from './api.js';
import { state } from './state.js';
import { applyRoleNav } from './nav.js';
import { showMFAScreen, setPendingMFAToken, showPasswordChangeScreen } from './mfa.js';

let onLoginSuccess = () => {};
export function setOnLoginSuccess(fn) {
    onLoginSuccess = fn;
}

export function showLogin() {
    state.currentUser = null;
    document.getElementById('login-screen').style.display = '';
    document.getElementById('app-shell').style.display = 'none';
    document.getElementById('login-error').textContent = '';
    document.getElementById('login-username').value = '';
    document.getElementById('login-password').value = '';

    const params = new URLSearchParams(window.location.search);
    const oidcError = params.get('oidc_error');
    const samlError = params.get('saml_error');
    const ssoError = oidcError || samlError;
    const ssoErrEl = document.getElementById('login-oidc-error');
    if (ssoError && ssoErrEl) {
        const messages = {
            exchange_failed: 'SSO authentication failed — please try again',
            assertion_failed: 'SAML assertion validation failed — please try again',
            provisioning_failed: 'Your SSO account is not provisioned — contact your admin',
            session_failed: 'Failed to create session after SSO login',
        };
        ssoErrEl.textContent = messages[ssoError] || 'SSO login error: ' + ssoError;
        ssoErrEl.style.display = '';
        window.history.replaceState({}, '', '/');
    } else if (ssoErrEl) {
        ssoErrEl.style.display = 'none';
    }

    configureLoginUI();
}

export async function configureLoginUI() {
    try {
        const res = await fetch('/auth/providers', { credentials: 'same-origin' });
        if (!res.ok) return;
        const p = await res.json();

        const form = document.getElementById('login-form');
        const divider = document.getElementById('login-divider');
        const oidcBtn = document.getElementById('login-oidc-btn');
        const samlBtn = document.getElementById('login-saml-btn');

        const showLocal = p.local !== false;
        const showOIDC = p.oidc_ready === true;
        const showSAML = p.saml_ready === true;
        const showAnySSO = showOIDC || showSAML;

        form.style.display = showLocal ? '' : 'none';
        oidcBtn.style.display = showOIDC ? '' : 'none';
        if (samlBtn) samlBtn.style.display = showSAML ? '' : 'none';
        divider.style.display = (showLocal && showAnySSO) ? '' : 'none';

        if (oidcBtn && showOIDC) {
            oidcBtn.dataset.ssoUrl = '/auth/oidc';
        }

        document.getElementById('login-username').required = showLocal;
        document.getElementById('login-password').required = showLocal;

        const loginInstanceEl = document.getElementById('login-instance-name');
        if (loginInstanceEl && p.instance_name) {
            loginInstanceEl.textContent = p.instance_name;
            loginInstanceEl.style.display = '';
        } else if (loginInstanceEl) {
            loginInstanceEl.style.display = 'none';
        }
    } catch (_) {}
}

export function showApp() {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('app-shell').style.display = '';
}

export async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    const errorEl = document.getElementById('login-error');
    const btn = document.getElementById('login-btn');

    errorEl.textContent = '';
    btn.disabled = true;
    btn.textContent = 'Signing in...';

    try {
        const res = await fetch('/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ username, password }),
        });
        const data = await res.json();
        if (!res.ok) {
            errorEl.textContent = data.error || 'Login failed';
            return;
        }
        if (data.mfa_required && data.mfa_token) {
            setPendingMFAToken(data.mfa_token);
            showMFAScreen(onLoginSuccess);
            return;
        }
        if (data.mfa_enrollment_required && data.mfa_token) {
            setPendingMFAToken(data.mfa_token);
            errorEl.textContent = 'MFA enrollment is required. Please set up two-factor authentication after login.';
            showMFAScreen(onLoginSuccess);
            return;
        }
        if (data.password_expired) {
            showPasswordChangeScreen(onLoginSuccess);
            return;
        }
        await onLoginSuccess();
    } catch (err) {
        errorEl.textContent = 'Network error — unable to reach server';
    } finally {
        btn.disabled = false;
        btn.textContent = 'Sign In';
    }
}

export async function handleLogout() {
    try {
        await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' });
    } catch (_) {}
    showLogin();
}

export async function loadCurrentUser() {
    try {
        state.currentUser = await get('/me');
        const nameEl = document.getElementById('user-name');
        const roleEl = document.getElementById('user-role');
        if (nameEl) nameEl.textContent = state.currentUser.display_name || state.currentUser.username || 'unknown';
        if (roleEl) roleEl.textContent = state.currentUser.role === 'platform-admin' ? 'Platform Admin' : 'User';
        applyRoleNav();
        updateInstanceBadge(state.currentUser);
    } catch (e) {
        console.warn('Failed to load user info:', e);
        showLogin();
    }
}

function updateInstanceBadge(user) {
    const sep = document.getElementById('instance-badge');
    const badgeText = document.getElementById('instance-badge-text');
    if (!sep || !badgeText) return;

    const name = user.instance_name || 'GateKeeper';
    const id = user.instance_id || '';
    const shortId = id.length > 12 ? id.slice(-8) : id;

    badgeText.textContent = name + (shortId ? ' \u00b7 ' + shortId : '');
    sep.style.display = '';
    badgeText.style.display = '';
}
