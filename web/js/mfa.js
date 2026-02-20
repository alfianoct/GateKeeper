import { API } from './config.js';
import { get, post } from './api.js';
import { toast } from './toast.js';

let pendingMFAToken = null;

export function setPendingMFAToken(token) {
    pendingMFAToken = token;
}

export function showMFAScreen(onSuccess) {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('mfa-screen').style.display = '';
    document.getElementById('mfa-code').value = '';
    document.getElementById('mfa-error').textContent = '';
    document.getElementById('mfa-recovery-form').style.display = 'none';
    document.getElementById('mfa-code').focus();

    const form = document.getElementById('mfa-form');
    form.onsubmit = async (e) => {
        e.preventDefault();
        const code = document.getElementById('mfa-code').value.trim();
        const errorEl = document.getElementById('mfa-error');
        const btn = document.getElementById('mfa-submit-btn');
        errorEl.textContent = '';
        btn.disabled = true;
        btn.textContent = 'Verifying...';
        try {
            const res = await fetch(API.replace('/api', '') + '/auth/mfa/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ mfa_token: pendingMFAToken, code }),
            });
            const data = await res.json();
            if (!res.ok) {
                errorEl.textContent = data.error || 'Invalid code';
                return;
            }
            document.getElementById('mfa-screen').style.display = 'none';
            pendingMFAToken = null;
            await onSuccess();
        } catch (err) {
            errorEl.textContent = 'Network error';
        } finally {
            btn.disabled = false;
            btn.textContent = 'Verify';
        }
    };

    // Recovery toggle
    document.getElementById('mfa-recovery-toggle').onclick = () => {
        document.getElementById('mfa-recovery-form').style.display = '';
        document.getElementById('mfa-recovery-code').focus();
    };

    const recoveryForm = document.getElementById('mfa-recovery-form');
    recoveryForm.onsubmit = async (e) => {
        e.preventDefault();
        const code = document.getElementById('mfa-recovery-code').value.trim();
        const errorEl = document.getElementById('mfa-recovery-error');
        const btn = document.getElementById('mfa-recovery-btn');
        errorEl.textContent = '';
        btn.disabled = true;
        btn.textContent = 'Recovering...';
        try {
            const res = await fetch(API.replace('/api', '') + '/auth/mfa/recover', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ mfa_token: pendingMFAToken, recovery_code: code }),
            });
            const data = await res.json();
            if (!res.ok) {
                errorEl.textContent = data.error || 'Invalid recovery code';
                return;
            }
            document.getElementById('mfa-screen').style.display = 'none';
            pendingMFAToken = null;
            if (data.recovery_codes_remaining !== undefined && data.recovery_codes_remaining < 3) {
                toast('warning', 'Low Recovery Codes', `Only ${data.recovery_codes_remaining} recovery codes remaining. Consider generating new ones.`);
            }
            await onSuccess();
        } catch (err) {
            errorEl.textContent = 'Network error';
        } finally {
            btn.disabled = false;
            btn.textContent = 'Recover';
        }
    };

    document.getElementById('mfa-back-to-login').onclick = (e) => {
        e.preventDefault();
        document.getElementById('mfa-screen').style.display = 'none';
        document.getElementById('login-screen').style.display = '';
        pendingMFAToken = null;
    };
}

export function showPasswordChangeScreen(onSuccess) {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('password-change-screen').style.display = '';
    document.getElementById('pwc-current').value = '';
    document.getElementById('pwc-new').value = '';
    document.getElementById('pwc-confirm').value = '';
    document.getElementById('pwc-error').textContent = '';

    const form = document.getElementById('password-change-form');
    form.onsubmit = async (e) => {
        e.preventDefault();
        const current = document.getElementById('pwc-current').value;
        const newPw = document.getElementById('pwc-new').value;
        const confirm = document.getElementById('pwc-confirm').value;
        const errorEl = document.getElementById('pwc-error');
        const btn = document.getElementById('pwc-btn');

        if (newPw !== confirm) {
            errorEl.textContent = 'Passwords do not match';
            return;
        }

        errorEl.textContent = '';
        btn.disabled = true;
        btn.textContent = 'Changing...';
        try {
            const res = await fetch(API + '/me/password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
                body: JSON.stringify({ current_password: current, new_password: newPw }),
            });
            const data = await res.json();
            if (!res.ok) {
                errorEl.textContent = data.error || 'Failed to change password';
                return;
            }
            document.getElementById('password-change-screen').style.display = 'none';
            toast('success', 'Password Changed', 'Your password has been updated.');
            await onSuccess();
        } catch (err) {
            errorEl.textContent = 'Network error';
        } finally {
            btn.disabled = false;
            btn.textContent = 'Change Password';
        }
    };
}

export async function loadMFAStatus() {
    try {
        return await get('/me/mfa');
    } catch (_) {
        return null;
    }
}

export async function enrollMFA() {
    try {
        const data = await post('/me/mfa/enroll', {});
        return data;
    } catch (e) {
        toast('error', 'MFA Error', e.message || 'Failed to start enrollment');
        return null;
    }
}

export async function confirmMFA(code) {
    try {
        return await post('/me/mfa/confirm', { code });
    } catch (e) {
        throw e;
    }
}

export async function disableMFA(code) {
    try {
        return await post('/me/mfa/disable', { code });
    } catch (e) {
        throw e;
    }
}

export async function changePassword(currentPassword, newPassword) {
    return await post('/me/password', { current_password: currentPassword, new_password: newPassword });
}
