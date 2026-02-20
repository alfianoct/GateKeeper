import { loadMFAStatus, enrollMFA, confirmMFA, disableMFA, changePassword } from './mfa.js';
import { toast } from './toast.js';
import { state } from './state.js';
import { closeModal } from './utils.js';

export async function loadSecurity() {
    const section = document.getElementById('mfa-section-status');
    if (!section) return;

    const status = await loadMFAStatus();
    if (!status) {
        section.innerHTML = '<p style="color:var(--text-dim); font-size:0.85rem;">Unable to load MFA status.</p>';
        return;
    }

    // Show password change card for local users
    const pwCard = document.getElementById('password-change-card');
    if (pwCard) pwCard.style.display = status.is_local ? '' : 'none';

    if (!status.is_local) {
        section.innerHTML = '<p style="color:var(--text-dim); font-size:0.85rem;">MFA is managed by your external identity provider (SSO/LDAP/SAML).</p>';
        return;
    }

    if (status.mfa_enabled) {
        section.innerHTML = `
            <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.75rem;">
                <span style="display:inline-flex; align-items:center; gap:0.3rem; padding:0.2rem 0.6rem; background:rgba(80,250,123,0.1); color:var(--accent-green); font-size:0.7rem; font-weight:600;">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                    Enabled
                </span>
                <span style="font-size:0.65rem; color:var(--text-dim);">${status.recovery_codes_remaining} recovery codes left</span>
            </div>
            <div style="display:flex; gap:0.5rem; align-items:end;">
                <div class="form-group" style="margin:0; width:100px;">
                    <label class="form-label">TOTP code</label>
                    <input class="form-input" type="text" id="mfa-disable-code" placeholder="000000" maxlength="6" inputmode="numeric" style="text-align:center;">
                </div>
                <button class="btn btn-sm btn-danger" id="btn-mfa-disable" style="height:2.2rem;">Disable 2FA</button>
            </div>
            <div class="login-error" id="mfa-disable-error" style="margin-top:0.35rem;"></div>
        `;
        document.getElementById('btn-mfa-disable').addEventListener('click', handleDisable);
    } else {
        const policyNote = status.mfa_required
            ? '<div style="color:var(--accent-amber); font-size:0.65rem; margin-bottom:0.5rem;">Your administrator requires MFA for your account.</div>'
            : '';
        section.innerHTML = `
            <div style="display:flex; align-items:center; gap:0.5rem; margin-bottom:0.5rem;">
                <span style="display:inline-flex; align-items:center; gap:0.3rem; padding:0.2rem 0.6rem; background:rgba(255,85,85,0.1); color:var(--accent-red, #ff5555); font-size:0.7rem; font-weight:600;">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                    Not Enabled
                </span>
            </div>
            <p style="font-size:0.7rem; color:var(--text-dim); margin-bottom:0.5rem;">
                Secure your account with an authenticator app.
            </p>
            ${policyNote}
            <button class="btn btn-sm btn-primary" id="btn-mfa-enroll">Enable 2FA</button>
        `;
        document.getElementById('btn-mfa-enroll').addEventListener('click', handleEnroll);
    }
}

async function handleEnroll() {
    const btn = document.getElementById('btn-mfa-enroll');
    btn.disabled = true;
    btn.textContent = 'Generating...';

    const data = await enrollMFA();
    if (!data) {
        btn.disabled = false;
        btn.textContent = 'Enable 2FA';
        return;
    }
    btn.disabled = false;
    btn.textContent = 'Enable 2FA';

    const body = document.getElementById('mfa-modal-body');
    const codesLeft = data.recovery_codes.slice(0, 5);
    const codesRight = data.recovery_codes.slice(5);

    body.innerHTML = `
        <div style="text-align:center; margin-bottom:1rem;">
            <div style="display:inline-block; background:white; padding:8px;">
                <img id="mfa-qr-img" alt="QR Code" style="width:160px; height:160px; display:block;">
            </div>
            <div style="margin-top:0.5rem;">
                <span style="font-size:0.6rem; color:var(--text-dim);">Or enter manually:</span>
                <code style="display:block; font-size:0.7rem; color:var(--accent-cyan); background:var(--bg-input); padding:0.25rem 0.5rem; margin-top:0.2rem; word-break:break-all;">${data.secret}</code>
            </div>
        </div>
        <div style="margin-bottom:1rem;">
            <div style="font-size:0.65rem; font-weight:600; color:var(--text-muted); text-transform:uppercase; letter-spacing:0.08em; margin-bottom:0.35rem;">Recovery Codes &mdash; save these somewhere safe</div>
            <div style="background:var(--bg-input); padding:0.5rem 0.75rem; font-family:var(--font-mono); font-size:0.7rem; display:flex; gap:2rem; justify-content:center; line-height:1.7;">
                <div>${codesLeft.join('<br>')}</div>
                <div>${codesRight.join('<br>')}</div>
            </div>
        </div>
        <div style="display:flex; gap:0.5rem; align-items:end;">
            <div class="form-group" style="margin:0; flex:1;">
                <label class="form-label">Enter code from your authenticator</label>
                <input class="form-input" type="text" id="mfa-confirm-code" placeholder="000000" maxlength="6" inputmode="numeric" style="text-align:center; font-size:1.1rem; letter-spacing:0.15em;">
            </div>
            <button class="btn btn-primary btn-sm" id="btn-mfa-confirm" style="height:2.4rem;">Verify &amp; Enable</button>
        </div>
        <div class="login-error" id="mfa-confirm-error" style="margin-top:0.35rem;"></div>
    `;

    const qrImg = document.getElementById('mfa-qr-img');
    if (qrImg && data.qr_data_uri) qrImg.src = data.qr_data_uri;

    // Open the modal
    document.getElementById('modal-mfa-enroll')?.classList.add('active');

    document.getElementById('btn-mfa-confirm').addEventListener('click', async () => {
        const code = document.getElementById('mfa-confirm-code').value.trim();
        const errorEl = document.getElementById('mfa-confirm-error');
        errorEl.textContent = '';
        if (!code || code.length !== 6) {
            errorEl.textContent = 'Enter the 6-digit code from your authenticator app';
            return;
        }
        try {
            await confirmMFA(code);
            closeModal('modal-mfa-enroll');
            toast('success', 'MFA Enabled', 'Two-factor authentication is now active on your account.');
            loadSecurity();
        } catch (e) {
            errorEl.textContent = e.message || 'Invalid code — try again';
        }
    });
}

async function handleDisable() {
    const code = document.getElementById('mfa-disable-code').value.trim();
    const errorEl = document.getElementById('mfa-disable-error');
    errorEl.textContent = '';
    if (!code) {
        errorEl.textContent = 'Enter your current TOTP code';
        return;
    }
    try {
        await disableMFA(code);
        toast('success', 'MFA Disabled', 'Two-factor authentication has been removed from your account.');
        loadSecurity();
    } catch (e) {
        errorEl.textContent = e.message || 'Invalid code';
    }
}

export function bindPasswordChange() {
    const btn = document.getElementById('btn-change-password');
    if (!btn) return;
    btn.addEventListener('click', async () => {
        const current = document.getElementById('sec-current-password').value;
        const newPw = document.getElementById('sec-new-password').value;
        const confirm = document.getElementById('sec-confirm-password').value;
        const errorEl = document.getElementById('sec-password-error');
        errorEl.textContent = '';

        if (!current || !newPw) {
            errorEl.textContent = 'All fields are required';
            return;
        }
        if (newPw !== confirm) {
            errorEl.textContent = 'Passwords do not match';
            return;
        }
        try {
            await changePassword(current, newPw);
            toast('success', 'Password Changed', 'Your password has been updated.');
            document.getElementById('sec-current-password').value = '';
            document.getElementById('sec-new-password').value = '';
            document.getElementById('sec-confirm-password').value = '';
        } catch (e) {
            errorEl.textContent = e.message || 'Failed to change password';
        }
    });
}
