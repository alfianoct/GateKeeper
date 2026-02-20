/**
 * Setup wizard — database and admin account configuration.
 * Event handlers are attached in DOMContentLoaded; no inline handlers (CSP-friendly).
 */
(function () {
    let currentStep = 1;
    let selectedDB = 'sqlite';
    let defaultDBPath = './gatekeeper.db';

    function validatePassword(pw) {
        if (pw.length < 12) return 'Password must be at least 12 characters';
        if (!/[A-Z]/.test(pw)) return 'Password must contain an uppercase letter';
        if (!/[a-z]/.test(pw)) return 'Password must contain a lowercase letter';
        if (!/[0-9]/.test(pw)) return 'Password must contain a digit';
        if (!/[^A-Za-z0-9]/.test(pw)) return 'Password must contain a special character';
        return null;
    }

    function selectDB(driver) {
        selectedDB = driver;
        document.getElementById('opt-sqlite').classList.toggle('selected', driver === 'sqlite');
        document.getElementById('opt-postgres').classList.toggle('selected', driver === 'postgres');
        document.getElementById('sqlite-fields').style.display = driver === 'sqlite' ? 'block' : 'none';
        document.getElementById('pg-fields').style.display = driver === 'postgres' ? 'block' : 'none';
        document.querySelector('input[name="db_driver"][value="' + driver + '"]').checked = true;
    }

    function goStep(n) {
        if (n > currentStep) {
            if (currentStep === 2) {
                const pw = document.getElementById('admin-password').value;
                const pw2 = document.getElementById('admin-password-confirm').value;
                const user = document.getElementById('admin-username').value.trim();
                const msg = document.getElementById('admin-msg');
                if (!user) { showMsg(msg, 'Username is required', 'error'); return; }
                const pwErr = validatePassword(pw);
                if (pwErr) { showMsg(msg, pwErr, 'error'); return; }
                if (pw !== pw2) { showMsg(msg, 'Passwords do not match', 'error'); return; }
                msg.className = 'msg'; msg.style.display = 'none';
            }
        }
        if (n === 3) buildSummary();

        currentStep = n;
        document.querySelectorAll('.step').forEach(s => s.classList.remove('active'));
        document.getElementById('step-' + n).classList.add('active');
        for (let i = 1; i <= 3; i++) {
            const dot = document.getElementById('dot-' + i);
            dot.classList.remove('active', 'done');
            if (i < n) dot.classList.add('done');
            if (i === n) dot.classList.add('active');
        }
    }

    function buildSummary() {
        const driver = selectedDB;
        let dbInfo = '';
        if (driver === 'sqlite') {
            dbInfo = document.getElementById('db-path').value || './gatekeeper.db';
        } else {
            const h = document.getElementById('pg-host').value || 'localhost';
            const p = document.getElementById('pg-port').value || '5432';
            const d = document.getElementById('pg-database').value || 'gatekeeper';
            dbInfo = h + ':' + p + '/' + d;
        }
        const user = document.getElementById('admin-username').value || 'admin';
        document.getElementById('summary').innerHTML =
            '<div class="summary-row"><span class="summary-label">Database</span><span class="summary-value">' + driver.toUpperCase() + '</span></div>' +
            '<div class="summary-row"><span class="summary-label">Connection</span><span class="summary-value">' + escapeHtml(dbInfo) + '</span></div>' +
            '<div class="summary-row"><span class="summary-label">Admin User</span><span class="summary-value">' + escapeHtml(user) + '</span></div>' +
            '<div class="summary-row"><span class="summary-label">TLS</span><span class="summary-value">Self-signed (auto)</span></div>';
    }

    function escapeHtml(s) {
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    function showMsg(el, text, type) {
        el.textContent = text;
        el.className = 'msg ' + type;
        el.style.display = 'block';
    }

    async function testDB() {
        const btn = document.getElementById('btn-test-db');
        const msg = document.getElementById('db-msg');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Testing...';
        msg.className = 'msg'; msg.style.display = 'none';

        const body = { db_driver: selectedDB };
        if (selectedDB === 'sqlite') {
            body.db_path = document.getElementById('db-path').value || defaultDBPath;
        } else {
            body.db_dsn = buildPGDSN();
        }

        try {
            const res = await fetch('/api/setup/test-db', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            const data = await res.json();
            if (res.ok) {
                showMsg(msg, '✓ ' + data.message, 'success');
            } else {
                showMsg(msg, data.error || 'Connection failed', 'error');
            }
        } catch (e) {
            showMsg(msg, 'Network error: ' + e.message, 'error');
        }

        btn.disabled = false;
        btn.textContent = 'Test Connection';
    }

    function buildPGDSN() {
        const h = document.getElementById('pg-host').value || 'localhost';
        const p = document.getElementById('pg-port').value || '5432';
        const d = document.getElementById('pg-database').value || 'gatekeeper';
        const u = document.getElementById('pg-user').value || '';
        const pw = document.getElementById('pg-password').value || '';
        const ssl = document.getElementById('pg-sslmode').value || 'disable';
        let dsn = 'postgres://';
        if (u) {
            dsn += encodeURIComponent(u);
            if (pw) dsn += ':' + encodeURIComponent(pw);
            dsn += '@';
        }
        dsn += h + ':' + p + '/' + d + '?sslmode=' + ssl;
        return dsn;
    }

    async function completeSetup() {
        const btn = document.getElementById('btn-complete');
        const msg = document.getElementById('setup-msg');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Setting up...';
        msg.className = 'msg'; msg.style.display = 'none';

        const body = {
            db_driver: selectedDB,
            db_path: selectedDB === 'sqlite' ? (document.getElementById('db-path').value || defaultDBPath) : '',
            db_dsn: selectedDB === 'postgres' ? buildPGDSN() : '',
            admin_username: document.getElementById('admin-username').value.trim(),
            admin_display_name: document.getElementById('admin-display-name').value.trim(),
            admin_password: document.getElementById('admin-password').value,
        };

        try {
            const res = await fetch('/api/setup/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            const data = await res.json();
            if (res.ok) {
                showMsg(msg, '\u2713 ' + data.message + ' — Redirecting...', 'success');
                btn.textContent = 'Redirecting...';
                retryRedirect();
            } else {
                showMsg(msg, data.error || 'Setup failed', 'error');
                btn.disabled = false;
                btn.textContent = 'Complete Setup';
            }
        } catch (e) {
            showMsg(msg, 'Network error: ' + e.message, 'error');
            btn.disabled = false;
            btn.textContent = 'Complete Setup';
        }
    }

    function retryRedirect(attempt) {
        attempt = attempt || 0;
        var delay = Math.min(1000 * Math.pow(1.5, attempt), 5000);
        setTimeout(function () {
            fetch('/', { credentials: 'same-origin' })
                .then(function (r) {
                    if (r.ok) window.location.href = '/';
                    else if (attempt < 15) retryRedirect(attempt + 1);
                })
                .catch(function () {
                    if (attempt < 15) retryRedirect(attempt + 1);
                });
        }, delay);
    }

    function init() {
        // Fetch defaults from server
        (async function () {
            try {
                const res = await fetch('/api/setup/defaults');
                if (res.ok) {
                    const data = await res.json();
                    if (data.db_path) defaultDBPath = data.db_path;
                }
            } catch (e) {}
            const el = document.getElementById('db-path');
            if (el && !el.value) { el.value = defaultDBPath; el.placeholder = ''; }
        })();

        // Bind events (no inline handlers — CSP script-src without 'unsafe-inline')
        document.getElementById('opt-sqlite')?.addEventListener('click', function () { selectDB('sqlite'); });
        document.getElementById('opt-postgres')?.addEventListener('click', function () { selectDB('postgres'); });
        document.getElementById('btn-test-db')?.addEventListener('click', testDB);
        document.getElementById('btn-complete')?.addEventListener('click', completeSetup);

        var step1Next = document.querySelector('#step-1 .btn-primary');
        var step2Back = document.querySelector('#step-2 .btn:first-of-type');
        var step2Next = document.querySelector('#step-2 .btn-primary');
        var step3Back = document.querySelector('#step-3 .btn:first-of-type');
        if (step1Next) step1Next.addEventListener('click', function () { goStep(2); });
        if (step2Back) step2Back.addEventListener('click', function () { goStep(1); });
        if (step2Next) step2Next.addEventListener('click', function () { goStep(3); });
        if (step3Back) step3Back.addEventListener('click', function () { goStep(2); });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
