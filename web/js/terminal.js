import { state } from './state.js';
import { esc } from './utils.js';
import { navigateTo } from './nav.js';
import { toast } from './toast.js';

export function openSSHTerminal(hostId, sshUser, password, keyId, reason) {
    const host = state.hosts.find(h => h.id === hostId);
    if (!host) return;

    navigateTo('terminal');

    const tabId = 'tab-' + (++state.tabCounter);
    const user = sshUser || state.currentUser?.username || 'user';

    const term = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: "'JetBrains Mono', monospace",
        theme: {
            background: '#0d0d14',
            foreground: '#e0e0e0',
            cursor: '#00ff9f',
            cursorAccent: '#0d0d14',
            selectionBackground: 'rgba(0, 255, 159, 0.25)',
            black: '#0a0a0f',
            red: '#ff5555',
            green: '#00ff9f',
            yellow: '#f1fa8c',
            blue: '#00d4ff',
            magenta: '#ff79c6',
            cyan: '#00d4ff',
            white: '#e0e0e0',
            brightBlack: '#555555',
            brightRed: '#ff6e6e',
            brightGreen: '#00ff9f',
            brightYellow: '#f1fa8c',
            brightBlue: '#00d4ff',
            brightMagenta: '#ff92df',
            brightCyan: '#00d4ff',
            brightWhite: '#ffffff',
        },
        allowProposedApi: true,
    });

    const fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);

    try {
        const webLinksAddon = new WebLinksAddon.WebLinksAddon();
        term.loadAddon(webLinksAddon);
    } catch (_) {}

    const container = document.createElement('div');
    container.id = tabId + '-container';
    container.className = 'xterm-container';
    container.style.width = '100%';
    container.style.height = '100%';
    container.style.display = 'none';

    const body = document.getElementById('terminal-body');
    if (!body) return;

    if (state.terminals.size === 0) {
        body.innerHTML = '';
    }
    body.appendChild(container);

    term.open(container);

    const tabs = document.getElementById('terminal-tabs');
    if (tabs) {
        if (state.terminals.size === 0) {
            tabs.innerHTML = '';
        }

        const tabEl = document.createElement('div');
        tabEl.className = 'terminal-tab';
        tabEl.id = tabId;
        tabEl.innerHTML = `
            <div class="terminal-tab-dot"></div>
            <span>${esc(user)}@${esc(host.name)}</span>
            <div class="tab-close" data-action="close-terminal-tab" data-id="${tabId}">✕</div>`;
        tabEl.addEventListener('click', () => switchTab(tabId));
        tabs.appendChild(tabEl);
    }

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    let wsUrl = `${proto}//${location.host}/ws/ssh/${host.id}?user=${encodeURIComponent(user)}`;
    if (reason && typeof reason === 'string' && reason.trim()) {
        wsUrl += '&reason=' + encodeURIComponent(reason.trim());
    }
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'auth', data: {} }));
        fitAddon.fit();
        const dims = fitAddon.proposeDimensions();
        if (dims) {
            ws.send(JSON.stringify({ type: 'resize', data: { cols: dims.cols, rows: dims.rows } }));
        }
    };

    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'output' && msg.data) {
                term.write(msg.data);
            }
        } catch (_) {
            term.write(event.data);
        }
    };

    ws.onclose = (ev) => {
        term.write('\r\n\x1b[90m[connection closed]\x1b[0m\r\n');
        const dot = document.querySelector(`#${tabId} .terminal-tab-dot`);
        if (dot) dot.style.background = 'var(--accent-red, #ff5555)';
        // If the connection never opened (e.g. 423 Host in use, 409 already connected), show a toast
        if (ev.code !== 1000 && ev.reason) {
            toast('error', 'Connection failed', ev.reason);
        } else if (ev.code === 1006 || ev.code === 1011) {
            toast('error', 'Connection failed', 'Host may be in use by another user, or the connection was rejected.');
        }
    };

    ws.onerror = () => {
        term.write('\r\n\x1b[31m[WebSocket error]\x1b[0m\r\n');
    };

    term.onData((data) => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'input', data: { data } }));
        }
    });

    term.onResize(({ cols, rows }) => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'resize', data: { cols, rows } }));
        }
    });

    const resizeHandler = () => {
        if (state.activeTabId === tabId) {
            fitAddon.fit();
        }
    };
    window.addEventListener('resize', resizeHandler);

    state.terminals.set(tabId, { term, fitAddon, ws, hostId: host.id, hostName: host.name, container, resizeHandler });

    switchTab(tabId);
}

export function switchTab(tabId) {
    if (state.activeTabId) {
        const prev = state.terminals.get(state.activeTabId);
        if (prev) prev.container.style.display = 'none';
        const prevTab = document.getElementById(state.activeTabId);
        if (prevTab) prevTab.classList.remove('active');
    }

    state.activeTabId = tabId;
    const entry = state.terminals.get(tabId);
    if (entry) {
        entry.container.style.display = 'block';
        const tabEl = document.getElementById(tabId);
        if (tabEl) tabEl.classList.add('active');
        requestAnimationFrame(() => {
            entry.fitAddon.fit();
            entry.term.focus();
        });
    }
}

export function closeTerminalTab(tabId) {
    const entry = state.terminals.get(tabId);
    if (!entry) return;

    if (entry.ws && entry.ws.readyState !== WebSocket.CLOSED) {
        entry.ws.close();
    }

    entry.term.dispose();
    entry.container.remove();
    window.removeEventListener('resize', entry.resizeHandler);

    const tabEl = document.getElementById(tabId);
    if (tabEl) tabEl.remove();

    state.terminals.delete(tabId);

    if (state.activeTabId === tabId) {
        state.activeTabId = null;
        if (state.terminals.size > 0) {
            const nextId = state.terminals.keys().next().value;
            switchTab(nextId);
        } else {
            const body = document.getElementById('terminal-body');
            if (body) {
                body.innerHTML = `<div class="empty-state">
                    <div class="empty-state-icon"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg></div>
                    <div>Select a host from the Hosts view to open a session</div>
                </div>`;
            }
            const tabs = document.getElementById('terminal-tabs');
            if (tabs) {
                tabs.innerHTML = `<div class="empty-state" style="padding: 0.5rem 1rem; font-size: 0.7rem;">
                    No active sessions — connect to a host to begin
                </div>`;
            }
        }
    }
}
