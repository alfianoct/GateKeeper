import { API } from './config.js';
import { get, post, del } from './api.js';
import { state } from './state.js';
import { toast } from './toast.js';
import { esc, formatTime, formatBytes, calcDuration, formatTimestamp } from './utils.js';

// ─── Sessions tab switching ─────────────────────────────
export function initSessionsTabs() {
    const tabBar = document.getElementById('sessions-tabs');
    if (!tabBar) return;
    tabBar.querySelectorAll('.view-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const key = tab.getAttribute('data-sessions-tab');
            switchSessionsTab(key);
        });
    });
}

export function initSessionsFilter() {
    const input = document.getElementById('filter-sessions-history');
    if (input) {
        let timer;
        input.addEventListener('input', () => {
            clearTimeout(timer);
            timer = setTimeout(renderSessions, 200);
        });
    }
}

export function switchSessionsTab(key) {
    document.querySelectorAll('#sessions-tabs .view-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('[data-sessions-pane]').forEach(p => p.classList.remove('active'));
    const tab = document.querySelector(`[data-sessions-tab="${key}"]`);
    const pane = document.querySelector(`[data-sessions-pane="${key}"]`);
    if (tab) tab.classList.add('active');
    if (pane) pane.classList.add('active');
}

export async function loadSessions() {
    try {
        const [active, history] = await Promise.all([
            get('/sessions'),
            get('/sessions/history'),
        ]);
        state.activeSessions = active || [];
        state.historySessions = history || [];
        renderSessions();
        const canApprove = state.currentUser && (state.currentUser.role === 'platform-admin' || (state.currentUser.permissions && state.currentUser.permissions.includes('manage_sessions')));
        const requestsTab = document.getElementById('sessions-tab-requests');
        if (canApprove) {
            if (requestsTab) requestsTab.style.display = '';
            loadAccessRequests();
        } else {
            if (requestsTab) requestsTab.style.display = 'none';
        }
    } catch (e) {
        console.error('Failed to load sessions:', e);
    }
}

export async function loadAccessRequests() {
    const tbody = document.getElementById('access-requests-body');
    if (!tbody) return;
    try {
        const list = await get('/access-requests') || [];
        state.accessRequests = list;
        const badge = document.getElementById('sessions-tab-requests-count');
        if (badge) {
            badge.textContent = list.length;
            badge.classList.toggle('tab-badge-dim', list.length === 0);
        }
        if (list.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state" style="padding: 2rem;">No pending requests</td></tr>';
        } else {
            tbody.innerHTML = list.map(r => `
                <tr>
                    <td>${esc(r.username)}</td>
                    <td>${esc(r.host_id)}</td>
                    <td>${esc(r.reason || '—')}</td>
                    <td style="font-size: 0.75rem;">${formatTimestamp(r.created_at)}</td>
                    <td>
                        <button class="btn btn-sm btn-primary" data-action="approve-request" data-id="${esc(r.id)}">Approve</button>
                        <button class="btn btn-sm" data-action="reject-request" data-id="${esc(r.id)}" style="margin-left:0.25rem;">Reject</button>
                    </td>
                </tr>`).join('');
        }
    } catch (e) {
        const requestsTab = document.getElementById('sessions-tab-requests');
        if (requestsTab) requestsTab.style.display = 'none';
    }
}

export function renderSessions() {
    const canKill = state.currentUser && (state.currentUser.role === 'platform-admin' || (state.currentUser.permissions && state.currentUser.permissions.includes('manage_sessions')));
    const activeBody = document.getElementById('active-sessions-body');
    if (activeBody) {
        if (state.activeSessions.length === 0) {
            activeBody.innerHTML = '<tr><td colspan="8"><div class="empty-state-box"><svg viewBox="0 0 24 24"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg><div class="empty-msg">No active sessions</div><div class="empty-hint">Sessions appear here when users connect to hosts</div></div></td></tr>';
        } else {
            activeBody.innerHTML = state.activeSessions.map(s => `
                <tr>
                    <td><span class="session-user">${esc(s.username)}</span></td>
                    <td><span class="session-target">${esc(s.host_name)}</span><br>
                        <span style="font-size: 0.65rem; color: var(--text-dim);">${esc(s.host_addr)}</span></td>
                    <td style="font-size: 0.75rem; color: var(--text-dim);">${esc(s.reason || '—')}</td>
                    <td><span class="badge badge-ssh">${esc(s.protocol)}</span></td>
                    <td style="font-variant-numeric: tabular-nums;">${formatTime(s.connected_at)}</td>
                    <td class="session-duration-live" data-start="${esc(s.connected_at)}">${calcDuration(s.connected_at)}</td>
                    <td style="font-size: 0.75rem;">${formatBytes(s.bytes_tx)} / ${formatBytes(s.bytes_rx)}</td>
                    <td>
                        <button class="btn btn-sm btn-watch" data-action="watch-session" data-id="${esc(s.id)}" data-host-name="${esc(s.host_name)}" data-username="${esc(s.username)}">Watch</button>
                        ${canKill ? `<button class="btn btn-sm btn-danger" data-action="kill-session" data-id="${esc(s.id)}" style="margin-left:0.25rem;">Kill</button>` : ''}
                    </td>
                </tr>`).join('');
        }
    }

    const historyBody = document.getElementById('history-sessions-body');
    if (historyBody) {
        const query = (document.getElementById('filter-sessions-history')?.value || '').toLowerCase().trim();
        const filtered = query
            ? state.historySessions.filter(s => `${s.username} ${s.host_name}`.toLowerCase().includes(query))
            : state.historySessions;

        const countEl = document.getElementById('filter-sessions-history-count');
        if (countEl) {
            const total = state.historySessions.length;
            countEl.textContent = filtered.length === total ? `${total} entries` : `${filtered.length} / ${total} entries`;
        }

        if (filtered.length === 0) {
            historyBody.innerHTML = '<tr><td colspan="7"><div class="empty-state-box"><svg viewBox="0 0 24 24"><path d="M12 8v4l3 3"/><circle cx="12" cy="12" r="10"/></svg><div class="empty-msg">No matching sessions</div><div class="empty-hint">Adjust your search or check back later</div></div></td></tr>';
        } else {
            historyBody.innerHTML = filtered.map(s => `
                <tr>
                    <td><span class="session-user">${esc(s.username)}</span></td>
                    <td><span class="session-target">${esc(s.host_name)}</span></td>
                    <td style="font-size: 0.75rem; color: var(--text-dim);">${esc(s.reason || '—')}</td>
                    <td><span class="badge badge-ssh">${esc(s.protocol)}</span></td>
                    <td style="font-variant-numeric: tabular-nums;">${formatTime(s.connected_at)}</td>
                    <td class="session-duration">${calcDuration(s.connected_at, s.closed_at)}</td>
                    <td>${s.has_recording
                        ? `<button class="btn btn-sm" data-action="replay-session" data-id="${esc(s.id)}" data-host-name="${esc(s.host_name)}">Replay</button>`
                        : '<span style="font-size: 0.65rem; color: var(--text-dim);">No recording</span>'}</td>
                </tr>`).join('');
        }
    }

    const badge = document.getElementById('nav-sessions-count');
    if (badge) badge.textContent = state.activeSessions.length;

    const tabBadge = document.getElementById('sessions-tab-active-count');
    if (tabBadge) {
        tabBadge.textContent = state.activeSessions.length;
        tabBadge.classList.toggle('tab-badge-dim', state.activeSessions.length === 0);
    }

    const killAllBtn = document.getElementById('btn-kill-all-sessions');
    if (killAllBtn) killAllBtn.style.display = canKill ? '' : 'none';
    const killAllBtn2 = document.getElementById('btn-kill-all-sessions-header');
    if (killAllBtn2) killAllBtn2.style.display = canKill ? '' : 'none';

    const statEl = document.getElementById('stat-active-sessions');
    if (statEl) statEl.textContent = state.activeSessions.length;

    const subtitle = document.getElementById('sessions-subtitle');
    if (subtitle) subtitle.textContent = `Live connections • ${state.activeSessions.length} active sessions`;
}

export async function approveAccessRequest(id) {
    try {
        await post('/access-requests/' + id + '/approve', {});
        toast('success', 'Request approved', 'The user can now connect.');
        loadAccessRequests();
    } catch (e) {
        toast('error', 'Error', e.message || 'Failed to approve');
    }
}

export async function rejectAccessRequest(id) {
    try {
        await post('/access-requests/' + id + '/reject', {});
        toast('success', 'Request rejected', '');
        loadAccessRequests();
    } catch (e) {
        toast('error', 'Error', e.message || 'Failed to reject');
    }
}

export async function killSession(id) {
    try {
        await del('/sessions/' + id);
        toast('success', 'Session killed', 'The session has been terminated');
        loadSessions();
    } catch (_) {}
}

export function killAllSessions() {
    if (!confirm('Kill ALL active sessions?')) return;
    Promise.all(state.activeSessions.map(s => del('/sessions/' + s.id)))
        .then(() => loadSessions())
        .catch(e => console.error('Failed to kill sessions:', e));
}

export async function replaySession(sessionId, hostName) {
    state.svCancelled = false;
    state.svPlaying = false;
    state.svPosition = 0;
    state.svSpeed = parseFloat(document.getElementById('sv-speed')?.value || '1');

    const titleEl = document.getElementById('sv-title');
    const metaEl = document.getElementById('sv-meta');
    if (titleEl) titleEl.textContent = `Session Replay — ${hostName}`;
    if (metaEl) metaEl.textContent = `Session ${sessionId}`;

    const progressEl = document.getElementById('sv-progress');
    if (progressEl) progressEl.value = 0;
    updateSvTime(0, 0);
    updateSvPlayBtn(false);

    const container = document.getElementById('sv-terminal');
    if (!container) return;
    container.innerHTML = '';
    document.getElementById('modal-session-viewer')?.classList.add('active');

    if (state.svTerm) { state.svTerm.dispose(); state.svTerm = null; }

    state.svTerm = new Terminal({
        cursorBlink: false,
        disableStdin: true,
        fontSize: 14,
        fontFamily: "'JetBrains Mono', monospace",
        theme: { background: '#0d0d14', foreground: '#e0e0e0', cursor: '#00ff9f' },
    });
    state.svFitAddon = new FitAddon.FitAddon();
    state.svTerm.loadAddon(state.svFitAddon);
    state.svTerm.open(container);
    setTimeout(() => state.svFitAddon.fit(), 100);

    try {
        const res = await fetch(API + '/sessions/' + sessionId + '/recording');
        if (!res.ok) throw new Error('Recording not found');
        const text = await res.text();
        const lines = text.trim().split('\n');

        state.svEvents = [];
        for (let i = 1; i < lines.length; i++) {
            try {
                const event = JSON.parse(lines[i]);
                const [time, type, data] = event;
                if (type === 'o') state.svEvents.push({ time, data });
            } catch (_) {}
        }

        state.svTotalTime = state.svEvents.length > 0 ? state.svEvents[state.svEvents.length - 1].time : 0;
        updateSvTime(0, state.svTotalTime);

        buildTranscript();

        const sess = state.historySessions.find(s => s.id === sessionId) || state.activeSessions.find(s => s.id === sessionId);
        if (sess && metaEl) {
            const dur = calcDuration(sess.connected_at, sess.closed_at || undefined);
            metaEl.textContent = `${sess.username} → ${sess.host_name} • ${formatTimestamp(sess.connected_at)} • Duration: ${dur}`;
        }

        const resizeHandler = () => state.svFitAddon?.fit();
        window.addEventListener('resize', resizeHandler);
        container._resizeHandler = resizeHandler;

        toast('info', 'Session loaded', `${state.svEvents.length} events — press Play to begin`);
    } catch (e) {
        state.svTerm.write('\x1b[31mFailed to load recording: ' + e.message + '\x1b[0m\r\n');
    }
}

export function buildTranscript() {
    const el = document.getElementById('sv-transcript');
    if (!el || state.svEvents.length === 0) return;

    const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*[a-zA-Z]/g, '').replace(/\x1b\][^\x07]*\x07/g, '');

    const buckets = [];
    let currentBucket = { time: 0, text: '' };
    for (const ev of state.svEvents) {
        const bucketTime = Math.floor(ev.time * 2) / 2;
        if (bucketTime !== currentBucket.time && currentBucket.text) {
            buckets.push({ ...currentBucket });
            currentBucket = { time: bucketTime, text: '' };
        }
        currentBucket.time = bucketTime;
        currentBucket.text += stripAnsi(ev.data);
    }
    if (currentBucket.text) buckets.push(currentBucket);

    const lines = buckets
        .filter(b => b.text.trim().length > 0)
        .map(b => {
            const m = Math.floor(b.time / 60);
            const s = Math.floor(b.time % 60);
            const ts = `${m}:${String(s).padStart(2, '0')}`;
            const clean = b.text.replace(/[\r\n]+/g, '\n').replace(/\n{3,}/g, '\n\n').trim();
            return `<div class="sv-transcript-line"><span class="sv-transcript-time">${ts}</span><span class="sv-transcript-text">${esc(clean)}</span></div>`;
        });

    el.innerHTML = lines.length > 0 ? lines.join('') : '<div class="empty-state" style="padding:1rem;font-size:0.75rem;">No printable output in this session</div>';
}

export function updateSvTime(current, total) {
    const el = document.getElementById('sv-time');
    if (!el) return;
    const fmt = (t) => {
        const m = Math.floor(t / 60);
        const s = Math.floor(t % 60);
        return `${m}:${String(s).padStart(2, '0')}`;
    };
    el.textContent = `${fmt(current)} / ${fmt(total)}`;
}

export function updateSvPlayBtn(playing) {
    const btn = document.getElementById('sv-play-btn');
    if (!btn) return;
    btn.innerHTML = playing
        ? '<svg viewBox="0 0 24 24" width="14" height="14"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg> Pause'
        : '<svg viewBox="0 0 24 24" width="14" height="14"><polygon points="5 3 19 12 5 21 5 3"/></svg> Play';
}

export async function svTogglePlay() {
    if (state.svPlaying) {
        state.svPlaying = false;
        state.svCancelled = true;
        updateSvPlayBtn(false);
        return;
    }

    if (state.svPosition >= state.svEvents.length) {
        state.svPosition = 0;
        state.svTerm?.reset();
    }

    state.svPlaying = true;
    state.svCancelled = false;
    updateSvPlayBtn(true);

    const startIndex = state.svPosition;
    let prevTime = startIndex > 0 ? state.svEvents[startIndex - 1].time : 0;

    for (let i = startIndex; i < state.svEvents.length; i++) {
        if (state.svCancelled) break;

        const ev = state.svEvents[i];
        const rawDelay = (ev.time - prevTime) * 1000;
        const scaledDelay = state.svSpeed === 0 ? 0 : Math.min(rawDelay / state.svSpeed, 2000);

        if (scaledDelay > 10) {
            await new Promise(r => {
                state.svTimerId = setTimeout(r, scaledDelay);
            });
        }

        if (state.svCancelled) break;

        state.svTerm?.write(ev.data);
        state.svPosition = i + 1;
        prevTime = ev.time;

        const progress = Math.floor((ev.time / state.svTotalTime) * 1000);
        const progressEl = document.getElementById('sv-progress');
        if (progressEl) progressEl.value = progress;
        updateSvTime(ev.time, state.svTotalTime);
    }

    if (!state.svCancelled) {
        state.svPlaying = false;
        updateSvPlayBtn(false);
    }
}

export function svSetSpeed(val) {
    state.svSpeed = parseFloat(val);
}

export function svSeek(val) {
    const targetTime = (parseInt(val) / 1000) * state.svTotalTime;
    const wasPlaying = state.svPlaying;

    if (state.svPlaying) {
        state.svPlaying = false;
        state.svCancelled = true;
        clearTimeout(state.svTimerId);
    }

    state.svTerm?.reset();
    state.svPosition = 0;

    for (let i = 0; i < state.svEvents.length; i++) {
        if (state.svEvents[i].time > targetTime) break;
        state.svTerm?.write(state.svEvents[i].data);
        state.svPosition = i + 1;
    }

    updateSvTime(targetTime, state.svTotalTime);

    if (wasPlaying) {
        setTimeout(() => {
            state.svCancelled = false;
            svTogglePlay();
        }, 50);
    }
}

export function closeSessionViewer() {
    state.svPlaying = false;
    state.svCancelled = true;
    clearTimeout(state.svTimerId);

    if (state.svWs) {
        state.svWs.close();
        state.svWs = null;
    }
    clearInterval(state.svLiveTicker);
    state.svLive = false;

    document.getElementById('modal-session-viewer')?.classList.remove('active');

    const liveBadge = document.getElementById('sv-live-badge');
    const replayControls = document.getElementById('sv-replay-controls');
    const liveElapsed = document.getElementById('sv-live-elapsed');
    if (liveBadge) { liveBadge.style.display = 'none'; liveBadge.style.color = ''; liveBadge.innerHTML = '<span class="sv-live-dot"></span> LIVE'; }
    if (replayControls) replayControls.style.display = '';
    if (liveElapsed) liveElapsed.style.display = 'none';

    const transcriptHeader = document.querySelector('.session-viewer-transcript-header');
    const transcriptEl = document.getElementById('sv-transcript');
    if (transcriptHeader) transcriptHeader.style.display = '';
    if (transcriptEl) transcriptEl.style.display = '';

    const container = document.getElementById('sv-terminal');
    if (container?._resizeHandler) {
        window.removeEventListener('resize', container._resizeHandler);
    }

    if (state.svTerm) { state.svTerm.dispose(); state.svTerm = null; }
}

export function watchSession(sessionId, hostName, sessionUser) {
    state.svPlaying = false;
    state.svCancelled = true;
    clearTimeout(state.svTimerId);
    if (state.svWs) { state.svWs.close(); state.svWs = null; }
    clearInterval(state.svLiveTicker);
    if (state.svTerm) { state.svTerm.dispose(); state.svTerm = null; }
    const oldContainer = document.getElementById('sv-terminal');
    if (oldContainer?._resizeHandler) {
        window.removeEventListener('resize', oldContainer._resizeHandler);
    }

    state.svLive = true;
    state.svLiveStart = new Date();
    state.svLiveTranscriptBuf = '';

    const titleEl = document.getElementById('sv-title');
    const metaEl = document.getElementById('sv-meta');
    if (titleEl) titleEl.textContent = `Live Watch — ${sessionUser}@${hostName}`;
    if (metaEl) metaEl.textContent = `Session ${sessionId} • Started ${formatTime(state.svLiveStart.toISOString())}`;

    const liveBadge = document.getElementById('sv-live-badge');
    const replayControls = document.getElementById('sv-replay-controls');
    const liveElapsed = document.getElementById('sv-live-elapsed');
    if (liveBadge) liveBadge.style.display = '';
    if (replayControls) replayControls.style.display = 'none';
    if (liveElapsed) { liveElapsed.style.display = ''; liveElapsed.textContent = '0:00'; }

    const transcriptHeader = document.querySelector('.session-viewer-transcript-header');
    const transcriptEl = document.getElementById('sv-transcript');
    if (transcriptHeader) transcriptHeader.style.display = 'none';
    if (transcriptEl) transcriptEl.style.display = 'none';

    state.svLiveTicker = setInterval(() => {
        if (liveElapsed && state.svLiveStart) {
            const sec = Math.floor((Date.now() - state.svLiveStart.getTime()) / 1000);
            const m = Math.floor(sec / 60);
            const s = sec % 60;
            liveElapsed.textContent = `${m}:${String(s).padStart(2, '0')}`;
        }
    }, 1000);

    const container = document.getElementById('sv-terminal');
    if (!container) return;
    container.innerHTML = '';
    document.getElementById('modal-session-viewer')?.classList.add('active');

    state.svTerm = new Terminal({
        cursorBlink: false,
        disableStdin: true,
        fontSize: 14,
        fontFamily: "'JetBrains Mono', monospace",
        theme: { background: '#0d0d14', foreground: '#e0e0e0', cursor: '#00d4ff' },
    });
    state.svFitAddon = new FitAddon.FitAddon();
    state.svTerm.loadAddon(state.svFitAddon);
    state.svTerm.open(container);
    setTimeout(() => state.svFitAddon.fit(), 100);

    const resizeHandler = () => state.svFitAddon?.fit();
    window.addEventListener('resize', resizeHandler);
    container._resizeHandler = resizeHandler;

    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${proto}//${location.host}/ws/watch/${sessionId}`;
    state.svWs = new WebSocket(wsUrl);

    state.svWs.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'output' && msg.data) {
                state.svTerm?.write(msg.data);
            }
        } catch (_) {
            state.svTerm?.write(event.data);
        }
    };

    state.svWs.onclose = () => {
        state.svTerm?.write('\r\n\x1b[90m[session ended]\x1b[0m\r\n');
        if (liveBadge) {
            liveBadge.innerHTML = '<span class="sv-live-dot" style="background:var(--text-dim);box-shadow:none;"></span> ENDED';
            liveBadge.style.color = 'var(--text-dim)';
        }
        clearInterval(state.svLiveTicker);
        state.svWs = null;
    };

    state.svWs.onerror = () => {
        state.svTerm?.write('\r\n\x1b[31m[WebSocket error]\x1b[0m\r\n');
    };

    toast('info', 'Watching session', `Live view of ${sessionUser}@${hostName}`);
}
