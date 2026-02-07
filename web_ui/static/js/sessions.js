/**
 * HackerDeX - Sessions Panel JavaScript
 * Handles: C2 sessions, listeners, interactive terminal (xterm.js)
 */

let selectedSessionId = null;
let sessionPollInterval = null;
let term = null;
let fitAddon = null;

function openSessionsModal() {
    document.getElementById('sessionsModal').style.display = 'flex';
    refreshSessions();
    sessionPollInterval = setInterval(refreshSessions, 5000);
}

function closeSessionsModal() {
    document.getElementById('sessionsModal').style.display = 'none';
    if (sessionPollInterval) {
        clearInterval(sessionPollInterval);
        sessionPollInterval = null;
    }
}

function refreshSessions() {
    safeFetch('/api/sessions')
        .then(data => {
            renderSessionsList(data.sessions || []);
            renderSummary(data.summary || {});
            document.getElementById('sessionCount').textContent = data.summary?.active || 0;
        })
        .catch(err => console.error('Failed to fetch sessions:', err));

    safeFetch('/api/listeners')
        .then(data => {
            renderListenersList(data.listeners || []);
            document.getElementById('summaryListeners').textContent = data.listeners?.length || 0;
        })
        .catch(err => console.error('Failed to fetch listeners:', err));
}

function renderSessionsList(sessions) {
    const container = document.getElementById('sessionsList');
    if (sessions.length === 0) {
        container.innerHTML = '<div class="empty-intel" style="padding: 20px;"><p>No sessions yet. Run scans or start a listener.</p></div>';
        return;
    }

    container.innerHTML = sessions.map(s => `
        <div class="session-card ${s.status}" onclick="selectSession('${s.session_id}')">
            <div class="session-header">
                <span class="session-type">${s.session_type}</span>
                <span class="session-status ${s.status}">${s.status.toUpperCase()}</span>
            </div>
            <div class="session-target">${s.target_ip}${s.target_port ? ':' + s.target_port : ''}</div>
            <div class="session-meta">
                ${s.source_tool} | ${s.username ? s.username + '@' : ''}${new Date(s.created_at).toLocaleTimeString()}
            </div>
        </div>
    `).join('');
}

function renderListenersList(listeners) {
    const container = document.getElementById('listenersList');
    if (listeners.length === 0) {
        container.innerHTML = '<div style="color: #6e7681; font-size: 0.8rem; text-align: center; padding: 10px;">No active listeners</div>';
        return;
    }

    container.innerHTML = listeners.map(l => `
        <div class="listener-item">
            <div>
                <span class="port">:${l.port}</span>
                <span class="protocol">${l.protocol.toUpperCase()}</span>
                <span style="font-size: 0.7rem; color: #6e7681; margin-left: 8px;">${l.connections || 0} conn</span>
            </div>
            <button class="stop-btn" onclick="stopListener(${l.port})">Stop</button>
        </div>
    `).join('');
}

function renderSummary(summary) {
    document.getElementById('summaryTotal').textContent = summary.total_sessions || 0;
    document.getElementById('summaryActive').textContent = summary.active || 0;
    document.getElementById('summaryPending').textContent = summary.pending || 0;
}

function showNewListenerForm() {
    document.getElementById('newListenerForm').style.display = 'block';
    document.getElementById('listenerPort').focus();
}

function hideNewListenerForm() {
    document.getElementById('newListenerForm').style.display = 'none';
    document.getElementById('listenerPort').value = '';
}

function startNewListener() {
    const port = document.getElementById('listenerPort').value;
    if (!port) {
        showToast('Please enter a port number', 'warning');
        return;
    }

    safeFetch('/api/listeners', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ port: parseInt(port), protocol: 'tcp' })
    })
        .then(data => {
            if (data.status === 'started') {
                showToast(`Listener started on port ${port}`, 'success');
                hideNewListenerForm();
                refreshSessions();
            } else {
                showToast(data.error || 'Failed to start listener', 'error');
            }
        })
        .catch(err => showToast('Network error', 'error'));
}

function stopListener(port) {
    safeFetch(`/api/listeners/${port}`, { method: 'DELETE' })
        .then(data => {
            if (data.status === 'stopped') {
                showToast(`Listener on port ${port} stopped`, 'success');
                refreshSessions();
            } else {
                showToast(data.error || 'Failed to stop listener', 'error');
            }
        })
        .catch(err => showToast('Network error', 'error'));
}

function initTerminal() {
    if (term) return; // Already initialized

    const terminalContainer = document.getElementById('sessionTerminal');
    terminalContainer.innerHTML = ''; // Clear fallback text

    term = new Terminal({
        cursorBlink: true,
        theme: {
            background: '#0d1117',
            foreground: '#c9d1d9',
            cursor: '#58a6ff'
        },
        fontFamily: 'JetBrains Mono, monospace',
        fontSize: 14
    });

    fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(terminalContainer);
    fitAddon.fit();

    // Resize observer to auto-fit terminal
    new ResizeObserver(() => fitAddon.fit()).observe(terminalContainer);

    // Handle input
    term.onData(data => {
        if (selectedSessionId) {
            socket.emit('session_input', {
                session_id: selectedSessionId,
                input: data
            });
        }
    });

    // Handle output from server
    socket.on('session_output', (data) => {
        if (selectedSessionId && data.session_id === selectedSessionId) {
            term.write(data.output);
        }
    });
}

function selectSession(sessionId) {
    selectedSessionId = sessionId;

    safeFetch(`/api/sessions/${sessionId}`)
        .then(session => {
            document.getElementById('noSessionSelected').style.display = 'none';
            document.getElementById('activeSessionView').style.display = 'flex';

            document.getElementById('detailType').textContent = session.session_type;
            document.getElementById('detailStatus').textContent = session.status.toUpperCase();
            document.getElementById('detailStatus').className = `session-status ${session.status}`;
            document.getElementById('detailTarget').textContent = `${session.target_ip}:${session.target_port || '-'}`;
            document.getElementById('detailSource').textContent = session.source_tool;
            document.getElementById('detailCreds').textContent = session.username
                ? `${session.username}:${session.password || '***'}`
                : (session.cookie ? '[Cookie captured]' : '-');

            // Initialize xterm if needed
            if (!term) initTerminal();

            term.clear();
            term.write(`\r\n\x1b[1;32m[*] Connected to session ${sessionId}\x1b[0m\r\n`);

            // Load history
            safeFetch(`/api/sessions/${sessionId}/output`)
                .then(data => {
                    if (data.output) term.write(data.output);
                });

            fitAddon.fit();
            term.focus();
        })
        .catch(err => showToast('Failed to load session', 'error'));
}

function deleteSelectedSession() {
    if (!selectedSessionId) return;

    if (confirm('Are you sure you want to kill this session?')) {
        safeFetch(`/api/sessions/${selectedSessionId}`, { method: 'DELETE' })
            .then(data => {
                showToast('Session terminated', 'success');
                selectedSessionId = null;
                document.getElementById('noSessionSelected').style.display = 'block';
                document.getElementById('activeSessionView').style.display = 'none';

                if (term) term.clear();

                refreshSessions();
            })
            .catch(err => showToast('Failed to delete session', 'error'));
    }
}

// Listen for new session detection
socket.on('session_detected', (data) => {
    showToast(`${data.count} new session(s) from ${data.tool}!`, 'success');
    document.getElementById('sessionCount').textContent =
        parseInt(document.getElementById('sessionCount').textContent) + data.count;
});

// Listen for new connections on listeners
socket.on('new_connection', (data) => {
    showToast(`New connection from ${data.client_ip} on port ${data.listener_port}!`, 'success');
    refreshSessions();
});
