/**
 * HackerDeX - Sessions Panel JavaScript
 * Handles: C2 sessions, listeners, interactive terminal
 */

let selectedSessionId = null;
let sessionPollInterval = null;

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

            document.getElementById('sessionTerminal').textContent = `$ Connected to ${session.target_ip}\n`;
            pollSessionOutput();
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
                refreshSessions();
            })
            .catch(err => showToast('Failed to delete session', 'error'));
    }
}

function sendSessionCmd() {
    if (!selectedSessionId) return;

    const input = document.getElementById('terminalInput');
    const command = input.value.trim();
    if (!command) return;

    const terminal = document.getElementById('sessionTerminal');
    terminal.textContent += `$ ${command}\n`;
    input.value = '';

    safeFetch(`/api/sessions/${selectedSessionId}/command`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command })
    })
        .then(data => {
            if (data.status !== 'sent') {
                terminal.textContent += `[!] ${data.error}\n`;
            }
            setTimeout(pollSessionOutput, 500);
        })
        .catch(err => {
            terminal.textContent += `[!] Network error\n`;
        });

    terminal.scrollTop = terminal.scrollHeight;
}

function pollSessionOutput() {
    if (!selectedSessionId) return;

    safeFetch(`/api/sessions/${selectedSessionId}/output`)
        .then(data => {
            if (data.output) {
                const terminal = document.getElementById('sessionTerminal');
                terminal.textContent += data.output;
                terminal.scrollTop = terminal.scrollHeight;
            }
        })
        .catch(() => { });
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
