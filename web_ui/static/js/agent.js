/**
 * HackerDeX - AI Agent JavaScript
 * Handles: AutoPilot agent, chat interface
 */

function openAgentModal() {
    document.getElementById('agentModal').style.display = 'flex';
}

function closeAgentModal() {
    document.getElementById('agentModal').style.display = 'none';
}

socket.on('agent_update', (data) => {
    const chatDiv = document.getElementById('agentChat');
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    let content = data.message;

    if (data.type === 'tool_output') {
        content = `<div class="tool-output-block">${content}</div>`;
    } else if (content.includes('🧠')) {
        content = `<span style="color: #9b72cb;">${content}</span>`;
    } else if (content.includes('💡')) {
        content = `<span style="color: #ffe08a;">${content}</span>`;
    } else if (content.includes('⚡')) {
        content = `<span style="color: #4285f4; font-weight: 600;">${content}</span>`;
    } else if (content.includes('✅')) {
        content = `<span style="color: var(--success); font-weight: 600;">${content}</span>`;
    } else if (content.includes('❌') || content.includes('⚠️')) {
        content = `<span style="color: var(--error); font-weight: 600;">${content}</span>`;
    }

    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble agent';
    bubble.innerHTML = `${content}<span class="chat-timestamp">${time}</span>`;

    chatDiv.appendChild(bubble);
    chatDiv.scrollTop = chatDiv.scrollHeight;
});

socket.on('agent_reasoning', (data) => {
    // Optionally log to a separate reasoning panel or just the chat
    const chatDiv = document.getElementById('agentChat');
    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble agent';
    bubble.style.borderLeft = '3px solid var(--accent)';
    bubble.innerHTML = `
        <div style="font-size: 0.75rem; color: var(--accent); margin-bottom: 5px;">[STRATEGIC REASONING STEP ${data.step}]</div>
        <b>Thought:</b> ${data.thought}<br>
        <b>Command:</b> <code>${data.command}</code><br>
        <b>Expectation:</b> ${data.expected_gain}
    `;
    chatDiv.appendChild(bubble);
    chatDiv.scrollTop = chatDiv.scrollHeight;
});

function stopAutoPilot() {
    if (!confirm("Are you sure you want to activate the KILL SWITCH?")) return;
    
    safeFetch('/api/autopilot/stop', { method: 'POST' })
        .then(data => showToast(data.message, 'warning'))
        .catch(err => showToast('Failed to stop agent', 'error'));
}

function startAutoPilot() {
    const target = document.getElementById('agentTarget').value;
    const goal = document.getElementById('agentGoal').value;

    if (!target || !goal) {
        alert('Please provide both target and goal!');
        return;
    }

    const chatDiv = document.getElementById('agentChat');
    chatDiv.innerHTML = '<div class="info" style="text-align: center; color: #666; margin-bottom: 20px;">--- New Mission Started ---</div>';

    const userBubble = document.createElement('div');
    userBubble.className = 'chat-bubble user';
    userBubble.innerHTML = `<b>Target:</b> ${target}<br><b>Goal:</b> ${goal}<span class="chat-timestamp">Now</span>`;
    chatDiv.appendChild(userBubble);

    safeFetch('/api/autopilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target, goal: goal })
    })
        .then(data => {
            if (data.error) {
                const errBubble = document.createElement('div');
                errBubble.className = 'chat-bubble agent';
                errBubble.innerHTML = `<span style="color: var(--error);">Error: ${data.error}</span><span class="chat-timestamp">Now</span>`;
                chatDiv.appendChild(errBubble);
            } else {
                const okBubble = document.createElement('div');
                okBubble.className = 'chat-bubble agent';
                okBubble.innerHTML = `Mission started and goal locked. Reasoning engine engaged.<span class="chat-timestamp">Now</span>`;
                chatDiv.appendChild(okBubble);
            }
        })
        .catch(() => {
            const errBubble = document.createElement('div');
            errBubble.className = 'chat-bubble agent';
            errBubble.innerHTML = `<span style="color: var(--error);">Failed to connect to agent backend.</span><span class="chat-timestamp">Now</span>`;
            chatDiv.appendChild(errBubble);
        });
}
