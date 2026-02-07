/**
 * HackerDeX - Core Application JavaScript
 * Handles: Socket.io, tools loading, toasts, status, and utilities
 */

// Global state
let currentTools = {};
let selectedTool = null;
let consoleOpen = false;
let lastScanOutput = '';
let lastScanTool = '';
let lastScanTarget = '';

// Initialize Socket.IO
const socket = io();
const consoleOutput = document.getElementById('consoleOutput');

// ================== UTILITY FUNCTIONS ==================

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function safeFetch(url, options = {}) {
    return fetch(url, options)
        .then(r => {
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return r.json();
        })
        .catch(err => {
            showToast(`Network Error: ${err.message}`, 'error');
            throw err;
        });
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `<span class="spinner" style="display: none;"></span>${message}`;
    container.appendChild(toast);
    setTimeout(() => toast.remove(), 4000);
}

function setStatus(status) {
    const dot = document.getElementById('statusDot');
    const text = document.getElementById('statusText');
    dot.className = 'status-dot ' + status;
    text.innerText = status.charAt(0).toUpperCase() + status.slice(1);
}

function log(text, type = 'info') {
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    const line = document.createElement('div');
    line.className = 'line';
    line.innerHTML = `<span class="timestamp">[${time}]</span><span class="${type}">${escapeHtml(text)}</span>`;
    consoleOutput.appendChild(line);
    consoleOutput.scrollTop = consoleOutput.scrollHeight;
}

// ================== SOCKET EVENTS ==================

socket.on('connect', () => {
    log('WebSocket connected', 'success');
    setStatus('ready');
});

socket.on('connect_error', () => {
    showToast('Lost connection to server!', 'error');
    setStatus('error');
});

socket.on('reconnect', () => {
    showToast('Reconnected to server', 'success');
    setStatus('ready');
});

socket.on('scan_output', (data) => {
    const line = data.line.trim();
    let type = 'info';
    if (line.toLowerCase().includes('error') || line.toLowerCase().includes('failed')) type = 'error';
    else if (line.toLowerCase().includes('warning') || line.toLowerCase().includes('warn')) type = 'warning';
    else if (line.toLowerCase().includes('success') || line.toLowerCase().includes('found') || line.toLowerCase().includes('open')) type = 'success';
    log(data.line.replace(/\n$/, ''), type);
});

socket.on('scan_complete', (data) => {
    log(`Scan complete (exit: ${data.exit_code})`, data.exit_code === 0 ? 'success' : 'warning');
    setStatus('ready');

    safeFetch(`/api/status/${data.job_id}`)
        .then(job => {
            lastScanOutput = job.output || '';
            lastScanTool = job.tool || '';
            lastScanTarget = job.target || '';
        })
        .catch(() => { });
});

socket.on('scan_error', (data) => {
    log(`Error: ${data.error}`, 'error');
    setStatus('error');
});

socket.on('store_updated', (data) => {
    if (typeof intelOpen !== 'undefined' && intelOpen) {
        loadTargets();
        const currentProfileId = document.getElementById('profileId').innerText;
        if (currentProfileId === data.target_id) viewProfile(data.target_id);
    }
    showToast(`Intel gathered: ${data.message}`, 'success');
});

// ================== TOOLS LOADING ==================

safeFetch('/api/tools')
    .then(catalog => {
        currentTools = catalog;
        const categories = Object.keys(catalog);
        const list = document.getElementById('categoryList');

        categories.forEach((cat, index) => {
            const li = document.createElement('li');
            li.className = 'category-item';
            li.innerHTML = `${cat} <span class="tool-count">${catalog[cat].length}</span>`;
            li.onclick = () => loadCategory(cat, li);
            list.appendChild(li);
            if (index === 0) loadCategory(cat, li);
        });

        log(`Loaded ${Object.values(catalog).flat().length} tools in ${categories.length} categories`, 'success');
    });

function loadCategory(name, element) {
    document.querySelectorAll('.category-item').forEach(el => el.classList.remove('active'));
    if (element) element.classList.add('active');

    document.getElementById('pageTitle').innerText = name;
    const grid = document.getElementById('toolGrid');
    grid.innerHTML = '';

    const tools = currentTools[name] || [];
    tools.forEach(tool => {
        const card = document.createElement('div');
        card.className = 'card';
        card.innerHTML = `<h3>${tool}</h3><p>Click to configure and launch.</p>`;
        card.onclick = () => openModal(tool);
        grid.appendChild(card);
    });
}

function filterTools(query) {
    const grid = document.getElementById('toolGrid');
    grid.innerHTML = '';

    if (!query || query.length < 2) {
        const firstCat = Object.keys(currentTools)[0];
        if (firstCat) loadCategory(firstCat);
        return;
    }

    document.getElementById('pageTitle').innerText = `Search: "${query}"`;
    document.querySelectorAll('.category-item').forEach(el => el.classList.remove('active'));

    const lowerQuery = query.toLowerCase();
    let matchCount = 0;

    Object.entries(currentTools).forEach(([category, tools]) => {
        tools.forEach(tool => {
            if (tool.toLowerCase().includes(lowerQuery) || category.toLowerCase().includes(lowerQuery)) {
                const card = document.createElement('div');
                card.className = 'card';
                card.innerHTML = `<h3>${tool}</h3><p><small style="color: #8b949e;">${category}</small></p>`;
                card.onclick = () => openModal(tool);
                grid.appendChild(card);
                matchCount++;
            }
        });
    });

    if (matchCount === 0) {
        grid.innerHTML = '<p style="color: #666; padding: 20px;">No tools found matching your search.</p>';
    }
}

// ================== TOOL MODAL ==================

function openModal(toolName) {
    selectedTool = toolName;
    document.getElementById('modalToolName').innerText = toolName;
    document.getElementById('configModal').style.display = 'flex';

    const target = document.getElementById('targetInput').value;
    const suggestionDiv = document.getElementById('contextSuggestions');
    if (target && suggestionDiv) {
        suggestionDiv.innerHTML = '<div class="spinner"></div> Checking Intel...';
        safeFetch(`/api/targets/${target}/profile`)
            .then(profile => {
                if (profile) {
                    let html = '<div style="background: rgba(88,166,255,0.1); padding: 10px; border-radius: 8px; font-size: 0.8rem; border: 1px dashed var(--accent);">';
                    html += `💡 <b>Intel Found:</b> ${profile.ports.length} ports, ${profile.vulnerabilities.length} vulns.<br>`;
                    if (profile.technologies.length > 0) {
                        html += `🛠️ <b>Tech:</b> ${profile.technologies.slice(0, 3).map(t => t.name).join(', ')}`;
                    }
                    html += '</div>';
                    suggestionDiv.innerHTML = html;
                } else {
                    suggestionDiv.innerHTML = '';
                }
            })
            .catch(() => suggestionDiv.innerHTML = '');
    }
}

function closeModal() {
    document.getElementById('configModal').style.display = 'none';
    selectedTool = null;
    if (document.getElementById('contextSuggestions')) document.getElementById('contextSuggestions').innerHTML = '';
}

function startScan() {
    const target = document.getElementById('targetInput').value;
    if (!target) return alert("Please enter a target!");

    closeModal();
    if (!consoleOpen) toggleConsole();

    log(`Launching ${selectedTool} against ${target}...`, 'cmd');
    setStatus('running');

    safeFetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool: selectedTool, target: target })
    })
        .then(data => {
            if (data.error) {
                log(`Error: ${data.message}`, 'error');
                setStatus('error');
                return;
            }
            log(`Job started: ${data.job_id}`, 'info');
        })
        .catch(() => setStatus('error'));
}

// ================== GEMINI INTEGRATION ==================

safeFetch('/api/gemini-status')
    .then(data => {
        if (data.configured) {
            log(`Gemini ${data.model} ready for analysis`, 'success');
        } else {
            log('Gemini API not configured (set GEMINI_API_KEY)', 'warning');
        }
    });

// Initial messages
log('HackerDeX Security Lab v1.0', 'cmd');
log('Ready to scan. Select a tool to begin.', 'info');
