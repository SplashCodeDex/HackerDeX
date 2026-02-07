/**
 * HackerDeX - Intelligence Sidebar JavaScript
 * Handles: Target management, profiles, exploit generation
 */

let intelOpen = false;

function toggleIntelPanel() {
    const panel = document.getElementById('intelSidebar');
    intelOpen = !intelOpen;
    panel.style.display = intelOpen ? 'flex' : 'none';
    if (intelOpen) loadTargets();
}

function loadTargets() {
    const list = document.getElementById('targetList');
    list.innerHTML = '<div class="spinner"></div> Loading...';

    safeFetch('/api/targets')
        .then(targets => {
            if (targets.length === 0) {
                list.innerHTML = '<div class="empty-intel">No targets discovered yet.</div>';
                return;
            }
            list.innerHTML = targets.map(t => `
                <div class="target-item" onclick="viewProfile('${t.id}')">
                    <span class="host">${t.target}</span>
                    <div class="stats">
                        🛡️ ${t.vulns_count} Vulns | 🔌 ${t.ports_count} Ports | 🕒 ${new Date(t.last_seen).toLocaleTimeString()}
                    </div>
                </div>
            `).join('');
        })
        .catch(() => list.innerHTML = '<div class="empty-intel">Failed to load targets</div>');
}

function viewProfile(tid) {
    document.getElementById('targetListSection').style.display = 'none';
    document.getElementById('profileSection').style.display = 'block';
    document.getElementById('profileContent').innerHTML = '<div class="spinner"></div> Loading profile...';

    safeFetch(`/api/targets/${tid}/profile`)
        .then(t => {
            document.getElementById('profileHost').innerText = t.main_target;
            document.getElementById('profileId').innerText = t.id;

            let html = `
                <div class="intel-section">
                    <h4>Ports & Services</h4>
                    <div>${t.ports.length ? t.ports.map(p => `
                        <div class="intel-pill port">
                            <b>${p.port}/${p.protocol}</b> ${p.service} ${p.version ? `(${p.version})` : ''}
                        </div>
                    `).join('') : '<small>None found</small>'}</div>
                </div>
                <div class="intel-section">
                    <h4>Vulnerabilities</h4>
                    <div>${t.vulnerabilities.length ? t.vulnerabilities.map(v => `
                        <div class="intel-pill vuln-${v.severity == 'critical' || v.severity == 'high' ? 'high' : 'med'}" style="display: flex; justify-content: space-between; align-items: center;">
                            <span title="${v.details}"><b>${v.severity.toUpperCase()}</b>: ${v.title}</span>
                            <button onclick="generateExploit('${v.title.replace(/'/g, "\\'")}', '${t.main_target}')" style="background: transparent; border: none; cursor: pointer; color: inherit; padding: 0 4px;" title="Generate AI Exploit">⚡</button>
                        </div>
                    `).join('') : '<small>No vulnerabilities detected</small>'}</div>
                </div>
                <div class="intel-section">
                    <h4>Technologies</h4>
                    <div>${t.technologies.length ? t.technologies.map(tech => `
                        <div class="intel-pill">
                            🛠️ ${tech.name} ${tech.version ? `(${tech.version})` : ''}
                        </div>
                    `).join('') : '<small>Unknown</small>'}</div>
                </div>
                <div class="intel-section">
                    <h4>History</h4>
                    <small style="color: #6e7681;">Discovered URLs: ${t.urls.length}</small>
                </div>
            `;
            document.getElementById('profileContent').innerHTML = html;
        })
        .catch(() => document.getElementById('profileContent').innerHTML = '<div class="empty-intel">Failed to load profile</div>');
}

function generateExploit(vulnTitle, target) {
    document.getElementById('exploitModal').style.display = 'flex';
    const codeBlock = document.getElementById('exploitCode');
    codeBlock.innerText = 'Generating exploit code...';

    showToast(`Generating exploit for: ${vulnTitle}`, 'info');

    safeFetch('/api/generate_exploit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ vuln: vulnTitle, target: target })
    })
        .then(data => {
            if (data.status === 'success') {
                codeBlock.innerText = data.code;
                showToast('Exploit generated successfully!', 'success');
            } else {
                codeBlock.innerText = `Error: ${data.error}`;
                showToast('Failed to generate exploit', 'error');
            }
        })
        .catch(err => {
            codeBlock.innerText = `Network Error: ${err.message}`;
        });
}

function closeExploitModal() {
    document.getElementById('exploitModal').style.display = 'none';
}

function copyExploit() {
    const text = document.getElementById('exploitCode').innerText;
    navigator.clipboard.writeText(text).then(() => {
        showToast('Exploit code copied!', 'success');
    });
}

function backToTargets() {
    document.getElementById('targetListSection').style.display = 'flex';
    document.getElementById('profileSection').style.display = 'none';
    loadTargets();
}
