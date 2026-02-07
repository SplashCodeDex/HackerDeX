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
            list.innerHTML = `
                <div class="intel-section" style="border-bottom: 1px solid var(--border); padding-bottom: 15px;">
                    <h4 style="margin-top:0;">Strategic Analysis</h4>
                    <button class="console-btn ai-btn" onclick="analyzeAttackPaths()" style="width: 100%; justify-content: center; margin-bottom: 10px;">
                        <svg class="icon"><use href="#icon-brain"/></svg> AI Attack Path Analysis
                    </button>
                </div>
            ` + targets.map(t => {
                const priorityClass = `priority-${t.priority_level}`;
                return `
                    <div class="target-item" onclick="viewProfile('${t.id}')">
                        <div style="display: flex; justify-content: space-between; align-items: start;">
                            <span class="host">${t.target}</span>
                            <span class="intel-pill ${priorityClass}" style="margin:0; font-size: 0.6rem;">${t.priority_level.toUpperCase()}</span>
                        </div>
                        <div class="stats">
                            🛡️ ${t.vulns_count} | 🔌 ${t.ports_count} | 🔥 Score: ${t.risk_score.toFixed(1)}
                        </div>
                    </div>
                `;
            }).join('');
        })
        .catch(() => list.innerHTML = '<div class="empty-intel">Failed to load targets</div>');
}

function analyzeAttackPaths() {
    showToast('Analyzing attack surface...', 'info');
    document.getElementById('reportModal').style.display = 'flex';
    const contentDiv = document.getElementById('reportContent');
    contentDiv.innerHTML = '<div class="spinner"></div> Gemini is correlating findings and predicting attack chains...';

    safeFetch('/api/intel/attack-paths', { method: 'POST' })
        .then(data => {
            contentDiv.innerText = data.analysis;
            showToast('Strategic analysis complete', 'success');
        })
        .catch(err => {
            contentDiv.innerHTML = `<div class="error">Analysis Failed: ${err.message}</div>`;
        });
}

function suggestNextAction(target) {
    showToast(`Consulting AI for next steps on ${target}...`, 'info');
    
    safeFetch('/api/intel/next-action', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ target: target })
    })
    .then(data => {
        if (data.tool === 'error') {
            showToast(data.reason, 'error');
        } else {
            // Show a custom modal or just a large toast
            alert(`AI Suggestion for ${target}:\n\nTool: ${data.tool}\nReason: ${data.reason}\n\nRecommended Command:\n${data.command}`);
        }
    })
    .catch(err => showToast('Failed to get recommendation', 'error'));
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
                <div class="intel-section" style="background: rgba(88,166,255,0.05); border-bottom: 2px solid var(--accent);">
                    <button class="console-btn" onclick="suggestNextAction('${t.main_target}')" style="width: 100%; justify-content: center; border-color: var(--accent); color: var(--accent);">
                        <svg class="icon"><use href="#icon-brain"/></svg> Suggest Next Best Action
                    </button>
                </div>
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
