/**
 * HackerDeX - Console & Analysis JavaScript
 * Handles: Console toggle, output, Gemini analysis
 */

function toggleConsole() {
    consoleOpen = !consoleOpen;
    document.getElementById('consoleOverlay').style.display = consoleOpen ? 'flex' : 'none';
    const btn = document.getElementById('toggleConsoleBtn');
    if (btn) btn.classList.toggle('active', consoleOpen);
}

function closeConsoleOnBackdrop(e) {
    if (e.target === document.getElementById('consoleOverlay')) {
        toggleConsole();
    }
}

function clearConsole() {
    consoleOutput.innerHTML = '';
    log('Console cleared', 'info');
}

function copyOutput() {
    const text = consoleOutput.innerText;
    navigator.clipboard.writeText(text).then(() => {
        log('Output copied to clipboard!', 'success');
    });
}

function analyzeWithGemini() {
    if (!lastScanOutput) {
        log('No scan output to analyze. Run a scan first!', 'warning');
        return;
    }

    log('Sending output to Gemini 2.5 Pro for analysis...', 'cmd');
    setStatus('running');

    safeFetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            output: lastScanOutput,
            tool: lastScanTool,
            target: lastScanTarget
        })
    })
        .then(data => {
            if (data.error) {
                log(`Analysis Error: ${data.error}`, 'error');
                setStatus('error');
                return;
            }

            log('=== GEMINI ANALYSIS ===', 'cmd');
            const lines = data.analysis.split('\n');
            lines.forEach(line => {
                if (line.startsWith('##') || line.startsWith('**')) {
                    log(line, 'cmd');
                } else if (line.toLowerCase().includes('high') || line.toLowerCase().includes('critical')) {
                    log(line, 'error');
                } else if (line.toLowerCase().includes('medium') || line.toLowerCase().includes('warning')) {
                    log(line, 'warning');
                } else if (line.includes('✓') || line.toLowerCase().includes('low')) {
                    log(line, 'success');
                } else {
                    log(line, 'info');
                }
            });
            log('=== END ANALYSIS ===', 'cmd');
            setStatus('ready');
        })
        .catch(err => {
            log(`Network error: ${err}`, 'error');
            setStatus('error');
        });
}

// Report Generation Functions
function generateReport() {
    document.getElementById('reportModal').style.display = 'flex';
    const contentDiv = document.getElementById('reportContent');
    contentDiv.innerHTML = '<div class="spinner"></div> Generating Professional Report...';

    safeFetch('/api/generate_report', { method: 'POST' })
        .then(data => {
            if (data.status === 'success') {
                contentDiv.innerText = data.report;
                showToast('Report generated successfully!', 'success');
            } else {
                contentDiv.innerHTML = `<div class="error">Failed to generate report: ${data.error}</div>`;
            }
        })
        .catch(err => {
            contentDiv.innerHTML = `<div class="error">Network Error: ${err.message}</div>`;
        });
}

function closeReportModal() {
    document.getElementById('reportModal').style.display = 'none';
}

function copyReport() {
    const text = document.getElementById('reportContent').innerText;
    navigator.clipboard.writeText(text).then(() => {
        showToast('Report copied to clipboard!', 'success');
    });
}
