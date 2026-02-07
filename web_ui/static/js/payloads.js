let currentStep = 1;
let selectedTemplate = null;
let generatedPayload = null;
let currentEvasion = 'none';

function openPayloadModal() {
    document.getElementById('payloadModal').style.display = 'flex';
    loadTemplates();
    resetWizard();
}

function closePayloadModal() {
    document.getElementById('payloadModal').style.display = 'none';
}

function resetWizard() {
    currentStep = 1;
    selectedTemplate = null;
    generatedPayload = null;
    currentEvasion = 'none';
    showStep(1);

    const container = document.getElementById('payloadOptionsForm');
    if (container) container.innerHTML = '';

    const codeBlock = document.getElementById('generatedCode');
    if (codeBlock) codeBlock.innerText = '';

    const hostResult = document.getElementById('hostUrlResult');
    if (hostResult) hostResult.style.display = 'none';

    // Reset inputs
    document.querySelectorAll('.evasion-option').forEach(el => el.classList.remove('selected'));
    // Select none by default if exists
    const defaultOption = document.querySelector('[onclick="selectEvasion(\'none\', this)"]');
    if (defaultOption) defaultOption.classList.add('selected');
}

function showStep(step) {
    if (step > 1 && !selectedTemplate) {
        showToast('Please select a template first', 'warning');
        return;
    }

    // Update Sidebar
    document.querySelectorAll('.wizard-step').forEach((el, index) => {
        el.classList.remove('active', 'completed');
        if (index + 1 < step) el.classList.add('completed');
        if (index + 1 === step) el.classList.add('active');
    });

    // Update Content
    document.querySelectorAll('.step-pane').forEach(el => el.style.display = 'none');
    document.getElementById(`step${step}`).style.display = 'flex';

    currentStep = step;

    if (step === 2) {
        renderOptionsForm();
    }
}

async function loadTemplates() {
    try {
        const response = await fetch('/api/payloads/templates');
        const templates = await response.json();

        const grid = document.getElementById('templateGrid');
        grid.innerHTML = '';

        templates.forEach(t => {
            const card = document.createElement('div');
            card.className = 'template-card';
            card.onclick = () => selectTemplate(t, card);

            let icon = '📄';
            if (t.category.includes('system')) icon = '💻';
            if (t.category.includes('web')) icon = '🌐';
            if (t.category.includes('macro')) icon = '📑';

            card.innerHTML = `
                <div class="template-icon">${icon}</div>
                <div style="font-weight:600; font-size:0.9rem;">${t.name}</div>
                <div style="color:#8b949e; font-size:0.75rem;">${t.category}</div>
            `;
            grid.appendChild(card);
        });
    } catch (e) {
        console.error(e);
        showToast('Failed to load templates', 'error');
    }
}

function selectTemplate(template, cardElement) {
    selectedTemplate = template;
    document.querySelectorAll('.template-card').forEach(el => el.classList.remove('selected'));
    cardElement.classList.add('selected');
    // Auto advance
    setTimeout(() => showStep(2), 300);
}

function renderOptionsForm() {
    const container = document.getElementById('payloadOptionsForm');
    container.innerHTML = '';

    // Identify required fields based on template content (simple heuristic)
    // For now we assume LHOST and LPORT are always needed for reverse shells
    const fields = ['LHOST', 'LPORT'];

    const currentHost = location.hostname || '127.0.0.1';

    fields.forEach(field => {
        const group = document.createElement('div');
        group.className = 'form-group';

        const label = document.createElement('label');
        label.innerText = field;

        const input = document.createElement('input');
        input.type = 'text';
        input.id = `opt_${field}`;
        input.value = field === 'LHOST' ? currentHost : (field === 'LPORT' ? '4444' : '');

        group.appendChild(label);
        group.appendChild(input);
        container.appendChild(group);
    });
}

function selectEvasion(level, element) {
    currentEvasion = level;
    document.querySelectorAll('.evasion-option').forEach(el => el.classList.remove('selected'));
    element.classList.add('selected');
}

async function generatePayload() {
    if (!selectedTemplate) return;

    const lhost = document.getElementById('opt_LHOST').value;
    const lport = document.getElementById('opt_LPORT').value;

    const options = {
        LHOST: lhost,
        LPORT: lport,
        type: selectedTemplate.id.includes('python') ? 'python' :
            selectedTemplate.id.includes('powershell') ? 'powershell' :
                selectedTemplate.id.includes('php') ? 'web' : 'unknown',
        persistence: document.getElementById('optPersistence').checked,
        anti_analysis: document.getElementById('optAntiAnalysis').checked
    };

    const btn = document.getElementById('generateBtn');
    const originalText = btn.innerHTML;
    btn.innerHTML = '<span class="spinner"></span> Forging...';
    btn.disabled = true;

    try {
        const res = await fetch('/api/payloads/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                template_id: loadingTemplateId(),
                evasion: currentEvasion,
                options: options
            })
        });

        const data = await res.json();

        if (data.status === 'success') {
            generatedPayload = data.code;
            document.getElementById('generatedCode').innerText = generatedPayload;
            showStep(4);
            showToast('Payload forged successfully!', 'success');
        } else {
            showToast(data.error || 'Generation failed', 'error');
        }
    } catch (e) {
        showToast('Network error during generation', 'error');
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

function loadingTemplateId() {
    return selectedTemplate ? selectedTemplate.id : '';
}

function copyPayload() {
    if (!generatedPayload) return;
    navigator.clipboard.writeText(generatedPayload);
    showToast('Payload copied to clipboard', 'success');
}

function downloadPayloadRaw() {
    const filename = prompt("Enter filename:", "payload.txt");
    if (!filename) return;

    const blob = new Blob([generatedPayload], { type: "text/plain" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
}

async function hostPayload() {
    if (!generatedPayload) {
        showToast('Generate payload first!', 'warning');
        return;
    }

    const filename = prompt("Enter filename to host as:", "update.exe");
    if (!filename) return;

    const lhost = document.getElementById('opt_LHOST').value;
    const lport = document.getElementById('opt_LPORT').value;

    const options = { LHOST: lhost, LPORT: lport };

    try {
        const res = await fetch('/api/payloads/host', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                template_id: loadingTemplateId(),
                evasion: currentEvasion,
                options: options,
                filename: filename
            })
        });

        const data = await res.json();

        if (data.status === 'hosted') {
            const urlDiv = document.getElementById('hostUrl');
            urlDiv.innerText = data.url;
            urlDiv.href = data.url;
            document.getElementById('hostUrlResult').style.display = 'block';
            showToast('Payload hosted!', 'success');
        } else {
            showToast(data.error || 'Hosting failed', 'error');
        }
    } catch (e) {
        showToast('Network error', 'error');
    }
}
