from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import sys
import os
import json
import logging
import subprocess
import threading
import uuid
from datetime import datetime

# Gemini AI Integration
from google import genai

# Add parent directory to path to import hackingtool modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the hackingtool module
from io import StringIO
old_stdout = sys.stdout
sys.stdout = StringIO()
try:
    from hackingtool import all_tools
finally:
    sys.stdout = old_stdout

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hackerdex_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

logging.basicConfig(level=logging.INFO)

# Job tracking storage
jobs = {}

# Gemini Configuration
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
GEMINI_MODEL = 'gemini-2.5-pro'

def get_gemini_client():
    """Get configured Gemini client."""
    if GEMINI_API_KEY:
        try:
            return genai.Client(api_key=GEMINI_API_KEY)
        except Exception:
            return None
    return None

# Tool command mappings
TOOL_COMMANDS = {
    "Network Map (nmap)": "nmap -sV {target}",
    "Nmap": "nmap -sV {target}",
    "SQLMap": "sqlmap -u {target} --batch --dbs",
    "sqlmap": "sqlmap -u {target} --batch --dbs",
    "katana": "katana -u {target} -jc",
    "Katana": "katana -u {target} -jc",
    "gospider": "gospider -s {target} -d 2",
    "Gospider": "gospider -s {target} -d 2",
    "arjun": "arjun -u {target}",
    "Arjun": "arjun -u {target}",
    "ffuf": "ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
    "WhatWeb": "whatweb {target}",
    "nikto": "nikto -h {target}",
}

def load_all_tools():
    """Introspects the all_tools list from hackingtool.py"""
    catalog = {}
    for category in all_tools:
        cat_name = getattr(category, 'TITLE', 'Unknown Category')
        tools_list = []
        if hasattr(category, 'TOOLS'):
            for tool in category.TOOLS:
                if hasattr(tool, 'TITLE'):
                     tools_list.append(tool.TITLE)
        if tools_list:
            catalog[cat_name] = tools_list
    return catalog

def run_tool_with_streaming(job_id, command):
    """Execute a tool command and stream output via WebSocket."""
    try:
        jobs[job_id]['status'] = 'running'
        jobs[job_id]['started_at'] = datetime.now().isoformat()

        process = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        output_lines = []
        for line in iter(process.stdout.readline, ''):
            if line:
                output_lines.append(line)
                socketio.emit('scan_output', {'job_id': job_id, 'line': line})

        process.wait()

        jobs[job_id]['output'] = ''.join(output_lines)
        jobs[job_id]['status'] = 'completed'
        jobs[job_id]['exit_code'] = process.returncode

        socketio.emit('scan_complete', {
            'job_id': job_id,
            'status': 'completed',
            'exit_code': process.returncode
        })

    except Exception as e:
        jobs[job_id]['status'] = 'error'
        jobs[job_id]['output'] = str(e)
        socketio.emit('scan_error', {'job_id': job_id, 'error': str(e)})

    jobs[job_id]['ended_at'] = datetime.now().isoformat()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/tools')
def get_tools():
    return jsonify(load_all_tools())

@app.route('/api/scan', methods=['POST'])
def run_scan():
    data = request.json
    tool_name = data.get('tool')
    target = data.get('target')

    if not tool_name or not target:
        return jsonify({"error": "Missing tool or target"}), 400

    command_template = TOOL_COMMANDS.get(tool_name)

    if not command_template:
        return jsonify({
            "status": "error",
            "message": f"Tool '{tool_name}' not yet wired. Add it to TOOL_COMMANDS in app.py."
        }), 400

    command = command_template.format(target=target)
    job_id = str(uuid.uuid4())[:8]

    jobs[job_id] = {
        'tool': tool_name,
        'target': target,
        'command': command,
        'status': 'queued',
        'output': '',
    }

    thread = threading.Thread(target=run_tool_with_streaming, args=(job_id, command))
    thread.start()

    logging.info(f"Started job {job_id}: {command}")

    return jsonify({
        "status": "started",
        "job_id": job_id,
        "message": f"Launched: {command}"
    })

@app.route('/api/status/<job_id>')
def get_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)

@app.route('/api/jobs')
def list_jobs():
    return jsonify(jobs)

@app.route('/api/analyze', methods=['POST'])
def analyze_with_gemini():
    """Analyze scan output using Gemini 2.5 Pro."""
    data = request.json
    scan_output = data.get('output', '')
    tool_name = data.get('tool', 'Unknown')
    target = data.get('target', 'Unknown')

    if not scan_output:
        return jsonify({"error": "No scan output provided"}), 400

    client = get_gemini_client()
    if not client:
        return jsonify({
            "error": "Gemini API key not configured. Set GEMINI_API_KEY environment variable."
        }), 400

    try:
        prompt = f"""You are a cybersecurity expert analyzing scan results.

**Scan Tool:** {tool_name}
**Target:** {target}

**Scan Output:**
```
{scan_output[:8000]}
```

**Your Task:**
1. **Summary:** Briefly summarize what the scan found (2-3 sentences)
2. **Vulnerabilities:** List any security issues discovered (if any)
3. **Risk Level:** Rate the overall risk (Low/Medium/High/Critical)
4. **Recommendations:** Provide 2-3 actionable security recommendations

Format your response in markdown with clear headers."""

        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt
        )

        return jsonify({
            "status": "success",
            "analysis": response.text,
            "model": GEMINI_MODEL
        })

    except Exception as e:
        logging.error(f"Gemini API error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/gemini-status')
def gemini_status():
    """Check if Gemini API is configured."""
    configured = bool(GEMINI_API_KEY)
    return jsonify({
        "configured": configured,
        "model": GEMINI_MODEL if configured else None
    })

@socketio.on('connect')
def handle_connect():
    logging.info('Client connected via WebSocket')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)
