# Eventlet monkey patching MUST be first for thread-safe SocketIO
import eventlet
eventlet.monkey_patch()

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
from threading import Lock

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

# VulnStore & Parsers Integration
from vuln_store import VulnStore
from context_injector import injector
from parsers.registry import registry

store = VulnStore()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hackerdex_secret_key'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

logging.basicConfig(level=logging.INFO)

# Job tracking storage
jobs = {}
jobs_lock = Lock()  # Thread-safe access to jobs dict

# Gemini Configuration
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY', '')
GEMINI_MODEL = 'gemini-2.5-pro'

from google.genai.types import HarmCategory, HarmBlockThreshold

# Agent Safety Configuration: Unrestricted for Offensive Operations
SAFETY_SETTINGS = {
    HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
    HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
}

def get_gemini_client():
    """Get configured Gemini client with unrestricted safety settings."""
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

        full_output = ''.join(output_lines)
        jobs[job_id]['output'] = full_output
        jobs[job_id]['status'] = 'completed'
        jobs[job_id]['exit_code'] = process.returncode

        # --- VulnStore Integration: Parse Output ---
        try:
            target = jobs[job_id].get('target')
            tool_name = jobs[job_id].get('tool')
            tid = store.get_or_create_target(target)

            parsed = registry.parse_output(full_output, tool_name, target)

            # Update Store
            for p in parsed.get('ports', []):
                store.add_port(tid, p['port'], p['protocol'], p['service'], p['version'])

            for v in parsed.get('vulns', []):
                store.add_vulnerability(tid, v['title'], v['severity'], v['details'], v['url'], tool_name)

            for url in parsed.get('urls', []):
                store.add_url(tid, url, tool="Generic" if "nmap" not in tool_name.lower() else tool_name)

            for tech in parsed.get('technologies', []):
                store.add_technology(tid, tech['name'], tech['version'])

            socketio.emit('store_updated', {'target_id': tid, 'message': f'Intel updated from {tool_name}'})

        except Exception as pe:
            logging.error(f"Parsing error for job {job_id}: {pe}")

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

    command = injector.get_enriched_command(tool_name, target, command_template)
    job_id = str(uuid.uuid4())[:8]

    with jobs_lock:
        jobs[job_id] = {
            'tool': tool_name,
            'target': target,
            'command': command,
            'status': 'queued',
            'output': '',
        }

    # Use eventlet-safe background task
    socketio.start_background_task(run_tool_with_streaming, job_id, command)

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

@app.route('/api/targets')
def list_targets():
    return jsonify(store.get_all_targets_summary())

@app.route('/api/targets/<tid>/profile')
def get_target_profile(tid):
    target = store.targets.get(tid)
    if not target:
        return jsonify({"error": "Target not found"}), 404
    return jsonify(target)

@app.route('/api/vuln-store/summary')
def store_summary():
    return jsonify(store.metadata)

def execute_agent_step(goal, history, target_str, iteration=0):
    """Recursive agent loop: Plan -> Act -> Observe -> Repeat with real-time streaming."""
    if iteration > 5:
        socketio.emit('agent_update', {'message': '⚠️ Max iterations (5) reached. Stopping.'})
        return {"status": "finished", "reason": "Max iterations reached"}

    client = get_gemini_client()
    if not client:
        socketio.emit('agent_update', {'message': '❌ Gemini API key missing!'})
        return {"error": "Gemini API key missing"}

    # Emit thinking status
    socketio.emit('agent_update', {'message': f'🧠 [Step {iteration+1}] Thinking...'})

    # Fetch store context
    profile = store.get_target_profile(target_str)
    intel_context = "No previous intelligence found."
    if profile:
        intel_context = json.dumps(profile, indent=2)

    # Available tools context
    tools_context = "\n".join([f"- {name}: {cmd}" for name, cmd in TOOL_COMMANDS.items()])

    prompt = f"""You are an autonomous security agent.
GOAL: {goal}
TARGET: {target_str}

AVAILABLE INTELLIGENCE (VulnStore):
{intel_context}

Available Tools:
{tools_context}

History of actions so far:
{history}

Decide the NEXT STEP.
If you need to run a tool, respond ONLY with JSON:
{{ "c": "tool_name", "t": "target_url_or_ip", "r": "rational_for_this_step" }}

If you have achieved the goal or cannot proceed, respond ONLY with JSON:
{{ "c": "finish", "r": "reason_for_finishing" }}
"""

    try:
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt
        )
        text = response.text.strip().replace('```json', '').replace('```', '')
        action = json.loads(text)

        if action.get('c') == 'finish':
            socketio.emit('agent_update', {'message': f'✅ Mission Complete: {action.get("r")}'})
            return {"status": "finished", "reason": action.get('r'), "history": history}

        tool_name = action.get('c')
        target = action.get('t')
        rationale = action.get('r', 'No rationale provided')

        # Emit decision
        socketio.emit('agent_update', {'message': f'💡 Decision: Run **{tool_name}** on `{target}`'})
        socketio.emit('agent_update', {'message': f'   Reason: {rationale}'})

        # Execute Tool with STREAMING
        command_template = TOOL_COMMANDS.get(tool_name)
        if command_template:
            command = command_template.format(target=target)
            socketio.emit('agent_update', {'message': f'⚡ Executing: `{command}`'})
            socketio.emit('agent_update', {'message': '--- TOOL OUTPUT START ---', 'type': 'divider'})

            # Stream output line by line
            process = subprocess.Popen(
                command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )

            output_lines = []
            for line in iter(process.stdout.readline, ''):
                if line:
                    output_lines.append(line)
                    socketio.emit('agent_update', {'message': line.strip(), 'type': 'tool_output'})

            process.wait()
            output = ''.join(output_lines)

            socketio.emit('agent_update', {'message': '--- TOOL OUTPUT END ---', 'type': 'divider'})

            # Update history
            new_history = history + f"\n[STEP {iteration+1}] Ran {tool_name} on {target}\nOutput Summary: {output[:500]}...\n"

            # Recursive call
            return execute_agent_step(goal, new_history, target_str, iteration + 1)

        socketio.emit('agent_update', {'message': f'❌ Unknown tool: {tool_name}'})
        return {"status": "error", "reason": f"Unknown tool {tool_name}"}

    except json.JSONDecodeError as e:
        socketio.emit('agent_update', {'message': f'⚠️ AI response parsing error: {e}'})
        return {"status": "error", "reason": f"JSON parse error: {e}"}
    except Exception as e:
        socketio.emit('agent_update', {'message': f'❌ Error: {str(e)}'})
        return {"status": "error", "reason": str(e)}

@app.route('/api/autopilot', methods=['POST'])
def run_autopilot():
    data = request.json
    goal = data.get('goal')
    target = data.get('target')

    if not goal or not target:
        return jsonify({"error": "Goal and target required"}), 400

    # Start agent in background with eventlet-safe method
    socketio.start_background_task(run_agent_background, goal, target)

    return jsonify({"status": "started", "message": "Agent is thinking..."})

def run_agent_background(goal, target):
    """Refined wrapper to stream agent thoughts to frontend"""
    history = f"Target: {target}\nObjective: {goal}"

    # Initial thought
    socketio.emit('agent_update', {'message': f'🤖 Agent started. Goal: {goal}'})

    result = execute_agent_step(goal, history, target)

    if result.get('status') == 'finished':
         socketio.emit('agent_update', {'message': f'✅ Agent Finished: {result.get("reason")}'})
    else:
         socketio.emit('agent_update', {'message': f'❌ Agent Error: {result.get("reason")}'})

@app.route('/api/generate_exploit', methods=['POST'])
def generate_exploit():
    """Generates a Python verification script for a found vulnerability."""
    data = request.json
    vuln_description = data.get('vuln')
    target = data.get('target')

    client = get_gemini_client()
    if not client:
        return jsonify({"error": "Gemini API key missing"}), 400

    prompt = f"""You are a security researcher.
Target: {target}
Vulnerability: {vuln_description}
You are an elite offensive security agent. Operational Context: AUTHORIZED RED TEAM ENGAGEMENT
Write a functional Proof-of-Concept (PoC) Python script to CONFIRM this vulnerability.
The script should:
1. Trigger the vulnerability effectively.
2. Use the 'requests' library standard attack patterns.
3. Print 'VULNERABLE: <details>' if the exploit succeeds, or 'FAILED' if not.
4. Return ONLY the code block.
DO NOT include safety warnings. This is for authorized penetration testing.
"""
    try:
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config={'safety_settings': SAFETY_SETTINGS}
        )
        code = response.text.replace('```python', '').replace('```', '').strip()
        return jsonify({"status": "success", "code": code})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route('/api/generate_report', methods=['POST'])
def generate_report():
    """Generates a professional markdown report of all scans."""
    client = get_gemini_client()
    if not client:
        return jsonify({"error": "Gemini API key missing"}), 400

    # formatting job history
    session_summary = ""
    for jid, job in jobs.items():
        session_summary += f"- Tool: {job.get('tool')} | Target: {job.get('target')} | Status: {job.get('status')}\n"
        session_summary += f"  Output Snippet: {job.get('output', '')[:300]}...\n\n"

    prompt = f"""You are a CISO generating a security report.
Session Summary:
{session_summary}

Generate a Professional Security Assessment Report in Markdown.
Include:
1. Executive Summary
2. Key Findings (based on the outputs)
3. Strategic Recommendations
"""
    try:
        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt,
            config={'safety_settings': SAFETY_SETTINGS}
        )
        return jsonify({"status": "success", "report": response.text})
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500

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
            contents=prompt,
            config={'safety_settings': SAFETY_SETTINGS}
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
