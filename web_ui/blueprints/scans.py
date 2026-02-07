from flask import Blueprint, jsonify, request
from extensions import socketio
from managers import jobs, jobs_lock, executor, store, load_all_tools
from context_injector import injector
from parsers.registry import registry
from session_parsers import SessionParserRegistry
import logging
import uuid
import datetime
import os

# Define Blueprint
scans_bp = Blueprint('scans', __name__)

# Stealth Mode Configuration
PROXY_MODE = os.environ.get('PROXY_MODE', 'false').lower() == 'true'
PROXY_CMD_PREFIX = "proxychains4 -f /root/hackingtool/proxychains.conf " if PROXY_MODE else ""

# Tool command mappings - Comprehensive (55+ Tools)
# (Copying the TOOL_COMMANDS dictionary from app.py)
TOOL_COMMANDS = {
    # --- Information Gathering ---
    "Network Map (nmap)": "nmap -sV -oX - {target}",
    "Nmap": "nmap -sV -oX - {target}",
    "Dracnmap": "sudo ./Dracnmap/dracnmap-v2.2.sh {target}",
    "Port Scanning": "nmap -O -Pn {target}",
    "Host to IP": "host {target}",
    "Xerosploit": "sudo xerosploit",
    "RED HAWK (All In One Scanning)": "cd RED_HAWK && php rhawk.php",
    "ReconSpider(For All Scanning)": "cd reconspider && python3 reconspider.py",
    "IsItDown (Check Website Down/Up)": "curl -I {target}",
    "Infoga - Email OSINT": "cd Infoga && python3 infoga.py --target {target}",
    "ReconDog": "cd ReconDog && sudo python dog",
    "Striker": "cd Striker && python3 striker.py {target}",
    "SecretFinder (like API & etc)": "cd SecretFinder && python3 SecretFinder.py -i {target} -o output.html",
    "Find Info Using Shodan": "python3 Shodanfy.py {target}",
    "Port Scanner - rang3r": "cd rang3r && python rang3r.py --ip {target}",
    "Breacher": "cd Breacher && python3 breacher.py -u {target}",

    # --- SQL Injection ---
    "SQLMap": "sqlmap -u {target} --batch --dbs",
    "sqlmap": "sqlmap -u {target} --batch --dbs",
    "NoSQLMap": "python NoSQLMap/NoSQLMap.py",
    "Damn Small SQLi Scanner": "python3 dsss.py -u {target}",
    "Explo": "./explo/explo -u {target} -w /usr/share/wordlists/dirb/common.txt",
    "Leviathan": "cd leviathan && python leviathan.py -u {target}",

    # --- Web Attacks ---
    "Web2Attack": "python3 Web2Attack/w2aconsole.py",
    "Skipfish": "skipfish -o skipfish_output {target}",
    "SubDomain Finder": "python3 Sublist3r/sublist3r.py -d {target}",
    "CheckURL": "python3 CheckURL/checkurl.py --url {target}",
    "Blazy": "python3 Blazy/blazy.py",
    "Sub-Domain TakeOver": "python3 subover/subover.py",
    "Dirb": "dirb {target}",

    # --- XSS Attacks ---
    "XSS-Strike": "python3 XSStrike/xsstrike.py -u {target}",
    "XSS-Freak": "python3 XSS-Freak/xss_freak.py",
    "Xerxes": "gcc Xerxes/xerxes.c -o xerxes && ./xerxes {target} 80",

    # --- DDOS ---
    "SlowLoris": "python3 slowloris.py {target}",
    "Asyncrone | Multifunction SYN Flood DDoS Weapon": "python3 a3.py",
    "UFOnet": "sudo python3 ufonet/ufonet",
    "GoldenEye": "python3 GoldenEye/goldeneye.py {target}",

    # --- Post Exploitation ---
    "Vegile - Ghost In The Shell": "cd Vegile && ./Vegile",
    "Chrome Keylogger": "python3 chrome-keylogger/install.py",

    # --- Wireless Attacks ---
    "WiFi-Pumpkin": "wifipumpkin3",
    "Fluxion": "sudo ./fluxion/fluxion.sh",
    "Wifite": "sudo wifite",

    # --- Wordlist Generator ---
    "Cupp": "python3 cupp/cupp.py -i",
    "WordlistCreator": "python3 WordlistCreator/wlc.py",

    # --- Forensics ---
    "Bulk_extractor": "bulk_extractor -o output {target}",

    # --- Modern Tools (Added externally) ---
    "katana": "katana -u {target} -jc",
    "Katana": "katana -u {target} -jc",
    "gospider": "gospider -s {target} -d 2",
    "Gospider": "gospider -s {target} -d 2",
    "arjun": "arjun -u {target}",
    "Arjun": "arjun -u {target}",
    "ffuf": "ffuf -u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt",
    "WhatWeb": "whatweb {target}",
    "nikto": "nikto -h {target} -Format xml -o -",
    "theHarvester": "theHarvester -d {target} -b all",
    "TheHarvester": "theHarvester -d {target} -b all",
}

def run_tool_with_streaming(job_id, command):
    """Execute a tool command and stream output via WebSocket using ToolExecutor."""
    try:
        jobs[job_id]['status'] = 'running'
        jobs[job_id]['started_at'] = datetime.datetime.now().isoformat()

        output_lines = []
        for line in executor.run_async(command):
            output_lines.append(line)
            socketio.emit('scan_output', {'job_id': job_id, 'line': line})

        full_output = ''.join(output_lines)
        jobs[job_id]['output'] = full_output
        jobs[job_id]['status'] = 'completed'
        jobs[job_id]['exit_code'] = executor.last_process.returncode if executor.last_process else 0

        # --- VulnStore Integration: Parse Output ---
        try:
            target = jobs[job_id].get('target')
            tool_name = jobs[job_id].get('tool')
            tid = store.get_or_create_target(target)

            parsed = registry.parse_output(full_output, tool_name, target)

            # Update Store
            for p in parsed.ports:
                store.add_port(tid, p.port, p.protocol, p.service, p.version)

            for v in parsed.vulns:
                store.add_vulnerability(
                    tid, v.title, v.severity, v.details, v.affected_url, tool_name,
                    source_layer=v.source_layer,
                    privilege_level=v.privilege_level,
                    strategic_advantage=v.strategic_advantage,
                    confidence=v.confidence
                )

            for url in parsed.urls:
                store.add_url(tid, url, tool="Generic" if "nmap" not in tool_name.lower() else tool_name)

            for tech in parsed.technologies:
                store.add_technology(tid, tech.name, tech.version)

            if parsed.dns_info:
                store.update_dns_info(tid, parsed.dns_info)

            if parsed.osint_info:
                store.update_osint_info(tid, parsed.osint_info)

            socketio.emit('store_updated', {'target_id': tid, 'message': f'Intel updated from {tool_name}'})

            # --- Session Auto-Detection (Phase 15 C2 Core) ---
            detected_sessions = SessionParserRegistry.auto_detect_and_store(
                tool_name=tool_name,
                output=full_output,
                target_ip=target,
                vuln_id=tid
            )
            if detected_sessions:
                socketio.emit('session_detected', {
                    'session_ids': detected_sessions,
                    'tool': tool_name,
                    'count': len(detected_sessions)
                })

        except Exception as pe:
            logging.error(f"Parsing error for job {job_id}: {pe}")

        socketio.emit('scan_complete', {
            'job_id': job_id,
            'status': 'completed',
            'exit_code': executor.last_process.returncode if executor.last_process else 0
        })

    except Exception as e:
        jobs[job_id]['status'] = 'error'
        jobs[job_id]['output'] = str(e)
        socketio.emit('scan_error', {'job_id': job_id, 'error': str(e)})

    jobs[job_id]['ended_at'] = datetime.datetime.now().isoformat()

@scans_bp.route('/api/tools')
def get_tools():
    return jsonify(load_all_tools())

@scans_bp.route('/api/scan', methods=['POST'])
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

    # Apply ProxyChains if enabled
    if PROXY_MODE and "proxychains" not in command:
        command = f"{PROXY_CMD_PREFIX}{command}"

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

@scans_bp.route('/api/status/<job_id>')
def get_status(job_id):
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)

@scans_bp.route('/api/jobs')
def list_jobs():
    return jsonify(jobs)
