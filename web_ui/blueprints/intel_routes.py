from flask import Blueprint, jsonify, request
from extensions import socketio
from managers import store, jobs, get_gemini_client, GEMINI_MODEL, SAFETY_SETTINGS
from attack_pather import AttackPather
from next_best_action import NextBestActionEngine
import logging

intel_bp = Blueprint('intel', __name__)

@intel_bp.route('/api/intel/attack-paths', methods=['POST'])
def get_attack_paths():
    """Generates strategic attack path analysis."""
    client = get_gemini_client()
    if not client:
        return jsonify({"error": "Gemini API key missing"}), 400
    
    pather = AttackPather(client, store)
    analysis = pather.analyze_attack_paths()
    return jsonify({"status": "success", "analysis": analysis})

@intel_bp.route('/api/intel/next-action', methods=['POST'])
def get_next_action():
    """Suggests the next best action for a target."""
    data = request.json
    target = data.get('target')
    if not target:
        return jsonify({"error": "Missing target"}), 400

    client = get_gemini_client()
    if not client:
        return jsonify({"error": "Gemini API key missing"}), 400
    
    engine = NextBestActionEngine(client, store)
    suggestion = engine.suggest_next_action(target)
    return jsonify(suggestion)

@intel_bp.route('/api/targets')
def list_targets():
    return jsonify(store.get_all_targets_summary())

@intel_bp.route('/api/intel/prioritized-vulns')
def prioritized_vulns():
    """Returns a globally prioritized list of vulnerabilities."""
    return jsonify(store.get_prioritized_vulnerabilities())

@intel_bp.route('/api/targets/<tid>/profile')
def get_target_profile(tid):
    target = store.targets.get(tid)
    if not target:
        return jsonify({"error": "Target not found"}), 404
    return jsonify(target)

@intel_bp.route('/api/vuln-store/summary')
def store_summary():
    return jsonify(store.metadata)

@intel_bp.route('/api/generate_report', methods=['POST'])
def generate_report():
    """Generates a professional markdown report of all scans."""
    client = get_gemini_client()
    if not client:
        return jsonify({"error": "Gemini API key missing"}), 400

    # formatting job history
    # Retrieve simplified session summary
    session_summary = ""
    target_ids = set()

    # 1. Collect Target IDs from recent jobs
    for jid, job in jobs.items():
        if job.get('status') == 'completed':
            t = job.get('target')
            # Find TID for this target
            tid = store.get_or_create_target(t)
            target_ids.add(tid)
            session_summary += f"- Tool: {job.get('tool')} | Target: {t}\n"

    # 2. Enrich with High-Fidelity Data from VulnStore
    full_technical_context = ""
    for tid in target_ids:
        target_card = store.get_target(tid)
        full_technical_context += f"\n--- Target: {target_card['address']} ---\n"
        full_technical_context += f"Open Ports: {len(target_card['ports'])}\n"
        for p in target_card['ports']:
            full_technical_context += f"  - Port {p['port']}/{p['protocol']}: {p['service']} {p['version']}\n"

        full_technical_context += f"Vulnerabilities: {len(target_card['vulns'])}\n"
        for v in target_card['vulns']:
            full_technical_context += f"  - [{v['severity'].upper()}] {v['title']}\n    Details: {v['details'][:200]}...\n"

        full_technical_context += f"Technologies: {', '.join([t['name'] + ' ' + t['version'] for t in target_card['technologies']])}\n"

    prompt = f"""You are a Lead Penetration Tester generating a Final Engagement Report.
SESSION SCOPE:
{session_summary}

TECHNICAL FINDINGS (High Fidelity):
{full_technical_context}

GENERATE A PROFESSIONAL PENTEST REPORT (Markdown).
The report must include:
1. **Executive Summary**: High-level risk assessment for stakeholders.
2. **Attack Surface Analysis**: Breakdown of open ports and identified technologies (CPEs).
3. **Critical Findings**: Detailed analysis of top vulnerabilities (use the technical context).
4. **Exploitation Paths**: Theoretical attack vectors based on the findings (e.g., "The outdated Apache 2.4.49 on port 80 is vulnerable to Path Traversal (CVE-2021-41773)...").
5. **Remediation Strategy**: Concrete steps to fix the issues.

Format: Clean Markdown with headers, lists, and code blocks for technical details.
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

@intel_bp.route('/api/analyze', methods=['POST'])
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

@intel_bp.route('/api/generate_exploit', methods=['POST'])
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

@intel_bp.route('/api/gemini-status')
def gemini_status():
    """Check if Gemini API is configured."""
    client = get_gemini_client()
    configured = client is not None
    return jsonify({
        "configured": configured,
        "model": GEMINI_MODEL if configured else None
    })
