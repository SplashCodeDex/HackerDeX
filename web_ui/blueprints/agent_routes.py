from flask import Blueprint, jsonify, request
from extensions import socketio
from managers import store, executor, get_gemini_client, GEMINI_MODEL, SAFETY_SETTINGS
from blueprints.scans import TOOL_COMMANDS
import json
import logging

agent_bp = Blueprint('agent', __name__)

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

    # Available tools context (Enriched)
    tools_context = """
- nmap: Network Mapper. Use for port scanning and service detection.
- nikto: Web Server Scanner. Use for finding web server vulnerabilities.
- sqlmap: SQL Injection Tool. Use for testing database injection points.
- whatweb: Web Technology Identifier. Use to fingerprint the target.
- arjun: HTTP Parameter Discovery. Use to find hidden parameters.
- ffuf: Fuzz Faster U Fool. Use for directory and file fuzzing.
- katana: Web Crawler. Use to index the target website.
- gospider: Fast Web Spider. Use for uncovering subdomains and URLs.
"""

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
            contents=prompt,
            config={'safety_settings': SAFETY_SETTINGS}
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

            # Stream output line by line using ToolExecutor
            output_lines = []
            for line in executor.run_async(command):
                output_lines.append(line)
                socketio.emit('agent_update', {'message': line.strip(), 'type': 'tool_output'})

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


@agent_bp.route('/api/autopilot', methods=['POST'])
def run_autopilot():
    data = request.json
    goal = data.get('goal')
    target = data.get('target')

    if not goal or not target:
        return jsonify({"error": "Goal and target required"}), 400

    # Start agent in background with eventlet-safe method
    socketio.start_background_task(run_agent_background, goal, target)

    return jsonify({"status": "started", "message": "Agent is thinking..."})
