from flask import Blueprint, jsonify, request
from extensions import socketio
from managers import store
from agent_manager import agent_manager
import logging

agent_bp = Blueprint('agent', __name__)

def run_agent_background(goal, target):
    """Refined wrapper to stream agent thoughts to frontend"""

    def update_callback(data):
        socketio.emit('agent_update', data)
        # Also log to console for debugging
        if data.get('type') != 'tool_output':
             print(f"[AGENT] {data.get('message')}")

    try:
        agent_manager.run_mission(goal, target, update_callback)
    except Exception as e:
        socketio.emit('agent_update', {'message': f'❌ Agent Crash: {str(e)}'})
        logging.error(f"Agent Crash: {e}")

@agent_bp.route('/api/autopilot/stop', methods=['POST'])
def stop_autopilot():
    agent_manager.stop_mission()
    return jsonify({"status": "stopped", "message": "Kill switch activated. Mission stopping."})

@agent_bp.route('/api/autopilot/reasoning')
def get_reasoning_history():
    return jsonify(agent_manager.logger.get_history())

@agent_bp.route('/api/autopilot', methods=['POST'])
def run_autopilot():
    data = request.json
    goal = data.get('goal')
    target = data.get('target')

    if not goal or not target:
        return jsonify({"error": "Goal and target required"}), 400

    # Start agent in background with eventlet-safe method
    socketio.start_background_task(run_agent_background, goal, target)

    return jsonify({"status": "started", "message": "Mastermind Agent activated."})
