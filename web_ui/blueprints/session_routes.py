from flask import Blueprint, jsonify, request
from extensions import socketio
from managers import session_store, listener_mgr
from session_store import SessionStatus, SessionType

session_bp = Blueprint('sessions', __name__)

@session_bp.route('/api/sessions')
def list_sessions():
    """List all sessions with optional filters."""
    status_filter = request.args.get('status')
    type_filter = request.args.get('type')
    target_filter = request.args.get('target')

    status = SessionStatus(status_filter) if status_filter else None
    sess_type = SessionType(type_filter) if type_filter else None

    sessions = session_store.list_sessions(status=status, session_type=sess_type, target_ip=target_filter)
    return jsonify({
        'sessions': [s.to_dict() for s in sessions],
        'summary': session_store.get_summary()
    })

@session_bp.route('/api/sessions/<session_id>')
def get_session(session_id):
    """Get a specific session."""
    session = session_store.get_session(session_id)
    if not session:
        return jsonify({'error': 'Session not found'}), 404
    return jsonify(session.to_dict())

@session_bp.route('/api/sessions/<session_id>', methods=['DELETE'])
def delete_session(session_id):
    """Delete a session."""
    if session_store.remove_session(session_id):
        return jsonify({'status': 'deleted', 'session_id': session_id})
    return jsonify({'error': 'Session not found'}), 404

@session_bp.route('/api/sessions/<session_id>/command', methods=['POST'])
def send_session_command(session_id):
    """Send a command to an active session."""
    data = request.json or {}
    command = data.get('command', '')

    if not command:
        return jsonify({'error': 'No command provided'}), 400

    if listener_mgr.send_to_session(session_id, command):
        return jsonify({'status': 'sent', 'command': command})
    return jsonify({'error': 'Session not connected or not interactive'}), 400

@session_bp.route('/api/sessions/<session_id>/output')
def get_session_output(session_id):
    """Get buffered output from a session."""
    output = listener_mgr.get_session_output(session_id)
    return jsonify({'session_id': session_id, 'output': output})

@session_bp.route('/api/listeners')
def list_listeners():
    """List all active listeners."""
    return jsonify({
        'listeners': listener_mgr.list_listeners(),
        'stored': session_store.list_listeners()
    })

@session_bp.route('/api/listeners', methods=['POST'])
def start_listener():
    """Start a new listener."""
    data = request.json or {}
    port = data.get('port')
    protocol = data.get('protocol', 'tcp')
    bind_ip = data.get('bind_ip', '0.0.0.0')

    if not port:
        return jsonify({'error': 'Port is required'}), 400

    def on_connection(conn):
        socketio.emit('new_connection', {
            'conn_id': conn.conn_id,
            'client_ip': conn.client_ip,
            'session_id': conn.session_id,
            'listener_port': conn.listener_port
        })

    if listener_mgr.start_listener(int(port), protocol, bind_ip, on_connection):
        return jsonify({'status': 'started', 'port': port, 'protocol': protocol})
    return jsonify({'error': f'Failed to start listener on port {port}'}), 400

@session_bp.route('/api/listeners/<int:port>', methods=['DELETE'])
def stop_listener(port):
    """Stop a listener."""
    if listener_mgr.stop_listener(port):
        return jsonify({'status': 'stopped', 'port': port})
    return jsonify({'error': f'No listener on port {port}'}), 404

# ==================== SOCKET.IO HANDLERS ====================

@socketio.on('session_input')
def handle_session_input(data):
    """Handle input from the xterm.js terminal."""
    session_id = data.get('session_id')
    command = data.get('input')

    if session_id and command:
        # Send raw input to the session (no newline appended here, client handles it)
        # However, for convenience with xterm, we might want to just send distinct commands or chars.
        # For a true raw shell, we send characters. For this implementation, we'll send robust commands.
        # Let's check if the command ends with \r (Enter key from xterm)
        listener_mgr.send_to_session(session_id, command)
