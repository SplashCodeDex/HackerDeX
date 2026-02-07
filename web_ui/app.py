# Eventlet monkey patching MUST be first for thread-safe SocketIO
import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template
from extensions import socketio
import logging
import os
import sys

# Add parent directory to path to import hackingtool modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import shared managers (ensure they are initialized)
import managers

# Import Blueprints
from blueprints.scans import scans_bp
from blueprints.intel_routes import intel_bp
from blueprints.agent_routes import agent_bp
from blueprints.session_routes import session_bp
from blueprints.payload_routes import payload_bp

app = Flask(__name__)
app.config['SECRET_KEY'] = 'hackerdex_secret_key'

# Initialize SocketIO
socketio.init_app(app)

# Register Blueprints
app.register_blueprint(scans_bp)
app.register_blueprint(intel_bp)
app.register_blueprint(agent_bp)
app.register_blueprint(session_bp)
app.register_blueprint(payload_bp)

logging.basicConfig(level=logging.INFO)

@app.route('/')
def index():
    # Use the new modular template
    return render_template('index_modular.html')

@socketio.on('connect')
def handle_connect():
    logging.info('Client connected via WebSocket')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)
