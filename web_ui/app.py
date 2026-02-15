# Gevent monkey patching MUST be first for thread-safe SocketIO
from gevent import monkey
monkey.patch_all()

from flask import Flask, render_template
from extensions import socketio
import logging
import os
import sys
import platform

if sys.platform != "linux":
    print("[!] This web interface is designed for Linux (Kali/Parrot/Ubuntu/Arch).")
    print(f"[!] Detected OS: {platform.system()} ({sys.platform})")
    print("[!] Please run inside WSL2, VirtualBox, or a native Linux environment.")
    sys.exit(1)

# Add parent directory to path to import hackingtool modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import shared managers (ensure they are initialized)
import managers

# The auto_updater will be started in the main block
from cve_auto_updater import auto_updater

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
    # Start CVE auto-updater in background
    print("[*] Starting CVE auto-updater...")
    socketio.start_background_task(auto_updater.start)

    print("[*] HackerDeX Web UI starting at http://0.0.0.0:8080")
    socketio.run(app, host='0.0.0.0', port=8080, debug=False)
