from flask_socketio import SocketIO

# Initialize SocketIO with Gevent for async support
socketio = SocketIO(cors_allowed_origins="*", async_mode='gevent')
