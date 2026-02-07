from flask_socketio import SocketIO

# Initialize SocketIO with Eventlet for async support
socketio = SocketIO(cors_allowed_origins="*", async_mode='eventlet')
