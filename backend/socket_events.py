from flask_socketio import SocketIO

socketio = SocketIO(cors_allowed_origins="*")

def emit_new_log(log_dict):
    """Broadcast a new log to all connected clients."""
    socketio.emit('new_log', log_dict)

def emit_new_alert(alert_dict):
    """Broadcast a new alert to all connected clients."""
    socketio.emit('new_alert', alert_dict)