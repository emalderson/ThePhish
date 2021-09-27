# Class used for logging with different levels of severity
# The constructor takes the socketio object and the socket id of the client to send logs to
class WebSocketLogger:

	def __init__(self, socketio, sid):
		self.socketio = socketio
		self.sid = sid

	def emit_info(self, message):
		self.socketio.emit("logInfo", message, to = self.sid)

	def emit_warning(self, message):
		self.socketio.emit("logWarning", message, to = self.sid)

	def emit_error(self, message):
		self.socketio.emit("logError", message, to = self.sid)