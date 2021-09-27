import flask
import flask_socketio
import list_emails
import case_from_email
import run_analysis
import eventlet
from ws_logger import WebSocketLogger

# Monkeypatches the standard library to replace its key elements with green equivalents (greenlets)
# This is needed for websocket to work and avoid falling back to long polling
eventlet.monkey_patch()

app = flask.Flask(__name__)
socketio = flask_socketio.SocketIO(app)

# The main page
@app.route("/")
def homepage():
	return flask.render_template("index.html")

@app.route('/list', methods = ['GET'])
def obtain_emails_to_analyze():
	# Obtain the list of emails
	emails_info = list_emails.main()
	response = flask.jsonify(emails_info)
	return response

# Analyze the email and obtain the verdict
@app.route('/analysis', methods = ['POST'])
def analyze_email():
	# UID of the email to analyze and sid of the client obtained from the request
	mail_uid = flask.escape(flask.request.form.get("mailUID"))
	sid_client = flask.escape(flask.request.form.get("sid"))
	# Instantiate the object used for logging by the other modules
	wsl = WebSocketLogger(socketio, sid_client)
	# Call the modules used to create the case and run the analysis
	new_case_id, external_from_field = case_from_email.main(wsl, mail_uid)
	verdict = run_analysis.main(wsl, new_case_id, external_from_field)
	response = flask.jsonify(verdict)
	return response

# If eventlet or gevent are installed, their wsgi server will be used
# else Werkzeug will be used
if __name__ == "__main__":
	socketio.run(app, host='0.0.0.0', port=8080)

