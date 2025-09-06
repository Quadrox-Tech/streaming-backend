from flask import Flask, jsonify

# Initialize the Flask application
app = Flask(__name__)

# This is a simple "route" or "endpoint"
# When we visit our server's main URL, this function will run
@app.route('/')
def status():
    # Return a JSON response to confirm the server is online
    return jsonify({"status": "Streaming server is online"})

# This part allows us to run the app
if __name__ == '__main__':
    # We'll let Gunicorn run this in production, but this is good for testing
    app.run(host='0.0.0.0', port=8000)
