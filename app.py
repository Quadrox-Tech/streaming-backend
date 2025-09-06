import os
import subprocess
import shlex
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow

# Initialize the application
app = Flask(__name__)

# --- Global variable to hold the FFmpeg process ---
stream_process = None

# --- Database Configuration ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)
# --- End of Configuration ---


# --- Database Model ---
class StreamKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    key = db.Column(db.String(200), unique=True, nullable=False)

    def __init__(self, platform, name, key):
        self.platform = platform
        self.name = name
        self.key = key
# --- End of Model ---


# --- API Schema ---
class StreamKeySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = StreamKey
        load_instance = True
# --- End of Schema ---


# --- API Endpoints for Key Management ---
@app.route('/api/keys', methods=['POST'])
def add_key():
    # ... (code is unchanged)
    platform = request.json.get('platform')
    name = request.json.get('name')
    key = request.json.get('key')
    if not all([platform, name, key]):
        return jsonify({"error": "Missing data"}), 400
    new_key = StreamKey(platform, name, key)
    db.session.add(new_key)
    db.session.commit()
    key_schema = StreamKeySchema()
    return jsonify(key_schema.dump(new_key))

@app.route('/api/keys', methods=['GET'])
def get_keys():
    # ... (code is unchanged)
    all_keys = StreamKey.query.all()
    keys_schema = StreamKeySchema(many=True)
    return jsonify(keys_schema.dump(all_keys))

@app.route('/api/keys/<int:id>', methods=['DELETE'])
def delete_key(id):
    # ... (code is unchanged)
    key = StreamKey.query.get(id)
    if not key:
        return jsonify({"error": "Key not found"}), 404
    db.session.delete(key)
    db.session.commit()
    return jsonify({"message": "Key deleted successfully"})
# --- End of Key Management Endpoints ---


# --- API Endpoints for Streaming Control ---
@app.route('/api/stream/start', methods=['POST'])
def start_stream():
    global stream_process
    if stream_process and stream_process.poll() is None:
        return jsonify({"error": "A stream is already running"}), 400

    data = request.get_json()
    source_url = data.get('source_url')
    key_ids = data.get('key_ids')

    if not source_url or not key_ids:
        return jsonify({"error": "Missing source_url or key_ids"}), 400

    # Fetch stream keys from the database
    keys_to_use = StreamKey.query.filter(StreamKey.id.in_(key_ids)).all()
    if not keys_to_use:
        return jsonify({"error": "No valid stream keys found for the given IDs"}), 404

    # --- Build the FFmpeg Command ---
    # Base RTMP URLs for platforms
    rtmp_bases = {
        'youtube': 'rtmp://a.rtmp.youtube.com/live2/',
        'facebook': 'rtmps://live-api-s.facebook.com:443/rtmp/'
    }
    
    command = ['ffmpeg', '-re', '-i', source_url, '-c', 'copy']
    
    for key in keys_to_use:
        platform_lower = key.platform.lower()
        if platform_lower in rtmp_bases:
            rtmp_url = rtmp_bases[platform_lower] + key.key
            command.extend(['-f', 'flv', rtmp_url])

    if len(command) <= 5: # No valid platforms were added
         return jsonify({"error": "No outputs for supported platforms (YouTube, Facebook) found"}), 400

    # Start the FFmpeg process
    try:
        # Use shlex to ensure command is properly formatted
        # For windows use: stream_process = subprocess.Popen(command, shell=True)
        stream_process = subprocess.Popen(command)
        return jsonify({"message": "Stream started successfully"})
    except Exception as e:
        return jsonify({"error": f"Failed to start FFmpeg: {str(e)}"}), 500

@app.route('/api/stream/stop', methods=['POST'])
def stop_stream():
    global stream_process
    if stream_process and stream_process.poll() is None:
        stream_process.terminate()
        stream_process.wait() # Wait for the process to terminate
        stream_process = None
        return jsonify({"message": "Stream stopped successfully"})
    else:
        return jsonify({"error": "No stream is currently running"}), 400

@app.route('/api/stream/status', methods=['GET'])
def stream_status():
    global stream_process
    if stream_process and stream_process.poll() is None:
        return jsonify({"status": "streaming"})
    else:
        return jsonify({"status": "idle"})
# --- End of Streaming Control Endpoints ---

@app.route('/')
def status():
    return jsonify({"status": "Streaming server is online"})

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
