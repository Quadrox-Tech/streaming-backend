import os
import subprocess
import shlex
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS

# Initialize the application
app = Flask(__name__)
CORS(app)

# --- Global variable to hold the FFmpeg process ---
stream_process = None

# --- Database Configuration ---
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
ma = Marshmallow(app)

# --- Database Model (Unchanged) ---
class StreamKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    key = db.Column(db.String(200), unique=True, nullable=False)

    def __init__(self, platform, name, key):
        self.platform = platform
        self.name = name
        self.key = key

# --- API Schema (Unchanged) ---
class StreamKeySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = StreamKey
        load_instance = True

# --- API Endpoints for Key Management (Unchanged) ---
@app.route('/api/keys', methods=['POST'])
def add_key():
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
    all_keys = StreamKey.query.all()
    keys_schema = StreamKeySchema(many=True)
    return jsonify(keys_schema.dump(all_keys))

@app.route('/api/keys/<int:id>', methods=['DELETE'])
def delete_key(id):
    key = StreamKey.query.get(id)
    if not key:
        return jsonify({"error": "Key not found"}), 404
    db.session.delete(key)
    db.session.commit()
    return jsonify({"message": "Key deleted successfully"})


# --- API Endpoints for Streaming Control (UPDATED) ---
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

    stream_url = source_url
    if "youtube.com" in source_url or "youtu.be" in source_url:
        try:
            yt_dlp_command = ['yt-dlp', '-g', source_url]
            result = subprocess.run(yt_dlp_command, capture_output=True, text=True, check=True)
            stream_url = result.stdout.strip().split('\n')[-1]
        except subprocess.CalledProcessError as e:
            return jsonify({"error": f"Failed to get YouTube stream URL: {e.stderr}"}), 500
        except Exception as e:
            return jsonify({"error": f"An unexpected error occurred with yt-dlp: {str(e)}"}), 500

    keys_to_use = StreamKey.query.filter(StreamKey.id.in_(key_ids)).all()
    if not keys_to_use:
        return jsonify({"error": "No valid stream keys found"}), 404

    rtmp_bases = {
        'youtube': 'rtmp://a.rtmp.youtube.com/live2/',
        'facebook': 'rtmps://live-api-s.facebook.com:443/rtmp/'
    }
    
    # --- THIS IS THE LINE THAT CHANGED ---
    # We now specify to copy video but re-encode audio to AAC format
    command = [
        'ffmpeg', '-re', '-i', stream_url,
        '-c:v', 'copy',      # Copy the video stream as is
        '-c:a', 'aac',       # Re-encode the audio to AAC
        '-ar', '44100',      # Set audio sample rate to 44.1kHz
        '-b:a', '128k'       # Set audio bitrate to 128k for good quality
    ]
    
    for key in keys_to_use:
        platform_lower = key.platform.lower()
        if platform_lower in rtmp_bases:
            rtmp_url = rtmp_bases[platform_lower] + key.key
            command.extend(['-f', 'flv', rtmp_url])

    if len(command) <= 9: # Check if any outputs were added
         return jsonify({"error": "No valid outputs found"}), 400

    try:
        stream_process = subprocess.Popen(command)
        return jsonify({"message": "Stream started successfully"})
    except Exception as e:
        return jsonify({"error": f"Failed to start FFmpeg: {str(e)}"}), 500

# --- Other endpoints are unchanged ---
@app.route('/api/stream/stop', methods=['POST'])
def stop_stream():
    global stream_process
    if stream_process and stream_process.poll() is None:
        stream_process.terminate()
        stream_process.wait()
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

@app.route('/')
def status():
    return jsonify({"status": "Streaming server is online"})

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
