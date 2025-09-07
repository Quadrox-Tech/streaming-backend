import os
import subprocess
import shlex
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from datetime import timedelta, datetime

# --- App Initialization & Config ---
app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-super-secret-key')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')

db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Global dictionary to hold running FFmpeg processes, keyed by broadcast_id
stream_processes = {}

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    profile_picture_url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    destinations = db.relationship('Destination', backref='user', lazy=True, cascade="all, delete-orphan")
    broadcasts = db.relationship('Broadcast', backref='user', lazy=True, cascade="all, delete-orphan")

    def __init__(self, email, full_name, password=None):
        self.email = email; self.full_name = full_name
        if password: self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password(self, password): return bcrypt.check_password_hash(self.password_hash, password)

class Destination(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    stream_key = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Broadcast(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, default="Untitled Broadcast")
    status = db.Column(db.String(20), nullable=False, default='pending') # pending, live, finished
    source_url = db.Column(db.String(500), nullable=False)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    destinations_used = db.Column(db.Text, nullable=True)

# --- API Schemas ---
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta: model = User; fields = ("id", "full_name", "email", "profile_picture_url")
class DestinationSchema(ma.SQLAlchemyAutoSchema):
    class Meta: model = Destination; include_fk = True
class BroadcastSchema(ma.SQLAlchemyAutoSchema):
    class Meta: model = Broadcast; include_fk = True

user_schema=UserSchema(); destination_schema=DestinationSchema(); destinations_schema=DestinationSchema(many=True); broadcast_schema=BroadcastSchema(); broadcasts_schema=BroadcastSchema(many=True)

# --- Auth Endpoints ---
@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data=request.get_json(); full_name=data.get('full_name'); email=data.get('email'); password=data.get('password')
    if not all([full_name, email, password]): return jsonify({"error": "All fields are required"}), 400
    if User.query.filter_by(email=email).first(): return jsonify({"error": "Email already exists"}), 409
    new_user=User(full_name=full_name, email=email, password=password); db.session.add(new_user); db.session.commit()
    return jsonify({"message": "User registered"}), 201

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    data=request.get_json(); email=data.get('email'); password=data.get('password')
    if not email or not password: return jsonify({"error": "Email and password required"}), 400
    user = User.query.filter_by(email=email).first()
    if user and user.password_hash and user.check_password(password):
        return jsonify(access_token=create_access_token(identity=str(user.id)))
    return jsonify({"error": "Invalid credentials"}), 401
    
@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    data=request.get_json(); token=data.get('token')
    try:
        id_info=id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        email=id_info['email']; full_name=id_info['name']
        user=User.query.filter_by(email=email).first()
        if not user: user=User(email=email, full_name=full_name); db.session.add(user); db.session.commit()
        return jsonify(access_token=create_access_token(identity=str(user.id)))
    except ValueError as e: return jsonify({"error": f"Token verification failed: {e}"}), 401

# --- User Profile Endpoints ---
@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile(): return jsonify(user_schema.dump(User.query.get(get_jwt_identity())))

@app.route('/api/user/profile', methods=['PUT'])
@jwt_required()
def update_user_profile():
    user=User.query.get(get_jwt_identity()); data=request.get_json()
    if 'full_name' in data: user.full_name=data['full_name']
    if 'profile_picture_url' in data: user.profile_picture_url=data['profile_picture_url']
    db.session.commit(); return jsonify(user_schema.dump(user))

# --- Destination Endpoints ---
@app.route('/api/destinations', methods=['POST'])
@jwt_required()
def add_destination():
    user_id=get_jwt_identity(); data=request.get_json(); platform=data.get('platform'); name=data.get('name'); stream_key=data.get('stream_key')
    if not all([platform, name, stream_key]): return jsonify({"error": "All fields are required"}), 400
    new_destination=Destination(platform=platform, name=name, stream_key=stream_key, user_id=user_id)
    db.session.add(new_destination); db.session.commit(); return jsonify(destination_schema.dump(new_destination)), 201

@app.route('/api/destinations', methods=['GET'])
@jwt_required()
def get_destinations(): return jsonify(destinations_schema.dump(Destination.query.filter_by(user_id=get_jwt_identity()).all()))

@app.route('/api/destinations/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_destination(id):
    destination=Destination.query.filter_by(id=id, user_id=get_jwt_identity()).first()
    if not destination: return jsonify({"error": "Not found"}), 404
    db.session.delete(destination); db.session.commit(); return jsonify({"message": "Deleted"}), 200

# --- Broadcast & Streaming Endpoints ---
@app.route('/api/broadcasts', methods=['POST'])
@jwt_required()
def create_broadcast():
    user_id=get_jwt_identity(); data=request.get_json(); source_url=data.get('source_url'); title=data.get('title'); dest_ids=data.get('destination_ids')
    if not all([source_url, title, dest_ids]): return jsonify({"error": "Missing required fields"}), 400
    
    destinations = Destination.query.filter(Destination.id.in_(dest_ids), Destination.user_id == user_id).all()
    if len(destinations) != len(dest_ids): return jsonify({"error": "Invalid destination IDs"}), 400
    
    dest_names = ", ".join([d.name for d in destinations])
    broadcast = Broadcast(user_id=user_id, source_url=source_url, title=title, destinations_used=dest_names)
    db.session.add(broadcast); db.session.commit()
    return jsonify(broadcast_schema.dump(broadcast)), 201

@app.route('/api/broadcasts', methods=['GET'])
@jwt_required()
def get_broadcasts():
    thirty_days_ago=datetime.utcnow() - timedelta(days=30)
    broadcasts=Broadcast.query.filter_by(user_id=get_jwt_identity()).filter(
        (Broadcast.start_time > thirty_days_ago) | (Broadcast.status == 'live') | (Broadcast.status == 'pending')
    ).order_by(Broadcast.start_time.desc()).all(); return jsonify(broadcasts_schema.dump(broadcasts))

@app.route('/api/broadcasts/<int:broadcast_id>/start', methods=['POST'])
@jwt_required()
def start_stream(broadcast_id):
    user_id = get_jwt_identity()
    broadcast = Broadcast.query.filter_by(id=broadcast_id, user_id=user_id).first()
    if not broadcast or broadcast.status != 'pending': return jsonify({"error": "Broadcast not found or not in pending state"}), 404
    if broadcast_id in stream_processes and stream_processes[broadcast_id].poll() is None: return jsonify({"error": "Stream is already running"}), 400
    
    dest_names = broadcast.destinations_used.split(", ")
    destinations = Destination.query.filter(Destination.name.in_(dest_names), Destination.user_id==user_id).all()
    
    video_url=broadcast.source_url; audio_url=None
    if "youtube.com" in video_url or "youtu.be" in video_url:
        try:
            yt_dlp_cmd = ['yt-dlp', '-f', 'bestvideo[ext=mp4][height<=720]+bestaudio[ext=m4a]/best[ext=mp4][height<=720]/best', '-g', video_url]
            result = subprocess.run(yt_dlp_cmd, capture_output=True, text=True, check=True)
            urls = result.stdout.strip().split('\n'); video_url=urls[0]
            if len(urls) > 1: audio_url = urls[1]
        except Exception as e: return jsonify({"error": f"yt-dlp failed: {e}"}), 500

    rtmp_bases = {'youtube': 'rtmp://a.rtmp.youtube.com/live2/', 'facebook': 'rtmps://live-api-s.facebook.com:443/rtmp/'}
    command = ['ffmpeg', '-re']; command.extend(['-i', video_url]);
    if audio_url: command.extend(['-i', audio_url])
    command.extend(['-c:v', 'libx264', '-preset', 'veryfast', '-vf', 'scale=854:480', '-b:v', '900k', '-maxrate', '900k', '-bufsize', '1800k', '-pix_fmt', 'yuv420p', '-g', '50'])
    if audio_url: command.extend(['-c:a', 'aac', '-b:a', '128k', '-ar', '44100', '-map', '0:v:0', '-map', '1:a:0'])
    else: command.extend(['-c:a', 'aac', '-b:a', '128k', '-ar', '44100'])
    
    for dest in destinations:
        platform_lower = dest.platform.lower()
        if platform_lower in rtmp_bases: command.extend(['-f', 'flv', rtmp_bases[platform_lower] + dest.stream_key])

    try:
        process = subprocess.Popen(command); stream_processes[broadcast_id] = process
        broadcast.status = 'live'; broadcast.start_time = datetime.utcnow(); db.session.commit()
        return jsonify({"message": "Stream started"})
    except Exception as e: return jsonify({"error": f"FFmpeg failed: {e}"}), 500

@app.route('/api/broadcasts/<int:broadcast_id>/stop', methods=['POST'])
@jwt_required()
def stop_stream(broadcast_id):
    user_id = get_jwt_identity()
    broadcast = Broadcast.query.filter_by(id=broadcast_id, user_id=user_id).first()
    if not broadcast: return jsonify({"error": "Broadcast not found"}), 404

    process = stream_processes.get(broadcast_id)
    if process and process.poll() is None:
        process.terminate(); process.wait()
        
    broadcast.status = 'finished'; broadcast.end_time = datetime.utcnow()
    db.session.commit()
    if broadcast_id in stream_processes: del stream_processes[broadcast_id]
    return jsonify({"message": "Stream stopped"})
    
@app.route('/api/broadcasts/status', methods=['GET'])
@jwt_required()
def get_live_broadcasts_status():
    user_id = get_jwt_identity()
    live_broadcasts = Broadcast.query.filter_by(user_id=user_id, status='live').all()
    
    # Prune dead processes
    for b in live_broadcasts:
        process = stream_processes.get(b.id)
        if not process or process.poll() is not None:
            b.status = 'finished'; b.end_time = datetime.utcnow()
            if b.id in stream_processes: del stream_processes[b.id]
    db.session.commit()

    live_broadcasts = Broadcast.query.filter_by(user_id=user_id, status='live').all()
    return jsonify(broadcasts_schema.dump(live_broadcasts))

# --- Health Check ---
@app.route('/')
def status(): return jsonify({"status": "API is online"})

# --- Create DB ---
with app.app_context(): db.create_all()
if __name__ == '__main__': app.run(host='0.0.0.0', port=8000)
