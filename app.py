import os
import subprocess
import shlex
from flask import Flask, jsonify, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from datetime import timedelta, datetime
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials
import requests
import uuid

# --- App Initialization & Config ---
app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-super-secret-key')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
REDIRECT_URI = 'https://smartnaijaservices.com.ng/youtube-callback.html' 
FRONTEND_URL = 'https://smartnaijaservices.com.ng'

db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

stream_processes = {}
oauth_states = {}

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    destinations = db.relationship('Destination', backref='user', lazy=True, cascade="all, delete-orphan")
    broadcasts = db.relationship('Broadcast', backref='user', lazy=True, cascade="all, delete-orphan")
    videos = db.relationship('Video', backref='user', lazy=True, cascade="all, delete-orphan")
    connected_accounts = db.relationship('ConnectedAccount', backref='user', lazy=True, cascade="all, delete-orphan")

class Destination(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    stream_key = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    video_url = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class ConnectedAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(50), nullable=False)
    account_name = db.Column(db.String(100), nullable=False)
    refresh_token = db.Column(db.String(500), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
class Broadcast(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    source_url = db.Column(db.String(500), nullable=False)
    resolution = db.Column(db.String(20), nullable=False, default='480p')
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    destinations_used = db.Column(db.Text, nullable=True)

# --- API Schemas ---
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta: model = User; fields = ("id", "full_name", "email")
class DestinationSchema(ma.SQLAlchemyAutoSchema):
    class Meta: model = Destination; include_fk = True
class ConnectedAccountSchema(ma.SQLAlchemyAutoSchema):
    class Meta: model = ConnectedAccount; fields = ("id", "platform", "account_name")
class VideoSchema(ma.SQLAlchemyAutoSchema):
    class Meta: model = Video; include_fk = True
class BroadcastSchema(ma.SQLAlchemyAutoSchema):
    class Meta: model = Broadcast; include_fk = True

user_schema=UserSchema(); destinations_schema=DestinationSchema(many=True); connected_account_schema = ConnectedAccountSchema(many=True); single_destination_schema=DestinationSchema(); video_schema=VideoSchema(many=True); broadcasts_schema=BroadcastSchema(many=True); single_broadcast_schema = BroadcastSchema()

# --- Auth Endpoints ---
@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.get_json(); full_name = data.get('full_name'); email = data.get('email'); password = data.get('password')
    if not all([full_name, email, password]): return jsonify({"error": "All fields are required"}), 400
    if User.query.filter_by(email=email).first(): return jsonify({"error": "Email already exists"}), 409
    new_user = User(full_name=full_name, email=email, password=password); db.session.add(new_user); db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    data = request.get_json(); email = data.get('email'); password = data.get('password')
    if not email or not password: return jsonify({"error": "Email and password required"}), 400
    user = User.query.filter_by(email=email).first()
    if user and user.password_hash and user.check_password(password):
        return jsonify(access_token=create_access_token(identity=str(user.id)))
    return jsonify({"error": "Invalid credentials"}), 401
    
@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    data = request.get_json(); token = data.get('token')
    try:
        id_info = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        email = id_info['email']; full_name = id_info['name']
        user = User.query.filter_by(email=email).first()
        if not user: user = User(email=email, full_name=full_name); db.session.add(user); db.session.commit()
        return jsonify(access_token=create_access_token(identity=str(user.id)))
    except ValueError: return jsonify({"error": "Token verification failed"}), 401

# --- User Profile Endpoint ---
@app.route('/api/user/profile', methods=['GET', 'PUT'])
@jwt_required()
def user_profile():
    user_id = get_jwt_identity(); user = User.query.get(user_id)
    if not user: return jsonify({"error": "User not found"}), 404
    if request.method == 'PUT':
        data = request.get_json(); new_name = data.get('full_name')
        if not new_name: return jsonify({"error": "Full name is required"}), 400
        user.full_name = new_name; db.session.commit()
        return jsonify({"message": "Profile updated successfully"}), 200
    if request.method == 'GET': return jsonify(user_schema.dump(user))

# --- Destination & Connection Endpoints ---
@app.route('/api/destinations', methods=['GET', 'POST'])
@jwt_required()
def handle_destinations():
    user_id = get_jwt_identity()
    if request.method == 'POST':
        data = request.get_json(); platform = data.get('platform'); name = data.get('name'); stream_key = data.get('stream_key')
        if not all([platform, name, stream_key]): return jsonify({"error": "All fields are required"}), 400
        new_destination = Destination(platform=platform, name=name, stream_key=stream_key, user_id=user_id)
        db.session.add(new_destination); db.session.commit()
        return jsonify(single_destination_schema.dump(new_destination)), 201
    return jsonify(destinations_schema.dump(Destination.query.filter_by(user_id=user_id).all()))

@app.route('/api/destinations/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_destination(id):
    destination = Destination.query.filter_by(id=id, user_id=get_jwt_identity()).first()
    if not destination: return jsonify({"error": "Destination not found"}), 404
    db.session.delete(destination); db.session.commit()
    return jsonify({"message": "Destination deleted"}), 200

@app.route('/api/connected-accounts', methods=['GET'])
@jwt_required()
def get_connected_accounts():
    accounts = ConnectedAccount.query.filter_by(user_id=get_jwt_identity()).all()
    return jsonify(connected_account_schema.dump(accounts))

@app.route('/api/connected-accounts/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_connected_account(id):
    account = ConnectedAccount.query.filter_by(id=id, user_id=get_jwt_identity()).first()
    if not account: return jsonify({"error": "Account not found"}), 404
    db.session.delete(account); db.session.commit()
    return jsonify({"message": "Account disconnected"}), 200

@app.route('/api/connect/youtube', methods=['GET'])
@jwt_required()
def youtube_connect():
    client_config = {"web": {"client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET, "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token", "redirect_uris": [REDIRECT_URI]}}
    
    ### FIX ### The scopes list was updated to include youtube.upload for live streaming
    flow = Flow.from_client_config(
        client_config, 
        scopes=[
            "https://www.googleapis.com/auth/youtube.upload", 
            "https://www.googleapis.com/auth/youtube.readonly", 
            "https://www.googleapis.com/auth/userinfo.profile"
        ], 
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    oauth_states[state] = get_jwt_identity()
    return jsonify({'authorization_url': authorization_url})

@app.route('/api/connect/youtube/callback')
def youtube_callback():
    state = request.args.get('state'); user_id = oauth_states.pop(state, None)
    if not user_id: return "Error: State mismatch or user ID not found.", 400
    client_config = {"web": {"client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET, "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token", "redirect_uris": [REDIRECT_URI]}}
    flow = Flow.from_client_config(client_config, scopes=None, state=state, redirect_uri=REDIRECT_URI)
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials; refresh_token = credentials.refresh_token
    user_info = build('oauth2', 'v2', credentials=credentials).userinfo().get().execute()
    account_name = user_info.get('name', 'YouTube Account')
    existing_account = ConnectedAccount.query.filter_by(user_id=user_id, platform='YouTube').first()
    if existing_account:
        existing_account.refresh_token = refresh_token; existing_account.account_name = account_name
    else:
        db.session.add(ConnectedAccount(platform='YouTube', account_name=account_name, refresh_token=refresh_token, user_id=user_id))
    db.session.commit()
    return redirect(f'{FRONTEND_URL}/profile.html')

@app.route('/api/all-possible-destinations', methods=['GET'])
@jwt_required()
def get_all_possible_destinations():
    user_id = get_jwt_identity(); all_destinations = []
    for dest in Destination.query.filter_by(user_id=user_id).all():
        all_destinations.append({"id": f"manual-{dest.id}", "platform": dest.platform, "name": f"{dest.platform}: {dest.name}", "type": "manual", "eligible": True, "reason": ""})
    for account in ConnectedAccount.query.filter_by(user_id=user_id, platform='YouTube').all():
        dest_info = {"id": f"youtube-{account.id}", "platform": "YouTube", "name": f"YouTube: {account.account_name}", "type": "connected"}
        try:
            creds = Credentials(None, refresh_token=account.refresh_token, token_uri='https://oauth2.googleapis.com/token', client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET)
            youtube = build('youtube', 'v3', credentials=creds)
            streams_response = youtube.liveStreams().list(part='id,snippet,status', mine=True).execute()
            if streams_response.get('items'):
                dest_info.update({"eligible": True, "reason": ""})
            else:
                dest_info.update({"eligible": False, "reason": "Channel not enabled for live streaming."})
        except HttpError as e:
            print(f"YouTube API HttpError: {e}")
            dest_info.update({"eligible": False, "reason": "API Error: Could not verify channel."})
        all_destinations.append(dest_info)
    return jsonify(all_destinations)

# --- Other Endpoints (Video, Broadcasts) ---
@app.route('/api/videos', methods=['GET'])
@jwt_required()
def get_videos(): return jsonify(video_schema.dump(Video.query.filter_by(user_id=get_jwt_identity()).all()))
@app.route('/api/broadcasts', methods=['POST'])
@jwt_required()
def create_broadcast():
    user_id = get_jwt_identity(); data = request.get_json()
    title = data.get('title'); source_url = data.get('source_url'); dest_ids = data.get('destination_ids'); resolution = data.get('resolution', '480p')
    if not all([title, source_url, dest_ids]): return jsonify({"error": "Missing required fields"}), 400
    
    dest_names = []
    for dest_id in dest_ids:
        if dest_id.startswith('manual-'):
            db_id = int(dest_id.split('-')[1])
            dest = Destination.query.filter_by(id=db_id, user_id=user_id).first()
            if dest: dest_names.append(f"{dest.platform}: {dest.name}")
        elif dest_id.startswith('youtube-'):
             dest_names.append("YouTube: Connected Account")

    broadcast = Broadcast(user_id=user_id, source_url=source_url, title=title, destinations_used=", ".join(dest_names), resolution=resolution)
    db.session.add(broadcast); db.session.commit()
    return jsonify(single_broadcast_schema.dump(broadcast)), 201

@app.route('/api/broadcasts', methods=['GET'])
@jwt_required()
def get_broadcasts():
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    broadcasts = Broadcast.query.filter(Broadcast.user_id == get_jwt_identity(),(Broadcast.start_time > thirty_days_ago) | (Broadcast.status == 'live') | (Broadcast.status == 'pending')).order_by(db.desc(Broadcast.id)).all()
    return jsonify(broadcasts_schema.dump(broadcasts))

@app.route('/api/broadcasts/<int:broadcast_id>/start', methods=['POST'])
@jwt_required()
def start_stream(broadcast_id):
    user_id = get_jwt_identity()
    broadcast = Broadcast.query.filter_by(id=broadcast_id, user_id=user_id).first()
    if not broadcast or broadcast.status != 'pending': return jsonify({"error": "Broadcast not found or not pending"}), 404
    if broadcast_id in stream_processes and stream_processes[broadcast_id].poll() is None: return jsonify({"error": "Stream already running"}), 400
    
    dest_names_from_db = [name.strip().split(": ")[1] for name in broadcast.destinations_used.split(", ") if "YouTube" not in name]
    destinations = Destination.query.filter(Destination.name.in_(dest_names_from_db), Destination.user_id == user_id).all()
    
    video_url = broadcast.source_url; audio_url = None
    if "youtube.com" in video_url or "youtu.be" in video_url:
        try:
            yt_dlp_cmd = ['yt-dlp', '-f', 'bestvideo[ext=mp4][height<=720]+bestaudio[ext=m4a]/best[ext=mp4][height<=720]/best', '-g', video_url]
            result = subprocess.run(yt_dlp_cmd, capture_output=True, text=True, check=True)
            urls = result.stdout.strip().split('\n'); video_url = urls[0]
            if len(urls) > 1: audio_url = urls[1]
        except Exception as e: return jsonify({"error": f"yt-dlp failed: {e}"}), 500

    settings = {'scale': '854:480', 'bitrate': '900k', 'bufsize': '1800k'}
    if broadcast.resolution == '720p': settings = {'scale': '1280:720', 'bitrate': '1800k', 'bufsize': '3600k'}

    rtmp_bases = {'youtube': 'rtmp://a.rtmp.youtube.com/live2/', 'facebook': 'rtmps://live-api-s.facebook.com:443/rtmp/', 'twitch': 'rtmp://live.twitch.tv/app/'}
    command = ['ffmpeg', '-re', '-i', video_url]
    if audio_url: command.extend(['-i', audio_url])
    command.extend(['-c:v', 'libx264', '-preset', 'veryfast', '-vf', f"scale={settings['scale']}", '-b:v', settings['bitrate'], '-maxrate', settings['bitrate'], '-bufsize', settings['bufsize'], '-pix_fmt', 'yuv420p', '-g', '50'])
    if audio_url: command.extend(['-c:a', 'aac', '-b:a', '128k', '-ar', '44100', '-map', '0:v:0', '-map', '1:a:0'])
    else: command.extend(['-c:a', 'aac', '-b:a', '128k', '-ar', '44100'])
    
    for dest in destinations:
        if dest.platform.lower() in rtmp_bases: command.extend(['-f', 'flv', rtmp_bases[dest.platform.lower()] + dest.stream_key])
    
    try:
        process = subprocess.Popen(command); stream_processes[broadcast_id] = process
        broadcast.status = 'live'; broadcast.start_time = datetime.utcnow(); db.session.commit()
        return jsonify({"message": "Stream started"})
    except Exception as e: return jsonify({"error": f"FFmpeg failed: {e}"}), 500

@app.route('/api/broadcasts/<int:broadcast_id>/stop', methods=['POST'])
@jwt_required()
def stop_stream(broadcast_id):
    broadcast = Broadcast.query.filter_by(id=broadcast_id, user_id=get_jwt_identity()).first()
    if not broadcast: return jsonify({"error": "Broadcast not found"}), 404
    process = stream_processes.get(broadcast_id)
    if process and process.poll() is None: process.terminate(); process.wait()
    broadcast.status = 'finished'; broadcast.end_time = datetime.utcnow()
    db.session.commit()
    if broadcast_id in stream_processes: del stream_processes[broadcast_id]
    return jsonify({"message": "Stream stopped"})

# --- Health Check ---
@app.route('/')
def status(): return jsonify({"status": "API is online"})

# --- Create DB ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
```eof
