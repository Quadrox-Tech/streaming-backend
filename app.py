import os
import subprocess
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
import json
import threading
import time
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- App Config ---
app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite3')
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

# --- Database Models & Schemas (Complete and Correct) ---
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
    destination_ids_used = db.Column(db.Text, nullable=True)
    youtube_broadcast_id = db.Column(db.String(100), nullable=True)
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

# --- API Endpoints (Complete and Correct) ---
@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.get_json(); full_name = data.get('full_name'); email = data.get('email'); password = data.get('password')
    if not all([full_name, email, password]): return jsonify({"error": "All fields are required"}), 400
    if User.query.filter_by(email=email).first(): return jsonify({"error": "Email already exists"}), 409
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(full_name=full_name, email=email, password_hash=password_hash); db.session.add(new_user); db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201
@app.route('/api/auth/login', methods=['POST'])
def login_user():
    data = request.get_json(); email = data.get('email'); password = data.get('password')
    if not email or not password: return jsonify({"error": "Email and password required"}), 400
    user = User.query.filter_by(email=email).first()
    if user and user.password_hash and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token)
    return jsonify({"error": "Invalid credentials"}), 401
@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    data = request.get_json(); token = data.get('token')
    if not token: return jsonify({"error": "No token provided"}), 400
    try:
        id_info = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        email = id_info['email']; full_name = id_info['name']
        user = User.query.filter_by(email=email).first()
        if not user: 
            user = User(email=email, full_name=full_name)
            db.session.add(user)
            db.session.commit()
        access_token = create_access_token(identity=str(user.id))
        return jsonify(access_token=access_token)
    except ValueError as e: 
        return jsonify({"error": "Token verification failed"}), 401
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
    return jsonify(user_schema.dump(user))
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
    destinations = Destination.query.filter_by(user_id=user_id).all()
    return jsonify(destinations_schema.dump(destinations))
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
    flow = Flow.from_client_config(client_config, scopes=["https://www.googleapis.com/auth/youtube", "https://www.googleapis.com/auth/youtube.force-ssl", "https://www.googleapis.com/auth/userinfo.profile"], redirect_uri=REDIRECT_URI)
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent', include_granted_scopes='true')
    oauth_states[state] = get_jwt_identity()
    return jsonify({'authorization_url': authorization_url})
@app.route('/api/connect/youtube/callback')
def youtube_callback():
    state = request.args.get('state'); user_id = oauth_states.pop(state, None)
    if not user_id: return "Error: State mismatch.", 400
    try:
        client_config = {"web": {"client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET, "auth_uri": "https://accounts.google.com/o/oauth2/auth", "token_uri": "https://oauth2.googleapis.com/token", "redirect_uris": [REDIRECT_URI]}}
        flow = Flow.from_client_config(client_config, scopes=None, state=state, redirect_uri=REDIRECT_URI)
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials; refresh_token = credentials.refresh_token
        user_info_service = build('oauth2', 'v2', credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        account_name = user_info.get('name', 'YouTube Account')
        existing_account = ConnectedAccount.query.filter_by(user_id=user_id, platform='YouTube').first()
        if existing_account:
            existing_account.refresh_token = refresh_token; existing_account.account_name = account_name
        else:
            new_account = ConnectedAccount(platform='YouTube', account_name=account_name, refresh_token=refresh_token, user_id=user_id)
            db.session.add(new_account)
        db.session.commit()
    except Exception as e:
        logger.error(f"YouTube callback error: {e}")
        return redirect(f'{FRONTEND_URL}/profile.html?error=true')
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
            youtube.liveBroadcasts().list(part='id', mine=True, maxResults=1).execute()
            dest_info.update({"eligible": True, "reason": ""})
        except HttpError as e:
            error_details = json.loads(e.content.decode()); reason = error_details.get("error", {}).get("message", "Could not verify account.")
            if 'liveStreamingNotEnabled' in reason:
                dest_info.update({"eligible": False, "reason": "Live streaming is not enabled on this channel."})
            else:
                dest_info.update({"eligible": False, "reason": "API Error: Could not verify channel."})
        all_destinations.append(dest_info)
    return jsonify(all_destinations)
@app.route('/api/broadcasts', methods=['POST', 'GET'])
@jwt_required()
def handle_broadcasts():
    user_id = get_jwt_identity()
    if request.method == 'POST':
        data = request.get_json()
        title = data.get('title'); source_url = data.get('source_url'); destination_ids = data.get('destination_ids'); resolution = data.get('resolution', '480p')
        if not all([title, source_url, destination_ids]): return jsonify({"error": "Missing required fields"}), 400
        dest_names = []
        for dest_id_str in destination_ids:
            if dest_id_str.startswith('manual-'):
                db_id = int(dest_id_str.split('-')[1]); dest = Destination.query.get(db_id)
                if dest and str(dest.user_id) == user_id: dest_names.append(f"{dest.platform}: {dest.name}")
            elif dest_id_str.startswith('youtube-'):
                db_id = int(dest_id_str.split('-')[1]); acc = ConnectedAccount.query.get(db_id)
                if acc and str(acc.user_id) == user_id: dest_names.append(f"YouTube: {acc.account_name}")
        if not dest_names: return jsonify({"error": "No valid destinations"}), 400
        broadcast = Broadcast(user_id=user_id, source_url=source_url, title=title, destinations_used=", ".join(dest_names), destination_ids_used=json.dumps(destination_ids), resolution=resolution)
        db.session.add(broadcast); db.session.commit()
        return jsonify(single_broadcast_schema.dump(broadcast)), 201
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    broadcasts = Broadcast.query.filter(Broadcast.user_id == user_id, (Broadcast.start_time > thirty_days_ago) | (Broadcast.status.in_(['live', 'pending', 'finished', 'failed']))).order_by(db.desc(Broadcast.id)).all()
    return jsonify(broadcasts_schema.dump(broadcasts))
@app.route('/api/broadcasts/<int:broadcast_id>/start', methods=['POST'])
@jwt_required()
def start_stream(broadcast_id):
    broadcast = Broadcast.query.get(broadcast_id)
    if not broadcast or str(broadcast.user_id) != get_jwt_identity(): return jsonify({"error": "Broadcast not found"}), 404
    if broadcast.status != 'pending': return jsonify({"error": "Stream not pending."}), 400
    broadcast.status = 'live'; broadcast.start_time = datetime.utcnow(); db.session.commit()
    thread = threading.Thread(target=_run_stream, args=(app, broadcast_id)); thread.daemon = True; thread.start()
    return jsonify({"message": "Stream initiated."})
@app.route('/api/broadcasts/<int:broadcast_id>/stop', methods=['POST'])
@jwt_required()
def stop_stream(broadcast_id):
    broadcast = Broadcast.query.filter_by(id=broadcast_id, user_id=get_jwt_identity()).first()
    if not broadcast: return jsonify({"error": "Broadcast not found"}), 404
    process = stream_processes.get(broadcast_id)
    if process and process.poll() is None:
        process.terminate()
        try: process.wait(timeout=5)
        except subprocess.TimeoutExpired: process.kill()
    return jsonify({"message": "Stream stopping..."})
def get_youtube_credentials(refresh_token):
    try:
        creds = Credentials(None, refresh_token=refresh_token, token_uri='https://oauth2.googleapis.com/token', client_id=GOOGLE_CLIENT_ID, client_secret=GOOGLE_CLIENT_SECRET)
        creds.refresh(google_requests.Request())
        return build('youtube', 'v3', credentials=creds)
    except Exception as e:
        logger.error(f"Failed to refresh YouTube credentials: {e}")
        raise
def create_youtube_stream(youtube_service, broadcast_title, resolution):
    try:
        cdn_settings = {"format": "1080p" if resolution == "1080p" else "720p" if resolution == "720p" else "480p", "ingestionType": "rtmp", "frameRate": "30fps"}
        stream_body = {"snippet": {"title": f"{broadcast_title} - Stream"}, "cdn": cdn_settings}
        stream_response = youtube_service.liveStreams().insert(part="snippet,cdn,status", body=stream_body).execute()
        stream_id = stream_response['id']
        ingestion_info = stream_response['cdn']['ingestionInfo']
        rtmp_url = f"{ingestion_info['ingestionAddress']}/{ingestion_info['streamName']}"
        broadcast_body = {"snippet": {"title": broadcast_title, "scheduledStartTime": datetime.utcnow().isoformat() + "Z"}, "status": {"privacyStatus": "public"}, "contentDetails": {"streamId": stream_id, "enableAutoStart": True, "enableAutoStop": True}}
        broadcast_response = youtube_service.liveBroadcasts().insert(part="snippet,status,contentDetails", body=broadcast_body).execute()
        broadcast_id = broadcast_response['id']
        logger.info(f"Created YouTube stream {stream_id} and broadcast {broadcast_id}")
        return stream_id, broadcast_id, rtmp_url
    except HttpError as e:
        error_details = json.loads(e.content.decode()); logger.error(f"YouTube API Error: {error_details}")
        raise Exception(f"YouTube API Error: {error_details.get('error', {}).get('message', 'Unknown error')}")

def _run_stream(app, broadcast_id):
    with app.app_context():
        broadcast = Broadcast.query.get(broadcast_id)
        if not broadcast: logger.error(f"Broadcast {broadcast_id} not found"); return

        process = None; youtube_streams = []
        try:
            logger.info(f"Starting stream for broadcast {broadcast_id}: {broadcast.title}")
            rtmp_outputs = []; destination_ids = json.loads(broadcast.destination_ids_used)
            for dest_id_str in destination_ids:
                if dest_id_str.startswith('manual-'):
                    db_id = int(dest_id_str.split('-')[1]); dest = Destination.query.get(db_id)
                    if dest: rtmp_outputs.append(dest.stream_key); logger.info(f"Added manual destination: {dest.platform}")
                elif dest_id_str.startswith('youtube-'):
                    db_id = int(dest_id_str.split('-')[1]); account = ConnectedAccount.query.get(db_id)
                    if not account: logger.warning(f"YouTube account {db_id} not found"); continue
                    try:
                        youtube_service = get_youtube_credentials(account.refresh_token)
                        stream_id, broadcast_id_yt, rtmp_url = create_youtube_stream(youtube_service, broadcast.title, broadcast.resolution)
                        youtube_streams.append({'service': youtube_service, 'stream_id': stream_id, 'broadcast_id': broadcast_id_yt})
                        rtmp_outputs.append(rtmp_url)
                        if not broadcast.youtube_broadcast_id:
                            broadcast.youtube_broadcast_id = broadcast_id_yt; db.session.commit()
                        logger.info(f"Created YouTube stream for account {account.account_name}")
                    except Exception as e:
                        logger.error(f"Failed to setup YouTube stream for account {db_id}: {e}")
                        continue
            
            if not rtmp_outputs: raise Exception("No valid RTMP outputs configured")
            
            video_url = broadcast.source_url; audio_url = None
            if "youtube.com" in video_url or "youtu.be" in video_url:
                logger.info("Processing YouTube source URL...")
                yt_dlp_cmd = ['yt-dlp', '-f', 'bestvideo[ext=mp4][height<=720]+bestaudio[ext=m4a]/best[ext=mp4]/best', '-g', video_url]
                if os.path.exists('/app/cookies.txt'):
                    yt_dlp_cmd.extend(['--cookies', '/app/cookies.txt'])
                try:
                    result = subprocess.run(yt_dlp_cmd, capture_output=True, text=True, check=True, timeout=60)
                    if not result.stdout or not result.stdout.strip(): raise Exception("yt-dlp returned no URLs")
                    urls = result.stdout.strip().split('\n'); video_url = urls[0]; audio_url = urls[1] if len(urls) > 1 else None
                    logger.info(f"yt-dlp extracted URLs successfully.")
                except subprocess.CalledProcessError as e:
                    logger.error(f"yt-dlp failed: {e.stderr}"); raise Exception("Failed to extract video URLs.")
            
            resolution_settings = {'480p': {'scale': '854:480', 'bitrate': '1000k'}, '720p': {'scale': '1280:720', 'bitrate': '2500k'}, '1080p': {'scale': '1920:1080', 'bitrate': '4000k'}}
            settings = resolution_settings.get(broadcast.resolution, resolution_settings['480p'])
            
            ffmpeg_cmd = ['ffmpeg', '-re', '-i', video_url]
            if audio_url: ffmpeg_cmd.extend(['-i', audio_url])
            ffmpeg_cmd.extend(['-c:v', 'libx264', '-preset', 'veryfast', '-b:v', settings['bitrate'], '-maxrate', settings['bitrate'], '-bufsize', f"{int(settings['bitrate'].replace('k',''))*2}k", '-pix_fmt', 'yuv420p', '-g', '60', '-c:a', 'aac', '-b:a', '128k', '-ar', '44100'])
            if audio_url: ffmpeg_cmd.extend(['-map', '0:v:0', '-map', '1:a:0'])
            
            for rtmp_url in rtmp_outputs:
                ffmpeg_cmd.extend(['-f', 'flv', rtmp_url])
            
            logger.info(f"Starting FFmpeg with {len(rtmp_outputs)} outputs")
            process = subprocess.Popen(ffmpeg_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            stream_processes[broadcast_id] = process
            
            # *** THE FINAL FIX: NO HEALTH CHECK LOOP NEEDED WITH enableAutoStart:True ***
            # We just wait for the process to finish on its own. YouTube handles the rest.
            logger.info("FFmpeg started successfully, monitoring process...")
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                logger.info("FFmpeg completed successfully")
                broadcast.status = 'finished'
            else:
                logger.error(f"FFmpeg failed with exit code {process.returncode}")
                logger.error(f"FFmpeg stderr: {stderr.decode('utf-8', errors='ignore')}")
                broadcast.status = 'failed'
                
        except Exception as e:
            logger.error(f"Stream failed for broadcast {broadcast_id}: {e}")
            broadcast.status = 'failed'
            if process and process.poll() is None:
                process.kill()
                    
        finally:
            broadcast.end_time = datetime.utcnow()
            for yt_stream in youtube_streams:
                try:
                    yt_stream['service'].liveBroadcasts().transition(part="id", id=yt_stream['broadcast_id'], broadcastStatus="complete").execute()
                except HttpError as e:
                    logger.warning(f"Could not set broadcast {yt_stream['broadcast_id']} to complete: {e}")
                try:
                    yt_stream['service'].liveStreams().delete(id=yt_stream['stream_id']).execute()
                except HttpError as e:
                    logger.warning(f"Could not delete stream {yt_stream['stream_id']}: {e}")
            
            if broadcast_id in stream_processes: del stream_processes[broadcast_id]
            db.session.commit()
            logger.info(f"Stream cleanup completed for broadcast {broadcast_id}")

@app.route('/')
def status(): return jsonify({"status": "API is online"})
with app.app_context():
    try:
        db.create_all()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=False)
