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
    destination_ids_used = db.Column(db.Text, nullable=True)
    youtube_broadcast_id = db.Column(db.String(100), nullable=True)

# --- Schemas ---
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

user_schema=UserSchema()
destinations_schema=DestinationSchema(many=True)
connected_account_schema = ConnectedAccountSchema(many=True)
single_destination_schema=DestinationSchema()
video_schema=VideoSchema(many=True)
broadcasts_schema=BroadcastSchema(many=True)
single_broadcast_schema = BroadcastSchema()

# --- Auth Routes ---
@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')
    if not all([full_name, email, password]):
        return jsonify({"error": "All fields are required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 409
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(full_name=full_name, email=email, password_hash=password_hash)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    user = User.query.filter_by(email=email).first()
    if user and user.password_hash and bcrypt.check_password_hash(user.password_hash, password):
        return jsonify(access_token=create_access_token(identity=str(user.id)))
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    data = request.get_json()
    token = data.get('token')
    try:
        id_info = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        email = id_info['email']
        full_name = id_info['name']
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, full_name=full_name)
            db.session.add(user)
            db.session.commit()
        return jsonify(access_token=create_access_token(identity=str(user.id)))
    except ValueError:
        return jsonify({"error": "Token verification failed"}), 401

# --- User Profile & Destinations ---
@app.route('/api/user/profile', methods=['GET', 'PUT'])
@jwt_required()
def user_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user: return jsonify({"error": "User not found"}), 404
    if request.method == 'PUT':
        data = request.get_json()
        new_name = data.get('full_name')
        if not new_name:
            return jsonify({"error": "Full name is required"}), 400
        user.full_name = new_name
        db.session.commit()
        return jsonify({"message": "Profile updated successfully"}), 200
    return jsonify(user_schema.dump(user))

@app.route('/api/destinations', methods=['GET', 'POST'])
@jwt_required()
def handle_destinations():
    user_id = get_jwt_identity()
    if request.method == 'POST':
        data = request.get_json()
        platform = data.get('platform')
        name = data.get('name')
        stream_key = data.get('stream_key')
        if not all([platform, name, stream_key]):
            return jsonify({"error": "All fields are required"}), 400
        new_destination = Destination(platform=platform, name=name, stream_key=stream_key, user_id=user_id)
        db.session.add(new_destination)
        db.session.commit()
        return jsonify(single_destination_schema.dump(new_destination)), 201
    return jsonify(destinations_schema.dump(Destination.query.filter_by(user_id=user_id).all()))

@app.route('/api/destinations/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_destination(id):
    destination = Destination.query.filter_by(id=id, user_id=get_jwt_identity()).first()
    if not destination: return jsonify({"error": "Destination not found"}), 404
    db.session.delete(destination)
    db.session.commit()
    return jsonify({"message": "Destination deleted"}), 200

# --- Connected Accounts ---
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
    db.session.delete(account)
    db.session.commit()
    return jsonify({"message": "Account disconnected"}), 200

# --- YouTube Connect ---
@app.route('/api/connect/youtube', methods=['GET'])
@jwt_required()
def youtube_connect():
    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [REDIRECT_URI]
        }
    }
    flow = Flow.from_client_config(
        client_config,
        scopes=["https://www.googleapis.com/auth/youtube", "https://www.googleapis.com/auth/youtube.force-ssl", "https://www.googleapis.com/auth/userinfo.profile"],
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(access_type='offline', prompt='consent', include_granted_scopes='true')
    oauth_states[state] = get_jwt_identity()
    return jsonify({'authorization_url': authorization_url})

@app.route('/api/connect/youtube/callback')
def youtube_callback():
    state = request.args.get('state')
    user_id = oauth_states.pop(state, None)
    if not user_id: return "Error: State mismatch or user ID not found.", 400
    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [REDIRECT_URI]
        }
    }
    flow = Flow.from_client_config(client_config, scopes=None, state=state, redirect_uri=REDIRECT_URI)
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    refresh_token = credentials.refresh_token
    user_info = build('oauth2', 'v2', credentials=credentials).userinfo().get().execute()
    account_name = user_info.get('name', 'YouTube Account')
    existing_account = ConnectedAccount.query.filter_by(user_id=user_id, platform='YouTube').first()
    if existing_account:
        existing_account.refresh_token = refresh_token
        existing_account.account_name = account_name
    else:
        db.session.add(ConnectedAccount(platform='YouTube', account_name=account_name, refresh_token=refresh_token, user_id=user_id))
    db.session.commit()
    return redirect(f'{FRONTEND_URL}/profile.html')

# --- All Destinations (Fixed) ---
@app.route('/api/all-possible-destinations', methods=['GET'])
@jwt_required()
def get_all_possible_destinations():
    user_id = get_jwt_identity()
    all_destinations = []
    for dest in Destination.query.filter_by(user_id=user_id).all():
        all_destinations.append({
            "id": f"manual-{dest.id}",
            "platform": dest.platform,
            "name": f"{dest.platform}: {dest.name}",
            "type": "manual",
            "eligible": True,
            "reason": ""
        })

    for account in ConnectedAccount.query.filter_by(user_id=user_id, platform='YouTube').all():
        dest_info = {
            "id": f"youtube-{account.id}",
            "platform": "YouTube",
            "name": f"YouTube: {account.account_name}",
            "type": "connected",
            "eligible": True,
            "reason": ""
        }
        try:
            creds = Credentials(
                None,
                refresh_token=account.refresh_token,
                token_uri='https://oauth2.googleapis.com/token',
                client_id=GOOGLE_CLIENT_ID,
                client_secret=GOOGLE_CLIENT_SECRET
            )
            youtube = build('youtube', 'v3', credentials=creds)
            youtube.channels().list(part="id", mine=True).execute()
        except Exception as e:
            print(f"YouTube API Error: {e}")
            dest_info.update({"eligible": False, "reason": "Re-authentication required"})
        all_destinations.append(dest_info)

    return jsonify(all_destinations)

# --- Broadcast Creation ---
@app.route('/api/broadcasts', methods=['POST'])
@jwt_required()
def create_broadcast():
    user_id = get_jwt_identity()
    data = request.get_json()
    title = data.get('title')
    source_url = data.get('source_url')
    destination_ids = data.get('destination_ids')
    resolution = data.get('resolution', '480p')
    if not all([title, source_url, destination_ids]):
        return jsonify({"error": "Missing required fields"}), 400

    dest_names = []
    for dest_id_str in destination_ids:
        if dest_id_str.startswith('manual-'):
            db_id = int(dest_id_str.split('-')[1])
            dest = Destination.query.get(db_id)
            if dest and str(dest.user_id) == user_id:
                dest_names.append(f"{dest.platform}: {dest.name}")
        elif dest_id_str.startswith('youtube-'):
            db_id = int(dest_id_str.split('-')[1])
            acc = ConnectedAccount.query.get(db_id)
            if acc and str(acc.user_id) == user_id:
                dest_names.append(f"YouTube: {acc.account_name}")

    if not dest_names:
        return jsonify({"error": "Invalid destination IDs"}), 400

    broadcast = Broadcast(
        user_id=user_id,
        source_url=source_url,
        title=title,
        destinations_used=", ".join(dest_names),
        destination_ids_used=json.dumps(destination_ids),
        resolution=resolution
    )
    db.session.add(broadcast)
    db.session.commit()
    return jsonify(single_broadcast_schema.dump(broadcast)), 201

# --- Broadcast List ---
@app.route('/api/broadcasts', methods=['GET'])
@jwt_required()
def get_broadcasts():
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    broadcasts = Broadcast.query.filter(
        Broadcast.user_id == get_jwt_identity(),
        (Broadcast.start_time > thirty_days_ago) | (Broadcast.status.in_(['live', 'pending']))
    ).order_by(db.desc(Broadcast.id)).all()
    return jsonify(broadcasts_schema.dump(broadcasts))

# --- Run Stream ---
def _run_stream(app, broadcast_id):
    with app.app_context():
        broadcast = Broadcast.query.get(broadcast_id)
        youtube_service = None
        youtube_broadcast_id = None
        try:
            rtmp_outputs = []
            destination_ids = json.loads(broadcast.destination_ids_used)

            for dest_id_str in destination_ids:
                if dest_id_str.startswith('manual-'):
                    db_id = int(dest_id_str.split('-')[1])
                    dest = Destination.query.get(db_id)
                    if dest: rtmp_outputs.append(dest.stream_key)

                elif dest_id_str.startswith('youtube-'):
                    db_id = int(dest_id_str.split('-')[1])
                    account = ConnectedAccount.query.get(db_id)
                    if not account: continue

                    creds = Credentials(
                        None,
                        refresh_token=account.refresh_token,
                        token_uri='https://oauth2.googleapis.com/token',
                        client_id=GOOGLE_CLIENT_ID,
                        client_secret=GOOGLE_CLIENT_SECRET
                    )
                    youtube_service = build('youtube', 'v3', credentials=creds)

                    stream_format = broadcast.resolution
                    if stream_format not in ['1080p', '1440p', '2160p', '720p', '480p', '360p', '240p']:
                        stream_format = '480p'

                    stream_insert = youtube_service.liveStreams().insert(
                        part="snippet,cdn,status",
                        body={
                            "snippet": {"title": broadcast.title},
                            "cdn": {"resolution": stream_format, "frameRate": "30fps", "ingestionType": "rtmp"}
                        }
                    ).execute()
                    stream_yt_id = stream_insert['id']

                    broadcast_insert = youtube_service.liveBroadcasts().insert(
                        part="snippet,status,contentDetails",
                        body={
                            "snippet": {"title": broadcast.title},
                            "status": {"privacyStatus": "public"},
                            "contentDetails": {"streamId": stream_yt_id, "enableAutoStart": True, "enableAutoStop": True}
                        }
                    ).execute()
                    youtube_broadcast_id = broadcast_insert['id']
                    broadcast.youtube_broadcast_id = youtube_broadcast_id
                    db.session.commit()

                    ingestion_address = stream_insert['cdn']['ingestionInfo']['ingestionAddress']
                    stream_name = stream_insert['cdn']['ingestionInfo']['streamName']
                    rtmp_outputs.append(f"{ingestion_address}/{stream_name}")

            if not rtmp_outputs:
                broadcast.status = 'failed'
                db.session.commit()
                return

            # Resolution settings
            if broadcast.resolution == '720p':
                settings = {'scale': '1280:720', 'bitrate': '1800k', 'bufsize': '3600k'}
            elif broadcast.resolution == '1080p':
                settings = {'scale': '1920:1080', 'bitrate': '3000k', 'bufsize': '6000k'}
            elif broadcast.resolution == '480p':
                settings = {'scale': '854:480', 'bitrate': '1000k', 'bufsize': '2000k'}
            else:
                settings = {'scale': '640:360', 'bitrate': '600k', 'bufsize': '1200k'}

            # FF
