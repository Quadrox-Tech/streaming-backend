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

# --- API Schemas ---
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        fields = ("id", "full_name", "email")

class DestinationSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Destination
        include_fk = True

class ConnectedAccountSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = ConnectedAccount
        fields = ("id", "platform", "account_name")

class VideoSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Video
        include_fk = True

class BroadcastSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Broadcast
        include_fk = True

user_schema = UserSchema()
destinations_schema = DestinationSchema(many=True)
connected_account_schema = ConnectedAccountSchema(many=True)
single_destination_schema = DestinationSchema()
video_schema = VideoSchema(many=True)
broadcasts_schema = BroadcastSchema(many=True)
single_broadcast_schema = BroadcastSchema()

# --- Broadcast & Streaming ---
def _run_stream(app, broadcast_id):
    with app.app_context():
        broadcast = Broadcast.query.get(broadcast_id)
        process = None
        youtube_service = None
        youtube_broadcast_id = None
        try:
            rtmp_outputs = []
            destination_ids = json.loads(broadcast.destination_ids_used)

            for dest_id_str in destination_ids:
                if dest_id_str.startswith('manual-'):
                    db_id = int(dest_id_str.split('-')[1])
                    dest = Destination.query.get(db_id)
                    if dest:
                        rtmp_outputs.append(dest.stream_key)

                elif dest_id_str.startswith('youtube-'):
                    db_id = int(dest_id_str.split('-')[1])
                    account = ConnectedAccount.query.get(db_id)
                    if not account:
                        continue

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
                            "cdn": {
                                "resolution": stream_format,
                                "frameRate": "30fps",
                                "ingestionType": "rtmp"
                            }
                        }
                    ).execute()
                    stream_yt_id = stream_insert['id']

                    broadcast_insert = youtube_service.liveBroadcasts().insert(
                        part="snippet,status,contentDetails",
                        body={
                            "snippet": {
                                "title": broadcast.title,
                                "scheduledStartTime": datetime.utcnow().isoformat() + "Z"
                            },
                            "status": {"privacyStatus": "public"},
                            "contentDetails": {
                                "streamId": stream_yt_id,
                                "enableAutoStart": True,
                                "enableAutoStop": True
                            }
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

            video_url, audio_url = (broadcast.source_url, None)
            if "youtube.com" in video_url or "youtu.be" in video_url:
                yt_dlp_cmd = [
                    'yt-dlp',
                    '-f',
                    'bestvideo[ext=mp4][height<=720]+bestaudio[ext=m4a]/best[ext=mp4]/best',
                    '-g',
                    video_url
                ]
                result = subprocess.run(yt_dlp_cmd, capture_output=True, text=True, check=True)
                urls = result.stdout.strip().split('\n')
                video_url = urls[0]
                if len(urls) > 1:
                    audio_url = urls[1]

            settings = {'scale': '854:480', 'bitrate': '900k', 'bufsize': '1800k'}
            if broadcast.resolution == '720p':
                settings = {'scale': '1280:720', 'bitrate': '1800k', 'bufsize': '3600k'}
            elif broadcast.resolution == '1080p':
                settings = {'scale': '1920:1080', 'bitrate': '3000k', 'bufsize': '6000k'}

            command = ['ffmpeg', '-re', '-i', video_url]
            if audio_url:
                command.extend(['-i', audio_url])
            command.extend([
                '-c:v', 'libx264',
                '-preset', 'veryfast',
                '-vf', f"scale={settings['scale']}",
                '-b:v', settings['bitrate'],
                '-maxrate', settings['bitrate'],
                '-bufsize', settings['bufsize'],
                '-pix_fmt', 'yuv420p',
                '-g', '50',
                '-c:a', 'aac',
                '-b:a', '128k',
                '-ar', '44100'
            ])
            if audio_url:
                command.extend(['-map', '0:v:0', '-map', '1:a:0'])

            for rtmp_url in rtmp_outputs:
                command.extend(['-f', 'flv', rtmp_url])

            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            stream_processes[broadcast.id] = process

            if youtube_service and youtube_broadcast_id:
                time.sleep(15)
                youtube_service.liveBroadcasts().transition(
                    part='id,snippet,status',
                    id=youtube_broadcast_id,
                    broadcastStatus='live'
                ).execute()

            for line in iter(process.stdout.readline, b''):
                if not line:
                    break
                print(f"[FFMPEG - broadcast {broadcast.id}]: {line.decode('utf-8', errors='ignore').strip()}")
            process.wait()

        except Exception as e:
            print(f"!!! STREAM FAILED (Broadcast ID {broadcast.id}) !!! ERROR: {e}")
            broadcast.status = 'failed'
        else:
            if process.returncode == 0:
                print(f"--- Stream finished successfully (Broadcast ID {broadcast.id}) ---")
                broadcast.status = 'finished'
            else:
                print(f"!!! STREAM FAILED (Broadcast ID {broadcast.id}) !!! FFMPEG exited with code: {process.returncode}")
                broadcast.status = 'failed'
        finally:
            broadcast.end_time = datetime.utcnow()
            if youtube_service and youtube_broadcast_id:
                try:
                    youtube_service.liveBroadcasts().transition(
                        part='id,snippet,status',
                        id=youtube_broadcast_id,
                        broadcastStatus='complete'
                    ).execute()
                except HttpError:
                    pass
            if broadcast.id in stream_processes:
                del stream_processes[broadcast.id]
            db.session.commit()

# --- Health Check ---
@app.route('/')
def status():
    return jsonify({"status": "API is online"})

# --- Create DB ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
