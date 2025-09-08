import os
import sys
import shlex
import json
import uuid
import signal
import secrets
import logging
import subprocess
from datetime import timedelta, datetime

from flask import Flask, jsonify, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
    JWTManager,
)
from sqlalchemy import desc, or_

# Google / YouTube
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials

# Redis for shared state
import redis

# --- App Initialization & Config ---
app = Flask(__name__)

# Required env
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required")

JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY is required")

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise RuntimeError("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are required")

FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://smartnaijaservices.com.ng")
REDIRECT_URI = os.environ.get(
    "GOOGLE_REDIRECT_URI", "https://smartnaijaservices.com.ng/youtube-callback.html"
)

# Flask config
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

# CORS locked to your frontend
CORS(app, resources={r"/api/*": {"origins": [FRONTEND_URL]}})

db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Logging (structured-ish)
logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("smartnaija.api")

# Redis
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

# YouTube scopes
YOUTUBE_SCOPES = [
    "https://www.googleapis.com/auth/youtube",
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "https://www.googleapis.com/auth/userinfo.profile",
    "openid",
    "email",
]

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)

    destinations = db.relationship(
        "Destination", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    broadcasts = db.relationship(
        "Broadcast", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    videos = db.relationship(
        "Video", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    connected_accounts = db.relationship(
        "ConnectedAccount", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    # password helpers
    def set_password(self, raw_password: str):
        self.password_hash = bcrypt.generate_password_hash(raw_password).decode("utf-8")

    def check_password(self, raw_password: str) -> bool:
        if not self.password_hash:
            return False
        return bcrypt.check_password_hash(self.password_hash, raw_password)


class Destination(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    stream_key = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    video_url = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class ConnectedAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(50), nullable=False)
    account_name = db.Column(db.String(100), nullable=False)
    refresh_token = db.Column(db.String(500), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Broadcast(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pending")
    source_url = db.Column(db.String(500), nullable=False)
    resolution = db.Column(db.String(20), nullable=False, default="480p")
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    destinations_used = db.Column(db.Text, nullable=True)
    destination_ids_used = db.Column(db.Text, nullable=True)


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

# --- Helpers ---
def build_youtube_from_refresh(refresh_token: str):
    creds = Credentials(
        None,
        refresh_token=refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GOOGLE_CLIENT_ID,
        client_secret=GOOGLE_CLIENT_SECRET,
    )
    return build("youtube", "v3", credentials=creds)


def _spawn_ffmpeg(cmd):
    # new process group so we can kill all children
    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid if sys.platform != "win32" else None,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
    )


def _kill_pid_tree(pid: int):
    try:
        if sys.platform == "win32":
            os.kill(pid, signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
    except Exception as e:
        log.warning("Failed graceful kill; terminating. pid=%s err=%s", pid, e)
        try:
            os.kill(pid, signal.SIGKILL if hasattr(signal, "SIGKILL") else signal.SIGTERM)
        except Exception as e2:
            log.error("Failed hard kill. pid=%s err=%s", pid, e2)


def _resolution_settings(res):
    table = {
        "2160p": {"scale": "3840:2160", "bitrate": "13000k", "bufsize": "26000k"},
        "1440p": {"scale": "2560:1440", "bitrate": "9000k", "bufsize": "18000k"},
        "1080p": {"scale": "1920:1080", "bitrate": "4500k", "bufsize": "9000k"},
        "720p": {"scale": "1280:720", "bitrate": "2500k", "bufsize": "5000k"},
        "480p": {"scale": "854:480", "bitrate": "1000k", "bufsize": "2000k"},
        "360p": {"scale": "640:360", "bitrate": "600k", "bufsize": "1200k"},
        "240p": {"scale": "426:240", "bitrate": "300k", "bufsize": "600k"},
    }
    if res not in table:
        log.warning("Invalid or missing resolution '%s'; defaulting to 480p", res)
        return table["480p"]
    return table[res]


def _store_stream_pid(broadcast_id: int, pid: int):
    key = f"stream:pid:{broadcast_id}"
    redis_client.set(key, pid, ex=24 * 3600)  # 1 day TTL


def _get_stream_pid(broadcast_id: int):
    key = f"stream:pid:{broadcast_id}"
    val = redis_client.get(key)
    return int(val) if val else None


def _delete_stream_pid(broadcast_id: int):
    redis_client.delete(f"stream:pid:{broadcast_id}")


def _new_oauth_state(user_id: int) -> str:
    state = secrets.token_urlsafe(32)
    key = f"oauth:state:{state}"
    redis_client.set(key, json.dumps({"uid": user_id, "ts": datetime.utcnow().isoformat()}), ex=600)  # 10 min TTL
    return state


def _consume_oauth_state(state: str):
    key = f"oauth:state:{state}"
    payload = redis_client.get(key)
    if not payload:
        return None
    redis_client.delete(key)
    try:
        return json.loads(payload)
    except Exception:
        return None


# --- Auth Endpoints ---
@app.route("/api/auth/register", methods=["POST"])
def register_user():
    data = request.get_json() or {}
    full_name = data.get("full_name")
    email = data.get("email")
    password = data.get("password")
    if not all([full_name, email, password]):
        return jsonify({"error": "All fields are required"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists"}), 409
    new_user = User(full_name=full_name, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201


@app.route("/api/auth/login", methods=["POST"])
def login_user():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        return jsonify(access_token=create_access_token(identity=user.id))
    return jsonify({"error": "Invalid credentials"}), 401


@app.route("/api/auth/google", methods=["POST"])
def google_auth():
    data = request.get_json() or {}
    token = data.get("token")
    try:
        id_info = id_token.verify_oauth2_token(
            token, google_requests.Request(), GOOGLE_CLIENT_ID
        )
        email = id_info["email"]
        full_name = id_info.get("name") or "Google User"
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, full_name=full_name)
            db.session.add(user)
            db.session.commit()
        return jsonify(access_token=create_access_token(identity=user.id))
    except ValueError:
        return jsonify({"error": "Token verification failed"}), 401


# --- User Profile & Connections Endpoints ---
@app.route("/api/user/profile", methods=["GET", "PUT"])
@jwt_required()
def user_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    if request.method == "PUT":
        data = request.get_json() or {}
        new_name = data.get("full_name")
        if not new_name:
            return jsonify({"error": "Full name is required"}), 400
        user.full_name = new_name
        db.session.commit()
        return jsonify({"message": "Profile updated successfully"}), 200
    if request.method == "GET":
        return jsonify(user_schema.dump(user))


@app.route("/api/destinations", methods=["GET", "POST"])
@jwt_required()
def handle_destinations():
    user_id = get_jwt_identity()
    if request.method == "POST":
        data = request.get_json() or {}
        platform = data.get("platform")
        name = data.get("name")
        stream_key = data.get("stream_key")
        if not all([platform, name, stream_key]):
            return jsonify({"error": "All fields are required"}), 400
        new_destination = Destination(
            platform=platform, name=name, stream_key=stream_key, user_id=user_id
        )
        db.session.add(new_destination)
        db.session.commit()
        return jsonify(single_destination_schema.dump(new_destination)), 201
    dests = Destination.query.filter_by(user_id=user_id).all()
    return jsonify(destinations_schema.dump(dests))


@app.route("/api/destinations/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_destination(id):
    destination = Destination.query.filter_by(
        id=id, user_id=get_jwt_identity()
    ).first()
    if not destination:
        return jsonify({"error": "Destination not found"}), 404
    db.session.delete(destination)
    db.session.commit()
    return jsonify({"message": "Destination deleted"}), 200


@app.route("/api/connected-accounts", methods=["GET"])
@jwt_required()
def get_connected_accounts():
    accounts = ConnectedAccount.query.filter_by(user_id=get_jwt_identity()).all()
    return jsonify(connected_account_schema.dump(accounts))


@app.route("/api/connected-accounts/<int:id>", methods=["DELETE"])
@jwt_required()
def delete_connected_account(id):
    account = ConnectedAccount.query.filter_by(
        id=id, user_id=get_jwt_identity()
    ).first()
    if not account:
        return jsonify({"error": "Account not found"}), 404
    db.session.delete(account)
    db.session.commit()
    return jsonify({"message": "Account disconnected"}), 200


@app.route("/api/connect/youtube", methods=["GET"])
@jwt_required()
def youtube_connect():
    user_id = get_jwt_identity()
    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [REDIRECT_URI],
        }
    }
    flow = Flow.from_client_config(
        client_config, scopes=YOUTUBE_SCOPES, redirect_uri=REDIRECT_URI
    )
    # generate opaque state and keep in redis with TTL
    state = _new_oauth_state(user_id)
    authorization_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes="true",
        state=state,
    )
    return jsonify({"authorization_url": authorization_url})


@app.route("/api/connect/youtube/callback")
def youtube_callback():
    state = request.args.get("state")
    if not state:
        return "Error: Missing state.", 400
    decoded = _consume_oauth_state(state)
    if not decoded:
        return "Error: Invalid or expired state.", 400
    user_id = decoded.get("uid")

    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [REDIRECT_URI],
        }
    }
    flow = Flow.from_client_config(
        client_config, scopes=YOUTUBE_SCOPES, state=state, redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    refresh_token = credentials.refresh_token

    oauth2 = build("oauth2", "v2", credentials=credentials)
    user_info = oauth2.userinfo().get().execute()
    account_name = user_info.get("name", "YouTube Account")

    existing_account = ConnectedAccount.query.filter_by(
        user_id=user_id, platform="YouTube"
    ).first()
    if existing_account:
        existing_account.refresh_token = refresh_token
        existing_account.account_name = account_name
    else:
        db.session.add(
            ConnectedAccount(
                platform="YouTube",
                account_name=account_name,
                refresh_token=refresh_token,
                user_id=user_id,
            )
        )
    db.session.commit()
    return redirect(f"{FRONTEND_URL}/profile.html")


@app.route("/api/all-possible-destinations", methods=["GET"])
@jwt_required()
def get_all_possible_destinations():
    user_id = get_jwt_identity()
    all_destinations = []

    # Manual RTMP destinations
    for dest in Destination.query.filter_by(user_id=user_id).all():
        all_destinations.append(
            {
                "id": f"manual-{dest.id}",
                "platform": dest.platform,
                "name": f"{dest.platform}: {dest.name}",
                "type": "manual",
                "eligible": True,
                "reason": "",
            }
        )

    # YouTube connected accounts
    for account in ConnectedAccount.query.filter_by(
        user_id=user_id, platform="YouTube"
    ).all():
        dest_info = {
            "id": f"youtube-{account.id}",
            "platform": "YouTube",
            "name": f"YouTube: {account.account_name}",
            "type": "connected",
            "eligible": True,  # default to True; strict checks can be noisy
            "reason": "",
        }
        try:
            youtube = build_youtube_from_refresh(account.refresh_token)
            youtube.channels().list(part="id", mine=True).execute()
        except HttpError as e:
            log.warning("YouTube eligibility probe failed: %s", e)
            dest_info.update(
                {"eligible": False, "reason": "API Error: Could not verify channel."}
            )
        all_destinations.append(dest_info)

    return jsonify(all_destinations)


# --- Broadcast & Streaming Endpoints ---
@app.route("/api/broadcasts", methods=["POST"])
@jwt_required()
def create_broadcast():
    user_id = get_jwt_identity()
    data = request.get_json() or {}
    title = data.get("title")
    source_url = data.get("source_url")
    destination_ids = data.get("destination_ids")
    resolution = data.get("resolution", "480p")

    if not all([title, source_url, destination_ids]):
        return jsonify({"error": "Missing required fields"}), 400

    dest_names = []
    for dest_id_str in destination_ids:
        if dest_id_str.startswith("manual-"):
            db_id = int(dest_id_str.split("-")[1])
            dest = Destination.query.get(db_id)
            if dest and dest.user_id == user_id:
                dest_names.append(f"{dest.platform}: {dest.name}")
        elif dest_id_str.startswith("youtube-"):
            db_id = int(dest_id_str.split("-")[1])
            acc = ConnectedAccount.query.get(db_id)
            if acc and acc.user_id == user_id:
                dest_names.append(f"YouTube: {acc.account_name}")

    if not dest_names:
        return jsonify({"error": "Invalid destination IDs"}), 400

    broadcast = Broadcast(
        user_id=user_id,
        source_url=source_url,
        title=title,
        destinations_used=", ".join(dest_names),
        destination_ids_used=json.dumps(destination_ids),
        resolution=resolution,
    )
    db.session.add(broadcast)
    db.session.commit()
    return jsonify(single_broadcast_schema.dump(broadcast)), 201


@app.route("/api/broadcasts", methods=["GET"])
@jwt_required()
def get_broadcasts():
    user_id = get_jwt_identity()
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    broadcasts = (
        Broadcast.query.filter(
            Broadcast.user_id == user_id,
            or_(
                Broadcast.start_time == None,
                Broadcast.start_time > thirty_days_ago,
                Broadcast.status.in_(["live", "pending"]),
            ),
        )
        .order_by(desc(Broadcast.id))
        .all()
    )
    return jsonify(broadcasts_schema.dump(broadcasts))


@app.route("/api/broadcasts/<int:broadcast_id>/start", methods=["POST"])
@jwt_required()
def start_stream(broadcast_id):
    user_id = get_jwt_identity()
    broadcast = Broadcast.query.get(broadcast_id)
    if not broadcast or broadcast.user_id != user_id or broadcast.status != "pending":
        return jsonify({"error": "Broadcast not found or not pending"}), 404

    try:
        rtmp_outputs = []
        destination_ids = json.loads(broadcast.destination_ids_used or "[]")

        # Build RTMP outputs
        for dest_id_str in destination_ids:
            if dest_id_str.startswith("manual-"):
                db_id = int(dest_id_str.split("-")[1])
                dest = Destination.query.get(db_id)
                if dest and dest.stream_key:
                    rtmp_outputs.append(dest.stream_key)

            elif dest_id_str.startswith("youtube-"):
                db_id = int(dest_id_str.split("-")[1])
                account = ConnectedAccount.query.get(db_id)
                if not account:
                    continue

                youtube = build_youtube_from_refresh(account.refresh_token)

                # resolution guard
                stream_format = broadcast.resolution or "480p"
                if stream_format not in [
                    "2160p",
                    "1440p",
                    "1080p",
                    "720p",
                    "480p",
                    "360p",
                    "240p",
                ]:
                    log.warning("Invalid resolution '%s'; defaulting to 480p", stream_format)
                    stream_format = "480p"

                log.info("Creating YouTube Live Stream title='%s' res='%s'",
                         broadcast.title, stream_format)

                stream_insert_body = {
                    "snippet": {"title": broadcast.title},
                    "cdn": {"format": stream_format, "ingestionType": "rtmp"},
                }

                stream_insert = (
                    youtube.liveStreams()
                    .insert(part="snippet,cdn,status", body=stream_insert_body)
                    .execute()
                )
                stream_yt_id = stream_insert["id"]

                # Create broadcast and bind to stream
                _ = (
                    youtube.liveBroadcasts()
                    .insert(
                        part="snippet,status,contentDetails",
                        body={
                            "snippet": {
                                "title": broadcast.title,
                                "scheduledStartTime": datetime.utcnow().isoformat() + "Z",
                            },
                            "status": {"privacyStatus": "private"},
                            "contentDetails": {
                                "streamId": stream_yt_id,
                                "enableAutoStart": True,
                                "enableAutoStop": True,
                            },
                        },
                    )
                    .execute()
                )

                ingestion = stream_insert["cdn"]["ingestionInfo"]
                ingestion_address = ingestion["ingestionAddress"]
                stream_name = ingestion["streamName"]
                rtmp_outputs.append(f"{ingestion_address}/{stream_name}")

        if not rtmp_outputs:
            return jsonify({"error": "No valid stream destinations found."}), 400

        # Prepare input(s)
        video_url = broadcast.source_url
        audio_url = None

        # If YouTube URL, resolve to media URLs with yt-dlp
        if "youtube.com" in video_url or "youtu.be" in video_url:
            yt_dlp_cmd = [
                "yt-dlp",
                "-f",
                "bestvideo[ext=mp4][height<=1080]+bestaudio[ext=m4a]/best[ext=mp4]/best",
                "-g",
                video_url,
            ]
            result = subprocess.run(
                yt_dlp_cmd, capture_output=True, text=True, check=True
            )
            urls = [u for u in result.stdout.strip().split("\n") if u.strip()]
            if len(urls) >= 2:
                video_url, audio_url = urls[0], urls[1]
            else:
                video_url = urls[0]
                audio_url = None

        # Output encoding settings
        s = _resolution_settings(broadcast.resolution)
        gop = "60"  # ~2s at 30fps

        command = ["ffmpeg", "-re", "-i", video_url]
        if audio_url:
            command.extend(["-i", audio_url])

        # Mapping
        if audio_url:
            io_map = ["-map", "0:v:0", "-map", "1:a:0"]
        else:
            io_map = ["-map", "0:v:0", "-map", "0:a:0?"]

        enc = [
            "-c:v", "libx264",
            "-preset", "veryfast",
            "-vf", f"scale={s['scale']}",
            "-b:v", s["bitrate"],
            "-maxrate", s["bitrate"],
            "-bufsize", s["bufsize"],
            "-pix_fmt", "yuv420p",
            "-g", gop, "-keyint_min", gop,
            "-c:a", "aac", "-b:a", "128k", "-ar", "44100",
        ]

        command.extend(io_map + enc)

        # Push to all RTMP outputs (single process)
        for rtmp_url in rtmp_outputs:
            if rtmp_url:
                command.extend(["-f", "flv", rtmp_url])

        log.info("Starting FFmpeg cmd=%s", shlex.join(command))

        process = _spawn_ffmpeg(command)
        _store_stream_pid(broadcast_id, process.pid)

        broadcast.status = "live"
        broadcast.start_time = datetime.utcnow()
        db.session.commit()
        return jsonify({"message": "Stream started"})

    except subprocess.CalledProcessError as e:
        broadcast.status = "failed"
        db.session.commit()
        log.exception("yt-dlp error: %s", e.stderr)
        return (
            jsonify({"error": "Failed to get video source URL.", "details": e.stderr}),
            500,
        )
    except HttpError as e:
        broadcast.status = "failed"
        db.session.commit()
        log.exception("YouTube API error: %s", e)
        return jsonify({"error": f"An error occurred with the YouTube API: {e}"}), 500
    except Exception as e:
        broadcast.status = "failed"
        db.session.commit()
        log.exception("General error: %s", e)
        return jsonify({"error": "An unexpected error occurred."}), 500


@app.route("/api/broadcasts/<int:broadcast_id>/stop", methods=["POST"])
@jwt_required()
def stop_stream(broadcast_id):
    broadcast = Broadcast.query.get(broadcast_id)
    if not broadcast or broadcast.user_id != get_jwt_identity():
        return jsonify({"error": "Broadcast not found"}), 404

    pid = _get_stream_pid(broadcast_id)
    if pid:
        _kill_pid_tree(pid)
        _delete_stream_pid(broadcast_id)

    broadcast.status = "finished"
    broadcast.end_time = datetime.utcnow()
    db.session.commit()

    return jsonify({"message": "Stream stopped"})


# --- Health Check ---
@app.route("/")
def status():
    return jsonify({"status": "API is online", "version": "1.0.0"})


# --- Create DB ---
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
