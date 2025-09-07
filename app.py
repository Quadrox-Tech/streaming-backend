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
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests

# --- App Initialization ---
app = Flask(__name__)
CORS(app)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-super-secret-key')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')

# --- Initialize Extensions ---
db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# --- Database Models (User updated, Broadcast added) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    profile_picture_url = db.Column(db.String(255), nullable=True) # <-- NEW
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    destinations = db.relationship('Destination', backref='user', lazy=True, cascade="all, delete-orphan")
    broadcasts = db.relationship('Broadcast', backref='user', lazy=True, cascade="all, delete-orphan") # <-- NEW

    def __init__(self, email, full_name, password=None):
        self.email = email
        self.full_name = full_name
        if password:
            self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Destination(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    stream_key = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Broadcast(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, default="Untitled Broadcast")
    status = db.Column(db.String(20), nullable=False, default='finished') # 'live' or 'finished'
    source_url = db.Column(db.String(500), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # We will store destinations as a simple comma-separated string of names
    destinations_used = db.Column(db.Text, nullable=True)

# --- API Schemas ---
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        fields = ("id", "full_name", "email", "profile_picture_url", "created_at")

class DestinationSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Destination
        include_fk = True
        
class BroadcastSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Broadcast
        include_fk = True

user_schema = UserSchema()
destination_schema = DestinationSchema()
destinations_schema = DestinationSchema(many=True)
broadcast_schema = BroadcastSchema()
broadcasts_schema = BroadcastSchema(many=True)

# --- Auth Endpoints (Unchanged) ---
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
    except ValueError as e: return jsonify({"error": f"Token verification failed: {e}"}), 401

# --- User Profile Endpoints ---
@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():
    user = User.query.get(get_jwt_identity()); return jsonify(user_schema.dump(user))

@app.route('/api/user/profile', methods=['PUT'])
@jwt_required()
def update_user_profile():
    user = User.query.get(get_jwt_identity())
    data = request.get_json()
    if 'full_name' in data: user.full_name = data['full_name']
    if 'profile_picture_url' in data: user.profile_picture_url = data['profile_picture_url']
    db.session.commit()
    return jsonify(user_schema.dump(user))

# --- Destination Endpoints (Unchanged) ---
@app.route('/api/destinations', methods=['POST'])
@jwt_required()
def add_destination():
    user_id = get_jwt_identity(); data = request.get_json(); platform = data.get('platform'); name = data.get('name'); stream_key = data.get('stream_key')
    if not all([platform, name, stream_key]): return jsonify({"error": "All fields are required"}), 400
    new_destination = Destination(platform=platform, name=name, stream_key=stream_key, user_id=user_id)
    db.session.add(new_destination); db.session.commit()
    return jsonify(destination_schema.dump(new_destination)), 201

@app.route('/api/destinations', methods=['GET'])
@jwt_required()
def get_destinations():
    destinations = Destination.query.filter_by(user_id=get_jwt_identity()).all()
    return jsonify(destinations_schema.dump(destinations))

@app.route('/api/destinations/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_destination(id):
    destination = Destination.query.filter_by(id=id, user_id=get_jwt_identity()).first()
    if not destination: return jsonify({"error": "Destination not found"}), 404
    db.session.delete(destination); db.session.commit()
    return jsonify({"message": "Destination deleted"}), 200

# --- Broadcast Endpoints ---
@app.route('/api/broadcasts', methods=['GET'])
@jwt_required()
def get_broadcasts():
    # Fetch broadcasts from the last 30 days, plus any that are currently live
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    broadcasts = Broadcast.query.filter_by(user_id=get_jwt_identity()).filter(
        (Broadcast.start_time > thirty_days_ago) | (Broadcast.status == 'live')
    ).order_by(Broadcast.start_time.desc()).all()
    return jsonify(broadcasts_schema.dump(broadcasts))

# --- Health Check ---
@app.route('/')
def status():
    return jsonify({"status": "API is online"})

# --- Create Database Tables ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
