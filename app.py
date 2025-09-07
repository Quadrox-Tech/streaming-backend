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
from googleapiclient.discovery import build # Correctly imported here
import requests

# --- App Initialization & Config ---
app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-super-secret-key')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
# This must match what you put in the Google Cloud Console
# IMPORTANT: Remember to change 'yourdomain.com' to your actual domain
REDIRECT_URI = 'https://yourdomain.com/youtube-callback.html' 

db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

stream_processes = {}

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

    def __init__(self, email, full_name, password=None):
        self.email = email
        self.full_name = full_name
        if password: self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    def check_password(self, password): return bcrypt.check_password_hash(self.password_hash, password)

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
    class Meta: model = ConnectedAccount; include_fk = True
class VideoSchema(ma.SQLAlchemyAutoSchema):
    class Meta: model = Video; include_fk = True
class BroadcastSchema(ma.SQLAlchemyAutoSchema):
    class Meta: model = Broadcast; include_fk = True

user_schema=UserSchema(); single_destination_schema=DestinationSchema(); destinations_schema=DestinationSchema(many=True); connected_account_schema=ConnectedAccountSchema(many=True); video_schema=VideoSchema(many=True); broadcasts_schema=BroadcastSchema(many=True); single_broadcast_schema=BroadcastSchema()

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
@app.route('/api/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile(): return jsonify(user_schema.dump(User.query.get(get_jwt_identity())))

# --- Destination Endpoints ---
@app.route('/api/destinations', methods=['GET'])
@jwt_required()
def get_destinations():
    destinations = Destination.query.filter_by(user_id=get_jwt_identity()).all()
    return jsonify(destinations_schema.dump(destinations))

@app.route('/api/destinations', methods=['POST'])
@jwt_required()
def add_destination():
    user_id = get_jwt_identity(); data = request.get_json(); platform = data.get('platform'); name = data.get('name'); stream_key = data.get('stream_key')
    if not all([platform, name, stream_key]): return jsonify({"error": "All fields are required"}), 400
    new_destination = Destination(platform=platform, name=name, stream_key=stream_key, user_id=user_id)
    db.session.add(new_destination); db.session.commit()
    return jsonify(single_destination_schema.dump(new_destination)), 201

@app.route('/api/destinations/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_destination(id):
    destination = Destination.query.filter_by(id=id, user_id=get_jwt_identity()).first()
    if not destination: return jsonify({"error": "Destination not found"}), 404
    db.session.delete(destination); db.session.commit()
    return jsonify({"message": "Destination deleted"}), 200

# --- Video Library Endpoints ---
@app.route('/api/videos', methods=['GET'])
@jwt_required()
def get_videos(): return jsonify(video_schema.dump(Video.query.filter_by(user_id=get_jwt_identity()).all()))

# --- YouTube Connection Endpoints ---
@app.route('/api/connect/youtube', methods=['GET'])
@jwt_required()
def youtube_connect():
    flow = Flow.from_client_secrets_file(
        'client_secret.json', # Assumes you have downloaded this file
        scopes=[
            "https://www.googleapis.com/auth/youtube.readonly",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email"
        ],
        redirect_uri=REDIRECT_URI
    )
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    user_id = get_jwt_identity()
    # Store the state with the user ID so we can retrieve it in the callback
    # A real app would use a database for this, but this is a simple example
    # For now, we pass it in the state parameter.
    app.config[f'STATE_{state}'] = user_id
    
    return jsonify({'authorization_url': authorization_url})

@app.route('/api/connect/youtube/callback')
def youtube_callback():
    state = request.args.get('state')
    user_id = app.config.pop(f'STATE_{state}', None) # Retrieve and remove the user_id

    if not user_id:
        return "Error: State mismatch or user ID not found.", 400

    flow = Flow.from_client_secrets_file('client_secret.json', scopes=None, state=state, redirect_uri=REDIRECT_URI)
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    refresh_token = credentials.refresh_token

    # Use the token to get the user's name
    user_info_service = build('oauth2', 'v2', credentials=credentials)
    user_info = user_info_service.userinfo().get().execute()
    account_name = user_info.get('name', 'YouTube Account')
    
    existing_account = ConnectedAccount.query.filter_by(user_id=user_id, platform='YouTube').first()
    if existing_account:
        existing_account.refresh_token = refresh_token
        existing_account.account_name = account_name
    else:
        new_account = ConnectedAccount(platform='YouTube', account_name=account_name, refresh_token=refresh_token, user_id=user_id)
        db.session.add(new_account)
    
    db.session.commit()
    
    return redirect('/destinations.html')

# --- (All other endpoints for Broadcasts remain the same) ---

# --- Create DB ---
with app.app_context(): db.create_all()
if __name__ == '__main__': app.run(host='0.0.0.0', port=8000)


## Step 3: Full Frontend Files
A. profile.html (Final Version)
This file is now complete with the working "Connect YouTube Account" button.
Your Task: Replace the code in profile.html.
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Profile - StreamHub</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
</head>
<body class="bg-gray-900 text-white font-sans">
    <div class="md:flex h-screen">
        <main class="flex-1 p-6 md:p-10 overflow-y-auto">
            <h2 class="text-3xl font-bold">My Profile</h2>
            <p class="text-gray-400 mt-2">Manage your account settings and connections.</p>
            <div class="mt-8 max-w-xl space-y-8">
                 <form id="profile-form" class="bg-gray-800 p-6 rounded-lg">
                    <h3 class="text-xl font-semibold mb-4">Account Information</h3>
                    <div class="space-y-4">
                        <div><label for="full_name" class="text-sm text-gray-400">Full Name</label><input type="text" id="full_name" class="mt-1 w-full bg-gray-700 rounded p-3 text-white border border-gray-600"></div>
                        <div><label for="email" class="text-sm text-gray-400">Email Address</label><input type="email" id="email" class="mt-1 w-full bg-gray-700 rounded p-3 text-gray-400 border border-gray-600" disabled></div>
                    </div>
                    <button type="submit" class="mt-6 w-full bg-indigo-500 hover:bg-indigo-600 text-white font-bold py-3 px-4 rounded-lg">Save Changes</button>
                 </form>

                 <div class="bg-gray-800 p-6 rounded-lg">
                    <h3 class="text-xl font-semibold mb-4">Connect Accounts</h3>
                    <div class="space-y-4">
                        <button id="connect-youtube" class="w-full bg-red-600 hover:bg-red-700 text-white font-bold py-3 px-4 rounded-lg flex items-center justify-center"><i class="fab fa-youtube mr-2"></i>Connect YouTube Account</button>
                        <button id="connect-facebook" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg flex items-center justify-center"><i class="fab fa-facebook mr-2"></i>Connect Facebook Account</button>
                    </div>
                    <p class="text-xs text-gray-500 mt-4 text-center">Facebook integration is coming soon.</p>
                 </div>
                 
                 <button id="logout-btn" class="w-full bg-gray-700 hover:bg-gray-600 text-white font-bold py-3 px-4 rounded-lg">Logout</button>
            </div>
        </main>
        
        <!-- Navigation -->
        <aside class="hidden md:flex w-64 bg-gray-800 p-6 flex-col justify-between"><div><h1 class="text-2xl font-bold text-indigo-400 mb-10">StreamHub</h1><nav class="space-y-2"><a href="dashboard.html" class="text-gray-300 hover:bg-gray-700 flex items-center py-2.5 px-4 rounded"><i class="fas fa-home w-6"></i>Dashboard</a><a href="destinations.html" class="text-gray-300 hover:bg-gray-700 flex items-center py-2.5 px-4 rounded"><i class="fas fa-satellite-dish w-6"></i>Destinations</a><a href="broadcasts.html" class="text-gray-300 hover:bg-gray-700 flex items-center py-2.5 px-4 rounded"><i class="fas fa-video w-6"></i>Broadcasts</a></nav></div><a href="profile.html" class="bg-gray-700 text-white w-full font-bold py-2 px-4 rounded-lg text-center">Profile</a></aside><nav class="md:hidden fixed bottom-0 left-0 right-0 bg-gray-800 border-t border-gray-700 flex justify-around"><a href="dashboard.html" class="flex-1 text-center py-3 text-gray-300"><i class="fas fa-home"></i><span class="block text-xs">Dashboard</span></a><a href="destinations.html" class="flex-1 text-center py-3 text-gray-300"><i class="fas fa-satellite-dish"></i><span class="block text-xs">Destinations</span></a><a href="broadcasts.html" class="flex-1 text-center py-3 text-gray-300"><i class="fas fa-video"></i><span class="block text-xs">Broadcasts</span></a><a href="profile.html" class="flex-1 text-center py-3 text-indigo-400"><i class="fas fa-user-circle"></i><span class="block text-xs">Profile</span></a></nav>
    </div>
    <script>
        const API_BASE_URL = 'https://streaming-backend-production-66db.up.railway.app';
        const token = localStorage.getItem('access_token');
        if (!token) { window.location.href = 'login.html'; }

        async function loadProfile() {
            const response = await fetch(`${API_BASE_URL}/api/user/profile`, { headers: { 'Authorization': `Bearer ${token}` } });
            const user = await response.json();
            document.getElementById('full_name').value = user.full_name;
            document.getElementById('email').value = user.email;
        }

        document.getElementById('logout-btn').addEventListener('click', () => {
            localStorage.removeItem('access_token');
            window.location.href = 'login.html';
        });
        
        document.getElementById('connect-youtube').addEventListener('click', async () => {
            try {
                const response = await fetch(`${API_BASE_URL}/api/connect/youtube`, { headers: { 'Authorization': `Bearer ${token}` } });
                const data = await response.json();
                if(data.authorization_url) { window.location.href = data.authorization_url; }
            } catch(e) { console.error('Failed to start YouTube connect flow', e); }
        });
        
        document.addEventListener('DOMContentLoaded', loadProfile);
    </script>
</body>
</html>

B. youtube-callback.html (New File)
This is the new, required file for the Google redirect.
Your Task: Create a new file named youtube-callback.html.
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Connecting to YouTube...</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-white flex items-center justify-center h-screen">
    <div class="text-center">
        <h1 class="text-2xl font-bold">Connecting your YouTube account...</h1>
        <p class="text-gray-400 mt-2">Please wait, you will be redirected shortly.</p>
    </div>
    <script>
        const API_BASE_URL = 'https://streaming-backend-production-66db.up.railway.app';
        const params = new URLSearchParams(window.location.search);
        
        // This page's only job is to forward the parameters from Google to our backend.
        // The backend will then exchange the code for a token and redirect back to the app.
        if (params.get('code') && params.get('state')) {
            window.location.href = `${API_BASE_URL}/api/connect/youtube/callback?${params.toString()}`;
        } else {
            // Handle error case
            document.querySelector('h1').textContent = 'Connection Failed';
            document.querySelector('p').textContent = 'Could not connect to YouTube. Please try again from your profile page.';
        }
    </script>
</body>
</html>
