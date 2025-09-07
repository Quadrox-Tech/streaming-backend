import os
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
from datetime import timedelta
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# --- App Initialization ---
app = Flask(__name__)
CORS(app)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-super-secret-key')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID') # You will add this to Railway variables

# --- Initialize Extensions ---
db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# --- Database Models (User model updated) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False) # <-- NEW FIELD
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True) # <-- Nullable for Google users
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def __init__(self, email, full_name, password=None):
        self.email = email
        self.full_name = full_name
        if password:
            self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# --- Auth Endpoints (register updated, new Google endpoint) ---
@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')

    if not all([full_name, email, password]):
        return jsonify({"error": "Full name, email, and password are required"}), 400
        
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email address already registered"}), 409

    new_user = User(full_name=full_name, email=email, password=password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/api/auth/login', methods=['POST'])
def login_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = User.query.filter_by(email=email).first()

    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)
    
    return jsonify({"error": "Invalid email or password"}), 401
    
@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    data = request.get_json()
    token = data.get('token')
    
    try:
        # Verify the token with Google
        id_info = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        
        email = id_info['email']
        full_name = id_info['name']
        
        # Check if user already exists
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # If user doesn't exist, create a new one without a password
            user = User(email=email, full_name=full_name)
            db.session.add(user)
            db.session.commit()
            
        # Create an access token for the user
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)

    except ValueError as e:
        # Invalid token
        return jsonify({"error": f"Token verification failed: {e}"}), 401

# --- Health Check ---
@app.route('/')
def status():
    return jsonify({"status": "API is online"})

# --- Create Database ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
