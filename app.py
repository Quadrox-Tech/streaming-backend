import os
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, JWTManager
from datetime import timedelta
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import requests # Make sure this is imported

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

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def __init__(self, email, full_name, password=None):
        self.email = email
        self.full_name = full_name
        if password:
            self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# --- API Schemas ---
class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        fields = ("id", "full_name", "email", "created_at")

user_schema = UserSchema()

# --- Auth Endpoints ---
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
    if user and user.password_hash and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)
    return jsonify({"error": "Invalid email or password"}), 401
    
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
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)
    except ValueError as e:
        return jsonify({"error": f"Token verification failed: {e}"}), 401

# --- NEW: User Profile Endpoint ---
@app.route('/api/user/profile', methods=['GET'])
@jwt_required() # This protects the route
def get_user_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(user_schema.dump(user))

# --- Health Check ---
@app.route('/')
def status():
    return jsonify({"status": "API is online"})

# --- Create Database ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
