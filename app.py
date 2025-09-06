import os
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
from datetime import timedelta

# --- App Initialization ---
app = Flask(__name__)
CORS(app)

# --- Database Configuration ---
# Railway provides the DATABASE_URL environment variable automatically
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- JWT Configuration ---
# You need to set a JWT_SECRET_KEY in your Railway environment variables
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-super-secret-key')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24) # Tokens will expire after 24 hours

# --- Initialize Extensions ---
db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# --- Database Models (The structure of our tables) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    def __init__(self, email, password):
        self.email = email
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# We will add the 'Destination' model in the next phase
# We will also add the streaming logic back in later


# --- API Endpoints for User Authentication ---
@app.route('/api/auth/register', methods=['POST'])
def register_user():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
        
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email address already registered"}), 409

    new_user = User(email=email, password=password)
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


# --- Health Check Endpoint ---
@app.route('/')
def status():
    return jsonify({"status": "API is online"})


# --- Create Database Tables ---
# This command will create the 'user' table based on our model
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
