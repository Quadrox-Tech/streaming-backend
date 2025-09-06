import os
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow

# Initialize the application
app = Flask(__name__)

# --- Database Configuration ---
# Set the base directory for our app
basedir = os.path.abspath(os.path.dirname(__file__))
# Configure the SQLite database. It will be a file named 'db.sqlite'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database and Marshmallow
db = SQLAlchemy(app)
ma = Marshmallow(app)
# --- End of Configuration ---


# --- Database Model (The structure of our StreamKey table) ---
class StreamKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    platform = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    key = db.Column(db.String(200), unique=True, nullable=False)

    def __init__(self, platform, name, key):
        self.platform = platform
        self.name = name
        self.key = key
# --- End of Model ---


# --- API Schema (Defines what fields to show in the API response) ---
class StreamKeySchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = StreamKey
        load_instance = True
# --- End of Schema ---


# --- API Endpoints (The URLs for our API) ---

# Endpoint to add a new stream key
@app.route('/api/keys', methods=['POST'])
def add_key():
    platform = request.json.get('platform')
    name = request.json.get('name')
    key = request.json.get('key')

    if not all([platform, name, key]):
        return jsonify({"error": "Missing data"}), 400

    new_key = StreamKey(platform, name, key)
    db.session.add(new_key)
    db.session.commit()

    key_schema = StreamKeySchema()
    return jsonify(key_schema.dump(new_key))

# Endpoint to get all stream keys
@app.route('/api/keys', methods=['GET'])
def get_keys():
    all_keys = StreamKey.query.all()
    keys_schema = StreamKeySchema(many=True)
    return jsonify(keys_schema.dump(all_keys))

# Endpoint to delete a stream key
@app.route('/api/keys/<int:id>', methods=['DELETE'])
def delete_key(id):
    key = StreamKey.query.get(id)
    if not key:
        return jsonify({"error": "Key not found"}), 404
        
    db.session.delete(key)
    db.session.commit()
    return jsonify({"message": "Key deleted successfully"})

# Health check endpoint
@app.route('/')
def status():
    return jsonify({"status": "Streaming server is online"})

# --- End of Endpoints ---

# Create the database tables before the first request
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)

