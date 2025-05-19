import os
import json
import datetime
from functools import wraps

from flask import Flask, request, jsonify
from pymongo import MongoClient
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

# Use environment variables for sensitive information
# Default to a local MongoDB for development if no environment variable is set
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/arcade_app')
JWT_SECRET = os.environ.get('JWT_SECRET', 'secret_key_for_development')

# MongoDB connection with error handling
try:
    # Create a new client and connect to the server
    client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
    # Send a ping to confirm a successful connection
    client.admin.command('ping')
    print("MongoDB connection successful!")
    db = client.arcade_app
    users_collection = db.users_authentication
    information_collection = db.users_information
except Exception as e:
    print(f"MongoDB connection error: {e}")
    # Set up a flag to indicate MongoDB is unavailable
    db_available = False
else:
    db_available = True

# Middleware to check if DB is available
@app.before_request
def check_db_connection():
    # Skip the check for static resources and the health endpoint
    if request.path.startswith('/static/') or request.path == '/health':
        return
    
    if not db_available:
        return jsonify({"status": "error", "message": "Database unavailable"}), 503

# JWT token verification decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        if not token:
            return jsonify({"status": "error", "message": "Token is missing"}), 401
        
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            current_user = users_collection.find_one({"username": data['username']})
            if not current_user:
                return jsonify({"status": "error", "message": "Invalid token"}), 401
        except:
            return jsonify({"status": "error", "message": "Invalid token"}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "database": "connected" if db_available else "disconnected"}), 200

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password required"}), 400
    
    try:
        if users_collection.find_one({"username": username}):
            return jsonify({"status": "error", "message": "Username already exists"}), 400
        
        # Hash the password for security
        hashed_password = generate_password_hash(password)
        
        users_collection.insert_one({"username": username, "password": hashed_password})
        information_collection.insert_one({"username": username, "score": 0})  # Initialize score
        
        return jsonify({"status": "success", "message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"status": "error", "message": f"Registration failed: {str(e)}"}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    username = data.get("username")
    password = data.get("password")
    
    try:
        user = users_collection.find_one({"username": username})
        
        if not user or not check_password_hash(user["password"], password):
            return jsonify({"status": "error", "message": "Invalid username or password"}), 401
        
        # Generate JWT token
        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }, JWT_SECRET, algorithm="HS256")
        
        score_entry = information_collection.find_one({"username": username})
        score = score_entry["score"] if score_entry else 0
        
        return jsonify({
            "status": "success", 
            "username": username, 
            "score": score,
            "token": token
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"Login failed: {str(e)}"}), 500

@app.route('/update_score', methods=['POST'])
@token_required
def update_score(current_user):
    data = request.get_json()
    
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    username = current_user["username"]
    score = data.get("score")
    
    if score is None:
        return jsonify({"status": "error", "message": "Score is required"}), 400
    
    try:
        information_collection.update_one({"username": username}, {"$set": {"score": score}}, upsert=True)
        return jsonify({"status": "success", "message": "Score updated successfully"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"Score update failed: {str(e)}"}), 500

@app.route('/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    username = current_user["username"]
    try:
        score_entry = information_collection.find_one({"username": username})
        
        if not score_entry:
            return jsonify({"status": "error", "message": "User profile not found"}), 404
        
        return jsonify({
            "status": "success", 
            "username": username, 
            "score": score_entry["score"]
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"Profile retrieval failed: {str(e)}"}), 500

@app.route('/get_score', methods=['GET'])
@token_required
def get_score(current_user):
    username = current_user["username"]
    try:
        score_entry = information_collection.find_one({"username": username})
        
        if not score_entry:
            return jsonify({"status": "error", "message": "User not found"}), 404
        
        return jsonify({
            "status": "success", 
            "username": username, 
            "score": score_entry["score"]
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"Score retrieval failed: {str(e)}"}), 500

@app.route('/scoreboard', methods=['GET'])
@token_required
def get_scoreboard(current_user):
    try:
        scores = list(information_collection.find().sort("score", -1))
        scoreboard = [{"username": entry["username"], "score": entry["score"]} for entry in scores]
        return jsonify({"status": "success", "scoreboard": scoreboard}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"Scoreboard retrieval failed: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.getenv("PORT", 80))  # Default to port 80 if PORT isn't set
    app.run(host="0.0.0.0", port=port, debug=True)
