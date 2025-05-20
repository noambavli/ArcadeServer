import os
import json
import datetime
from functools import wraps
from typing import Dict, Any, Optional

from flask import Flask, request, jsonify
from pymongo import MongoClient
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException

app = Flask(__name__)
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

# Use environment variables for sensitive information
# Default to a local MongoDB for development if no environment variable is set
MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/arcade_app')
JWT_SECRET = os.environ.get('JWT_SECRET', 'secret_key_for_development')

# Custom error classes
class APIError(Exception):
    def __init__(self, message: str, status_code: int = 500, payload: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.message = message
        self.status_code = status_code
        self.payload = payload

    def to_dict(self) -> Dict[str, Any]:
        rv = dict(self.payload or ())
        rv['status'] = 'error'
        rv['message'] = self.message
        return rv

class ValidationError(APIError):
    def __init__(self, message: str, payload: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=400, payload=payload)

class AuthenticationError(APIError):
    def __init__(self, message: str, payload: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=401, payload=payload)

class DatabaseError(APIError):
    def __init__(self, message: str, payload: Optional[Dict[str, Any]] = None):
        super().__init__(message, status_code=503, payload=payload)

# Error handlers
@app.errorhandler(APIError)
def handle_api_error(error: APIError):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response

@app.errorhandler(HTTPException)
def handle_http_error(error: HTTPException):
    response = jsonify({
        'status': 'error',
        'message': error.description
    })
    response.status_code = error.code
    return response

@app.errorhandler(Exception)
def handle_generic_error(error: Exception):
    response = jsonify({
        'status': 'error',
        'message': 'An unexpected error occurred'
    })
    response.status_code = 500
    return response

# Improved MongoDB connection with better error handling
try:
    client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
    client.admin.command('ping')
    print("MongoDB connection successful!")
    db = client.arcade_app
    users_collection = db.users_authentication
    information_collection = db.users_information
except Exception as e:
    print(f"MongoDB connection error: {e}")
    db_available = False
    raise DatabaseError("Database connection failed", {"error": str(e)})
else:
    db_available = True

# Improved middleware
@app.before_request
def check_db_connection():
    if request.path.startswith('/static/') or request.path == '/health':
        return
    
    if not db_available:
        raise DatabaseError("Database unavailable")

# Improved token verification
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
        
        if not token:
            raise AuthenticationError("Token is missing")
        
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            current_user = users_collection.find_one({"username": data['username']})
            if not current_user:
                raise AuthenticationError("Invalid token")
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid token")
        
        return f(current_user, *args, **kwargs)
    
    return decorated

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "database": "connected" if db_available else "disconnected"}), 200

# Improved register endpoint
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        
        if not data:
            raise ValidationError("Please provide registration details")
        
        username = data.get("username")
        password = data.get("password")
        
        if not username or not password:
            raise ValidationError("Both username and password are required")
        
        if len(username) < 3:
            raise ValidationError("Username must be at least 3 characters long")
        
        if len(password) < 6:
            raise ValidationError("Password must be at least 6 characters long for security")
        
        if users_collection.find_one({"username": username}):
            raise ValidationError("This username is already taken. Please choose a different one")
        
        hashed_password = generate_password_hash(password)
        
        users_collection.insert_one({"username": username, "password": hashed_password})
        information_collection.insert_one({"username": username, "score": 0})
        
        return jsonify({"status": "success", "message": "Registration successful! You can now log in."}), 201
    except ValidationError as e:
        raise e
    except Exception as e:
        raise APIError(f"Registration failed. Please try again later.")

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data:
        return jsonify({"status": "error", "message": "Please provide login credentials"}), 400
    
    username = data.get("username")
    password = data.get("password")
    remember_me = data.get("remember_me", False)  # Default to False if not provided
    
    try:
        user = users_collection.find_one({"username": username})
        
        if not user:
            return jsonify({"status": "error", "message": "No account found with this username"}), 401
        
        if not check_password_hash(user["password"], password):
            return jsonify({"status": "error", "message": "Incorrect password. Please try again"}), 401
        
        # Set token expiration based on remember_me
        expiration = datetime.datetime.utcnow() + datetime.timedelta(minutes=300)
        
        # Generate JWT token
        token = jwt.encode({
            'username': username,
            'exp': expiration
        }, JWT_SECRET, algorithm="HS256")
        
        return jsonify({
            "status": "success", 
            "username": username, 
            "token": token,
            "expires_in": 30,  # Return expiration in minutes
            "message": "Login successful! Welcome back!"
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": "Unable to log in. Please try again later."}), 500

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
        # Get fresh score directly from database
        score_entry = information_collection.find_one({"username": username})
        if not score_entry:
            return jsonify({"status": "error", "message": "User profile not found"}), 404
        
        response = jsonify({
            "status": "success", 
            "username": username,
            "score": score_entry["score"]
        })
        
        # Add cache control headers to prevent caching
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        
        return response, 200
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
        scoreboard = []
        
        for entry in scores:
            username = entry["username"]
            scoreboard.append({
                "username": username,
                "score": entry["score"]
            })
        
        return jsonify({"status": "success", "scoreboard": scoreboard}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"Scoreboard retrieval failed: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))  # Default to port 80 if PORT isn't set
    app.run(host="0.0.0.0", port=port, debug=True)
