import os

from flask import Flask, request, jsonify
from pymongo import MongoClient
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64

app = Flask(__name__)
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
uri = "mongodb+srv://noambavli07:dbpasswordiloveisrael123456@cluster0.3hmty.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))

db = client.arcade_app
users_collection = db.users_authentication
information_collection = db.users_information

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
public_key = private_key.public_key()

# Export keys as PEM
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Helper function to decrypt payloads
def decrypt_payload(encrypted_payload):
    try:
        encrypted_bytes = base64.b64decode(encrypted_payload)
        decrypted_bytes = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print("Decryption error:", e)
        return None

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    encrypted_payload = data.get('data')
    payload = decrypt_payload(encrypted_payload)

    if not payload:
        return jsonify({"status": "error", "message": "Invalid encrypted payload"}), 400

    payload = eval(payload)
    username = payload.get("username")
    password = payload.get("password")

    if not username or not password:
        return jsonify({"status": "error", "message": "Invalid input"}), 400

    if users_collection.find_one({"username": username}):
        return jsonify({"status": "error", "message": "Username already exists"}), 400

    users_collection.insert_one({"username": username, "password": password})
    information_collection.insert_one({"username": username, "score": 0})  # Initialize score
    return jsonify({"status": "success", "message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    encrypted_payload = data.get('data')
    payload = decrypt_payload(encrypted_payload)

    if not payload:
        return jsonify({"status": "error", "message": "Invalid encrypted payload"}), 400

    payload = eval(payload)
    username = payload.get("username")
    password = payload.get("password")

    user = users_collection.find_one({"username": username, "password": password})

    if not user:
        return jsonify({"status": "error", "message": "Invalid username or password"}), 401

    score_entry = information_collection.find_one({"username": username})
    score = score_entry["score"] if score_entry else 0

    return jsonify({"status": "success", "username": username, "score": score}), 200

@app.route('/update_score', methods=['POST'])
def update_score():
    data = request.get_json()
    encrypted_payload = data.get('data')
    payload = decrypt_payload(encrypted_payload)

    if not payload:
        return jsonify({"status": "error", "message": "Invalid encrypted payload"}), 400

    payload = eval(payload)
    username = payload.get("username")
    score = payload.get("score")

    if not username or score is None:
        return jsonify({"status": "error", "message": "Invalid input"}), 400

    information_collection.update_one({"username": username}, {"$set": {"score": score}}, upsert=True)
    return jsonify({"status": "success", "message": "Score updated successfully"}), 200

@app.route('/get_score', methods=['POST'])
def get_score():
    data = request.get_json()
    encrypted_payload = data.get('data')
    payload = decrypt_payload(encrypted_payload)

    if not payload:
        return jsonify({"status": "error", "message": "Invalid encrypted payload"}), 400

    payload = eval(payload)
    username = payload.get("username")

    if not username:
        return jsonify({"status": "error", "message": "Invalid input"}), 400

    score_entry = information_collection.find_one({"username": username})
    if not score_entry:
        return jsonify({"status": "error", "message": "User not found"}), 404

    return jsonify({"status": "success", "username": username, "score": score_entry["score"]}), 200

@app.route('/get_scoreboard', methods=['GET'])
def get_scoreboard():
    scores = list(information_collection.find().sort("score", -1))
    scoreboard = [{"username": entry["username"], "score": entry["score"]} for entry in scores]
    return jsonify({"status": "success", "scoreboard": scoreboard}), 200

@app.route('/public_key', methods=['GET'])
def get_public_key():
    return jsonify({"public_key": public_key_pem.decode('utf-8')}), 200

if __name__ == '__main__':
        port = int(os.getenv("PORT", 5000))  # Default to port 5000 if PORT isn't set
        app.run(host="0.0.0.0", port=port, debug=True)
