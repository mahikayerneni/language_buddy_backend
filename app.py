from flask import Flask, request, jsonify
import jwt
import datetime
import bcrypt
from openai import OpenAI
from flask_cors import CORS
import os
import logging

# Set up logging
logging.basicConfig(filename="language_buddy.log", level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__)

# Allow frontend hosted on S3
CORS(app, resources={r"/*": {"origins": [
    "http://language-buddy.s3-website.ap-south-1.amazonaws.com"
]}}, supports_credentials=True)

# Load environment variables
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')

# Initialize OpenAI client
try:
    client = OpenAI(api_key=OPENAI_API_KEY)
except Exception as e:
    logging.error(f"Failed to initialize OpenAI client: {str(e)}")
    client = None

# JWT helpers
def generate_jwt(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def verify_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Temporary in-memory user storage
users = {}

# Health check route
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "✅ Flask is running",
        "openai_available": client is not None
    })

@app.route("/", methods=["GET"])
def index():
    return jsonify({"message": "Welcome to Language Buddy Backend!"})

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")
        email = data.get("email", "")

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        if username in users:
            return jsonify({"error": "User already exists"}), 400

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        users[username] = {"password": hashed_pw, "email": email}
        return jsonify({"message": "Registration successful"}), 200

    except Exception as e:
        logging.error(f"Register error: {str(e)}")
        return jsonify({"error": "Server error"}), 500

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")

        user = users.get(username)
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user["password"]):
            return jsonify({"error": "Invalid username or password"}), 401

        token = generate_jwt(username)
        return jsonify({"message": "Login successful", "token": token, "username": username}), 200

    except Exception as e:
        logging.error(f"Login error: {str(e)}")
        return jsonify({"error": "Server error"}), 500

@app.route("/chat", methods=["POST"])
def chat():
    try:
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        user_id = verify_jwt(token)
        if not user_id:
            return jsonify({"error": "Unauthorized"}), 401

        message = request.json.get("message")
        if not message:
            return jsonify({"error": "Empty message"}), 400

        if not client:
            return jsonify({"error": "OpenAI not available"}), 503

        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": message}]
        )

        reply = response.choices[0].message.content
        return jsonify({"response": reply}), 200

    except Exception as e:
        logging.error(f"Chat error: {str(e)}")
        return jsonify({"error": "Server error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
