from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import jwt
import datetime
import bcrypt
import logging
import google.generativeai as genai

# === Logging Setup ===
logging.basicConfig(filename="language_buddy.log", level=logging.DEBUG)

# === Flask App Setup ===
app = Flask(__name__)

# Allow S3 frontend origins
CORS(app, origins=[
    "http://language-buddy.s3-website.ap-south-1.amazonaws.com",
    "https://language-buddy.s3-website.ap-south-1.amazonaws.com"
])

# === Load Env Vars ===
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')
genai.configure(api_key=GOOGLE_API_KEY)

# === JWT Helpers ===
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

# === Routes ===

@app.route("/", methods=["GET"])
def index():
    return jsonify({"message": "Welcome to Language Buddy Backend!"})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "✅ Flask is running",
        "gemini_available": bool(GOOGLE_API_KEY)
    })

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        return jsonify({"message": "User registered (not stored)", "email": email}), 200

    except Exception as e:
        logging.exception("Error during registration")
        return jsonify({"error": "Registration failed"}), 500

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        fake_hashed_pw = bcrypt.hashpw("password123".encode('utf-8'), bcrypt.gensalt())
        if not bcrypt.checkpw(password.encode('utf-8'), fake_hashed_pw):
            return jsonify({"error": "Invalid credentials"}), 401

        token = generate_jwt(email)
        return jsonify({"token": token})

    except Exception as e:
        logging.exception("Login failed")
        return jsonify({"error": "Login error"}), 500

@app.route("/chat", methods=["POST"])
def chat():
    try:
        data = request.get_json()
        user_message = data.get("message")

        if not user_message:
            return jsonify({"error": "No message provided"}), 400

        print("✅ Sending to Gemini:", user_message)
        model = genai.GenerativeModel("gemini-pro")
        response = model.generate_content(user_message)

        reply = response.text.strip()
        print("🤖 Gemini replied:", reply)
        return jsonify({"reply": reply})

    except Exception as e:
        logging.exception("Gemini API error")
        return jsonify({"error": "Failed to get response from Gemini"}), 500

# === Run App ===
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)


    
        
        
