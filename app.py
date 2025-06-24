from flask import Flask, request, jsonify
import jwt
import datetime
import bcrypt
from openai import OpenAI
from flask_cors import CORS
import os
import logging
import traceback
from pymongo import MongoClient

# Set up logging
logging.basicConfig(filename="language_buddy.log", level=logging.DEBUG)

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": [
    "https://mahika6.pythonanywhere.com",
    "http://language-buddy.s3-website.ap-south-1.amazonaws.com"
]}}, supports_credentials=True)

# Load environment variables
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://yernenimahika:8gg0Rw6dTpUW39IO@cluster0.w12xvvr.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")

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

# Health check
@app.route("/health", methods=["GET"])
def health():
    try:
        db_status = "Unavailable"
        db_error = None
        try:
            mongo_client = MongoClient(MONGO_URI)
            mongo_client.admin.command('ping')
            db_status = "Available"
        except Exception as db_err:
            db_error = str(db_err)

        return jsonify({
            "status": "✅ Flask is running",
            "db_status": db_status,
            "db_error": db_error,
            "openai_available": client is not None
        }), 200

    except Exception as e:
        return jsonify({
            "status": "❌ Error",
            "error": str(e)
        }), 500

@app.route("/", methods=["GET"])
def index():
    return jsonify({"message": "Welcome to Language Buddy Backend!"})

# You can keep or reimplement endpoints like /chat, /register, /login, etc. using MongoDB

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
