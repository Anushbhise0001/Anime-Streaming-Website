import os
import jwt
import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
from psycopg2 import extras # Dictionary cursor के लिए

# --- Configuration ---
# Render पर ये Environment Variables से आएंगे
# LOCAL TESTING के लिए आप os.environ.get() की जगह सीधे मान (value) दे सकते हैं
SECRET_KEY = os.environ.get("SECRET_KEY", "your_default_secret_key_for_local_dev")
DATABASE_URL = os.environ.get("DATABASE_URL")

app = Flask(__name__)
# CORS को आपके Render Static Site URL से बदलें जब आप उसे डिप्लॉय कर लें
CORS(app) 

# --- Database Connection and Initialization ---
def get_db_connection():
    """PostgreSQL database से कनेक्शन बनाता है."""
    if not DATABASE_URL:
        # यह एरर Render पर नहीं आएगी क्योंकि हमने DATABASE_URL set किया है
        raise ValueError("DATABASE_URL is not set.")
    
    # Render के DATABASE_URL में SSL की आवश्यकता होती है, इसलिए sslmode='require' जोड़ें
    # Render URL में पहले से ही username, password, host, port, dbname होता है
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    return conn

def init_db():
    """Database में 'users' table बनाता है."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(80) UNIQUE NOT NULL,
                password VARCHAR(128) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
    except Exception as e:
        print(f"Database initialization error: {e}")
    finally:
        if conn:
            conn.close()

# --- Utility Functions ---

def token_required(f):
    """JWT Token verification के लिए decorator."""
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            # Token verify करें और user_id निकालें
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            # आप user ID का उपयोग करके डेटाबेस से user की जानकारी fetch कर सकते हैं, 
            # लेकिन सरल रखने के लिए, हम बस token को verify कर रहे हैं।
        except:
            return jsonify({'message': 'Token is invalid or expired!'}), 401

        return f(*args, **kwargs)
    decorated.__name__ = f.__name__ # Flask को रूट पहचान में मदद करता है
    return decorated

# --- Routes ---

@app.route('/')
def home():
    """API health check route."""
    return "Anime Stream API is running!", 200

# -----------------
# SIGNUP Route
# -----------------
@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"status": "error", "message": "Username and password are required"}), 400

        # Hash the password
        # werkzeug.security is used for hashing
        hashed_password = generate_password_hash(password)

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Save user to the database
        cursor.execute(
            'INSERT INTO users (username, password) VALUES (%s, %s)', 
            (username, hashed_password)
        )
        conn.commit()
        
        return jsonify({"status": "ok", "message": "Signup successful"}), 201
    
    except psycopg2.errors.UniqueViolation:
        # Username पहले से मौजूद होने पर PostgreSQL error
        return jsonify({"status": "error", "message": "Username already exists"}), 409
    except Exception as e:
        return jsonify({"status": "error", "message": "An error occurred", "details": str(e)}), 500
    finally:
        if conn:
            conn.close()

# -----------------
# LOGIN Route
# -----------------
@app.route('/api/login', methods=['POST'])
def login():
    conn = None
    try:
        auth = request.get_json()
        username = auth.get('username')
        password = auth.get('password')

        if not username or not password:
            return jsonify({'message': 'Missing username or password'}), 400

        conn = get_db_connection()
        # Dictionary Cursor का उपयोग करें ताकि परिणाम Dictionary के रूप में मिलें
        cursor = conn.cursor(cursor_factory=extras.RealDictCursor) 
        
        cursor.execute('SELECT id, password FROM users WHERE username = %s', (username,))
        user = cursor.fetchone()

        if not user:
            return jsonify({'message': 'Invalid credentials'}), 401

        # Password verify करें
        if check_password_hash(user['password'], password):
            # JWT Token बनाएँ
            token = jwt.encode({
                'user_id': user['id'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30) # Token 30 मिनट में expire होगा
            }, SECRET_KEY, algorithm="HS256")
            
            # Token फ्रंटएंड पर भेजें
            return jsonify({'status': 'ok', 'token': token}), 200

        return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({"status": "error", "message": "An error occurred", "details": str(e)}), 500
    finally:
        if conn:
            conn.close()


# -----------------
# PROTECTED Route (Example)
# -----------------
@app.route('/api/protected-data')
@token_required
def protected():
    """यह route केवल valid JWT token के साथ ही एक्सेस किया जा सकता है।"""
    # यहाँ पर आप स्ट्रीमिंग लिस्ट या यूज़र-स्पेसिफिक डेटा का लॉजिक लिख सकते हैं
    return jsonify({
        'status': 'ok', 
        'message': 'This is your secret streaming data.',
        'data': ['Anime A', 'Anime B', 'Anime C']
    })


if __name__ == '__main__':
    # Render पर init_db() को अलग से run करना बेहतर है, लेकिन local testing के लिए इसे यहाँ रखें
    if not os.environ.get("RENDER"): # Render environment में इसे skip करें
        init_db() 
        app.run(debug=True)