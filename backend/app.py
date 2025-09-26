import os
from flask import Flask, jsonify
import psycopg2

app = Flask(__name__)

# --- Database Connection Test ---
# Ye 'DATABASE_URL' environment variable ko use karega
# jo humne Render par set ki hai (aur local test ke liye bhi set kar sakte hain).

def get_db_connection():
    # Attempt to connect using the DATABASE_URL environment variable
    conn = psycopg2.connect(os.environ.get('postgresql://animewebdb_user:0SA7G3HdMiNBuxLhtdDjPwI1TJAJffKo@dpg-d3b9b46r433s738hkbhg-a/animewebdb'))
    return conn

@app.route('/')
def home():
    # Ye ek basic JSON response dega
    return jsonify({
        'status': 'OK',
        'message': 'Backend is running successfully!',
        'database_check': 'Not checked on this route, but setup is ready.'
    })

@app.route('/health')
def health_check():
    # Database connection test
    try:
        conn = get_db_connection()
        conn.close()
        return jsonify({
            'status': 'Healthy',
            'database': 'PostgreSQL connected successfully!'
        }), 200
    except Exception as e:
        # Agar connection fail hua toh error message
        return jsonify({
            'status': 'Error',
            'database': 'PostgreSQL connection failed.',
            'error_details': str(e)
        }), 500


if __name__ == '__main__':
    # Jab Render par deploy hoga, toh Gunicorn isko chalayega.
    # Hum local test ke liye isko use kar sakte hain.
    app.run(debug=True)