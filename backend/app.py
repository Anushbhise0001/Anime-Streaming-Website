import os
from flask import Flask, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Render me DATABASE_URL env variable milega
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL").replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Example model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)

# Default route
@app.route("/")
def home():
    return jsonify({"msg": "Earner with SM Backend Running with DB!"})

# Test DB route
@app.route("/testdb")
def testdb():
    try:
        db.session.execute("SELECT 1")
        return jsonify({"msg": "DB Connected Successfully!"})
    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
