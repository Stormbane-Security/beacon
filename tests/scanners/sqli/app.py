"""Deliberately vulnerable Flask app with SQL injection in ?id= parameter."""
import sqlite3
import time
from flask import Flask, request, jsonify

app = Flask(__name__)

def get_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT)")
    db.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin')")
    db.execute("INSERT OR IGNORE INTO users VALUES (2, 'user')")
    db.commit()
    return db

@app.route("/health")
def health():
    return "OK"

@app.route("/")
def index():
    return "<h1>User Lookup</h1><form action='/api/v1/users'><input name='id'><button>Search</button></form>"

@app.route("/api/v1/users")
def users():
    user_id = request.args.get("id", "1")
    db = get_db()
    try:
        # VULNERABLE: string concatenation in SQL query
        cursor = db.execute(f"SELECT * FROM users WHERE id = {user_id}")
        rows = cursor.fetchall()
        return jsonify({"users": [{"id": r[0], "name": r[1]} for r in rows]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    try:
        # VULNERABLE: string concatenation in SQL query
        cursor = db.execute(f"SELECT * FROM users WHERE name LIKE '%{q}%'")
        rows = cursor.fetchall()
        return jsonify({"results": [{"id": r[0], "name": r[1]} for r in rows]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
