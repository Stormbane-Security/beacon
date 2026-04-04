"""Deliberately vulnerable Flask app with insecure pickle deserialization."""
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route("/health")
def health():
    return "OK"

@app.route("/")
def index():
    return "<html><body><h1>Session Manager</h1><p>POST to /api/v1/session with base64-encoded data</p></body></html>"

@app.route("/api/v1/session", methods=["POST"])
def session():
    data = request.get_data()
    if not data:
        return "No data", 400
    try:
        # VULNERABLE: deserializes arbitrary pickle data from user input
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)
        return f"Session loaded: {obj}"
    except Exception as e:
        return f"Error: {e}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
