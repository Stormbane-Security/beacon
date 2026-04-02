"""Deliberately vulnerable Flask app with SSRF in ?url= parameter."""
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/health")
def health():
    return "OK"

@app.route("/")
def index():
    return "<h1>URL Fetcher</h1><form action='/api/v1/fetch'><input name='url' placeholder='URL'><button>Fetch</button></form>"

@app.route("/api/v1/fetch")
def fetch():
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url parameter required"}), 400
    try:
        # VULNERABLE: fetches arbitrary URLs including internal/cloud metadata
        resp = requests.get(url, timeout=5)
        return jsonify({
            "status": resp.status_code,
            "body": resp.text[:1000],
            "headers": dict(resp.headers)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/health")
def api_health():
    return jsonify({"status": "ok"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
