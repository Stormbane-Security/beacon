"""Simple Flask app behind nginx for HTTP request smuggling testing."""
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "<html><body><h1>API Gateway</h1><p>Backend service</p></body></html>"

@app.route("/health")
def health():
    return "OK"

@app.route("/api/v1/admin")
def admin():
    return "Admin panel"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
