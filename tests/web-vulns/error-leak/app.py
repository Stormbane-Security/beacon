"""Deliberately vulnerable Flask app running in debug mode with verbose error pages."""
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "<h1>App</h1><p>Welcome to the application</p>"

@app.route("/health")
def health():
    return "OK"

@app.route("/api/v1/data")
def data():
    # VULNERABLE: unhandled exception in debug mode leaks full stack trace
    result = 1 / 0
    return str(result)

@app.route("/admin")
def admin():
    # VULNERABLE: debug endpoint leaks internal config
    import os
    return str(dict(os.environ))

if __name__ == "__main__":
    # VULNERABLE: debug=True exposes Werkzeug debugger
    app.run(host="0.0.0.0", port=8080, debug=True)
