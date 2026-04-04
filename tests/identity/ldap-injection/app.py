"""Deliberately vulnerable Flask app with LDAP injection in login form."""
import ldap
import os
from flask import Flask, request

app = Flask(__name__)
LDAP_HOST = os.environ.get("LDAP_HOST", "ldap")

@app.route("/")
def index():
    return "<html><body><h1>Login</h1><form method=POST action=/login><input name=user placeholder=Username><input name=pass type=password placeholder=Password><button>Login</button></form></body></html>"

@app.route("/health")
def health():
    return "OK"

@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user", "")
    password = request.form.get("pass", "")
    try:
        conn = ldap.initialize(f"ldap://{LDAP_HOST}:389")
        # VULNERABLE: user input directly interpolated into LDAP filter
        search_filter = f"(uid={user})"
        result = conn.search_s("dc=test,dc=local", ldap.SCOPE_SUBTREE, search_filter)
        if result:
            return f"Found user: {result[0][0]}"
        return "User not found", 401
    except Exception as e:
        return f"Error: {e}", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
