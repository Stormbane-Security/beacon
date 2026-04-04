"""Vulnerable Flask app with Jinja2 SSTI in /greet endpoint.
Used by drydock chain test: ssti-env-harvest.
"""
from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)

@app.route("/")
def index():
    return "ok"

@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # VULNERABLE: user input rendered as Jinja2 template
    t = Template(f"Hello {name}!")
    return t.render()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
