"""Minimal FastAPI app with default /docs and /openapi.json exposed."""
from fastapi import FastAPI

app = FastAPI(title="Test API", version="1.0.0")

@app.get("/")
def root():
    return {"message": "hello"}

@app.get("/api/users")
def users():
    return [{"id": 1, "name": "admin"}]
