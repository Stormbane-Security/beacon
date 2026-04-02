"""Minimal JWT server that issues tokens with alg:none."""
import json
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_none_jwt(claims: dict) -> str:
    header = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = b64url(json.dumps(claims).encode())
    return f"{header}.{payload}."


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        if self.path == "/login":
            token = make_none_jwt({
                "sub": "admin",
                "role": "superuser",
                "iat": 1700000000,
                "exp": 9999999999,
            })
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"session={token}; Path=/; HttpOnly")
            self.end_headers()
            self.wfile.write(json.dumps({"token": token}).encode())
            return

        if self.path == "/":
            token = make_none_jwt({
                "sub": "guest",
                "role": "viewer",
                "iat": 1700000000,
                "exp": 9999999999,
            })
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Set-Cookie", f"session={token}; Path=/; HttpOnly")
            self.end_headers()
            self.wfile.write(b"<html><body>Welcome</body></html>")
            return

        self.send_response(404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"not found")

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
