"""Minimal server vulnerable to host header injection.

Reflects the Host header in redirect Location and response body,
simulating a password reset or login page that trusts the Host header.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        host = self.headers.get("Host", "localhost")

        # /login redirects using the Host header — vulnerable to host header injection
        if self.path == "/login":
            self.send_response(302)
            self.send_header("Location", f"http://{host}/dashboard")
            self.end_headers()
            return

        # Root page reflects Host in the body (password reset link pattern)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        body = (
            f"<html><body>"
            f"<p>Reset your password: <a href='http://{host}/reset?token=abc123'>Click here</a></p>"
            f"</body></html>"
        )
        self.wfile.write(body.encode())

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
