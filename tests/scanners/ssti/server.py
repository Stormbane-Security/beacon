"""Minimal Jinja2 template app vulnerable to SSTI."""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from jinja2 import Template


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        params = parse_qs(urlparse(self.path).query)

        # Vulnerable: user input rendered directly as a Jinja2 template
        q = params.get("q", params.get("query", params.get("name", [""])))
        user_input = q[0] if q else ""

        if user_input:
            try:
                rendered = Template(user_input).render()
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(f"<html><body><p>Result: {rendered}</p></body></html>".encode())
                return
            except Exception:
                pass

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<html><body>"
            b"<form action='/search'>"
            b"<input name='q' placeholder='Search...'>"
            b"<button>Search</button>"
            b"</form></body></html>"
        )

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
