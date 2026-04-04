"""Minimal URL fetch proxy vulnerable to SSRF."""
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import urlopen
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        if self.path.startswith("/fetch?"):
            params = parse_qs(urlparse(self.path).query)
            url = params.get("url", [""])[0]
            if not url:
                self.send_response(400)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"missing url parameter")
                return
            try:
                resp = urlopen(url, timeout=5)
                body = resp.read(4096)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                self.send_response(502)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(str(e).encode())
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<html><body>"
            b"<form action='/fetch'>"
            b"<input name='url' placeholder='Enter URL'>"
            b"<button>Fetch</button>"
            b"</form></body></html>"
        )

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
