"""Minimal server vulnerable to CRLF injection in headers."""
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return

        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # Vulnerable: reflects user input directly in Location header
        redirect = params.get("redirect", [""])[0]
        if redirect:
            self.send_response(302)
            # Intentionally vulnerable: no sanitization of CRLF characters
            self.wfile.write(
                f"HTTP/1.1 302 Found\r\nLocation: {redirect}\r\n\r\n".encode()
            )
            return

        lang = params.get("lang", ["en"])[0]
        self.send_response(200)
        # Intentionally vulnerable: reflects parameter in Set-Cookie header
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", f"lang={lang}; Path=/")
        self.end_headers()
        self.wfile.write(
            b"<html><body>"
            b"<a href='/?lang=en'>English</a> | "
            b"<a href='/?lang=fr'>French</a>"
            b"</body></html>"
        )

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
