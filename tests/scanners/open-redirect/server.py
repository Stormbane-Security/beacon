"""Minimal server vulnerable to open redirect.

Redirects to any URL provided in the 'url', 'next', or 'redirect' query
parameter without validating the destination domain.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
            return

        # Vulnerable: redirects to any user-supplied URL without validation
        redirect_url = None
        for param in ("url", "next", "redirect", "return_to", "continue"):
            vals = params.get(param)
            if vals:
                redirect_url = vals[0]
                break

        if redirect_url:
            self.send_response(302)
            self.send_header("Location", redirect_url)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # Default: landing page with redirect links
        body = b"""<html>
<head><title>Redirect Service</title></head>
<body>
<h1>Redirect Service</h1>
<p>Use /redirect?url=https://example.com to redirect.</p>
<a href="/redirect?url=https://example.com">Example redirect</a>
<form action="/redirect" method="get">
  <label>URL: <input name="url" size="40" placeholder="https://..."></label>
  <button type="submit">Go</button>
</form>
</body>
</html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
