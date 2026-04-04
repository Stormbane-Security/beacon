"""Multi-vulnerability web server for full-pipeline e2e testing.

Exposes multiple issues that different scanners detect independently:
  - DLP: .env file with API keys, page with email addresses
  - Port identification: HTTP service on port 8080
  - Clickjacking: no X-Frame-Options or CSP frame-ancestors
  - Security headers: no CSP, HSTS, X-Frame-Options, etc.
  - Open redirect: ?url= parameter redirects to arbitrary URLs
  - CORS: reflects arbitrary Origin with credentials
  - CRLF: header injection via query parameter
  - Server info leak: X-Powered-By header
"""
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

# Fake .env contents — triggers dlp.api_key
DOTENV = """# Application configuration
DATABASE_URL=postgres://admin:s3cret@db.internal:5432/prod
JWT_SECRET=supersecretkey12345678901234567890
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12
REDIS_URL=redis://:password123@cache.internal:6379/0
"""

# Page with many emails — triggers dlp.email_list (>= 25 unique emails)
EMAIL_PAGE = """<html><head><title>Team Directory</title></head><body>
<h1>Company Directory</h1>
<table>
""" + "\n".join(
    f'<tr><td>User {i}</td><td>user{i}@example-corp.com</td></tr>'
    for i in range(30)
) + """
</table>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # --- Open redirect: ?url= redirects to arbitrary URL ---
        if "url" in params:
            target = params["url"][0]
            self.send_response(302)
            self.send_header("Location", target)
            self._common_headers()
            self.end_headers()
            return

        if "redirect" in params:
            target = params["redirect"][0]
            self.send_response(302)
            self.send_header("Location", target)
            self._common_headers()
            self.end_headers()
            return

        if parsed.path == "/health":
            self._respond(200, "text/plain", "ok")
            return

        if parsed.path == "/.env":
            self._respond(200, "text/plain", DOTENV)
            return

        if parsed.path == "/directory":
            self._respond(200, "text/html", EMAIL_PAGE)
            return

        if parsed.path == "/robots.txt":
            self._respond(200, "text/plain",
                          "User-agent: *\nDisallow: /admin\nDisallow: /api/internal\n")
            return

        # Default index — plain page with links so crawler can discover paths.
        self._respond(200, "text/html", """<html>
<head><title>Test Application</title></head>
<body>
<h1>Welcome</h1>
<p>This is the test application.</p>
<ul>
  <li><a href="/directory">Team Directory</a></li>
  <li><a href="/.env">.env</a></li>
</ul>
</body></html>""")

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        origin = self.headers.get("Origin", "")
        self.send_response(200)
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self._common_headers()
        self.end_headers()

    def do_HEAD(self):
        """Respond to HEAD requests (used by classify/fingerprinting)."""
        self.do_GET()

    def _common_headers(self):
        """Add headers that expose vulnerabilities."""
        # CORS: reflect any Origin with credentials — triggers cors.arbitrary_origin
        origin = self.headers.get("Origin", "")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")

        # Server info leak — triggers headers.server_info_leak
        self.send_header("X-Powered-By", "Express 4.18.2")

        # Intentionally NO security headers:
        # - No Content-Security-Policy
        # - No Strict-Transport-Security
        # - No X-Frame-Options
        # - No X-Content-Type-Options
        # - No Referrer-Policy
        # - No Permissions-Policy

    def _respond(self, code, content_type, body):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self._common_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
