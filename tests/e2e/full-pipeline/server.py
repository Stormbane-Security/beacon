"""Multi-vulnerability web server for full-pipeline e2e testing.

Exposes multiple issues that different scanners detect independently:
  - DLP: .env file with API keys, page with email addresses
  - Port identification: HTTP service on port 8080
  - Clickjacking: no X-Frame-Options or CSP frame-ancestors
"""
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

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
        if self.path == "/health":
            self._respond(200, "text/plain", "ok")
            return

        if self.path == "/.env":
            self._respond(200, "text/plain", DOTENV)
            return

        if self.path == "/directory":
            self._respond(200, "text/html", EMAIL_PAGE)
            return

        if self.path == "/robots.txt":
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

    def do_HEAD(self):
        """Respond to HEAD requests (used by classify/fingerprinting)."""
        self.do_GET()

    def _respond(self, code, content_type, body):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        # No X-Frame-Options or CSP — clickjacking-vulnerable
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
