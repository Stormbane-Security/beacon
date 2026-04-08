"""Minimal HTTP server simulating an LDAP-backed search endpoint vulnerable to
LDAP filter injection. Returns different result counts for injected payloads
vs normal queries, which is what the beacon iam scanner uses to detect injection."""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import json

# Simulated user database (as if backed by LDAP)
USERS = [
    {"cn": "admin", "mail": "admin@corp.local"},
    {"cn": "alice", "mail": "alice@corp.local"},
    {"cn": "bob", "mail": "bob@corp.local"},
    {"cn": "charlie", "mail": "charlie@corp.local"},
    {"cn": "service-account", "mail": "svc@corp.local"},
]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        if parsed.path == "/search":
            q = params.get("q", [""])[0]
            # Simulate LDAP injection: wildcard/injection payloads return all users
            if "*" in q or ")(" in q or ")(|" in q:
                results = USERS  # injection succeeded — returns all entries
            elif q:
                results = [u for u in USERS if q.lower() in u["cn"].lower()]
            else:
                results = []
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"results": results, "count": len(results)}).encode())
        elif parsed.path == "/api/users":
            filt = params.get("filter", [""])[0]
            if "*" in filt or ")(" in filt or ")(|" in filt:
                results = USERS
            elif filt:
                results = [u for u in USERS if filt.lower() in u["cn"].lower()]
            else:
                results = []
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"results": results, "count": len(results)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # silence logs


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print("LDAP injection test server on :8080")
    server.serve_forever()
