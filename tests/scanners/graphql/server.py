"""Minimal GraphQL server with introspection enabled."""
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

SCHEMA = {
    "queryType": {"name": "Query"},
    "types": [
        {
            "kind": "OBJECT",
            "name": "Query",
            "fields": [
                {
                    "name": "users",
                    "args": [],
                    "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "User"}},
                },
                {
                    "name": "secrets",
                    "args": [],
                    "type": {"kind": "LIST", "ofType": {"kind": "OBJECT", "name": "Secret"}},
                },
            ],
        },
        {
            "kind": "OBJECT",
            "name": "User",
            "fields": [
                {"name": "id", "type": {"kind": "SCALAR", "name": "ID"}},
                {"name": "email", "type": {"kind": "SCALAR", "name": "String"}},
                {"name": "role", "type": {"kind": "SCALAR", "name": "String"}},
            ],
        },
        {
            "kind": "OBJECT",
            "name": "Secret",
            "fields": [
                {"name": "key", "type": {"kind": "SCALAR", "name": "String"}},
                {"name": "value", "type": {"kind": "SCALAR", "name": "String"}},
            ],
        },
    ],
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>GraphQL endpoint at /graphql</body></html>")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        query = body.get("query", "")

        if "__schema" in query or "__type" in query:
            result = {"data": {"__schema": SCHEMA}}
        else:
            result = {"data": {"users": [{"id": "1", "email": "admin@test.local", "role": "admin"}]}}

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
