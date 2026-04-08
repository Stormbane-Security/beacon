#!/usr/bin/env python3
"""Minimal reverse proxy that is vulnerable to hop-by-hop header abuse.

It sets X-Forwarded-For on every forwarded request, but also honours
RFC 7230 Connection-nominated hop-by-hop headers — stripping them
AFTER setting X-Forwarded-For. This means an attacker can remove
X-Forwarded-For from the backend's view by listing it in the
Connection header.
"""

import http.server
import http.client
import os
import sys

BACKEND_HOST = os.environ.get("BACKEND_HOST", "backend")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "80"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "80"))


class VulnerableProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self._proxy()

    def do_HEAD(self):
        self._proxy()

    def do_POST(self):
        self._proxy()

    def _proxy(self):
        # Build headers to forward, adding X-Forwarded-For first.
        headers = {}
        for key, val in self.headers.items():
            headers[key] = val

        # Set X-Forwarded-For from the client address (proxy behaviour).
        headers["X-Forwarded-For"] = self.client_address[0]

        # Now honour hop-by-hop: strip headers listed in Connection.
        conn_hdr = self.headers.get("Connection", "")
        hop_by_hop = {h.strip().lower() for h in conn_hdr.split(",") if h.strip()}
        # Remove nominated hop-by-hop headers (the vulnerability).
        forward_headers = {}
        for key, val in headers.items():
            if key.lower() not in hop_by_hop and key.lower() != "connection":
                forward_headers[key] = val

        try:
            conn = http.client.HTTPConnection(BACKEND_HOST, BACKEND_PORT, timeout=5)
            conn.request(self.command, self.path, headers=forward_headers)
            resp = conn.getresponse()
            body = resp.read()

            self.send_response(resp.status)
            for key, val in resp.getheaders():
                if key.lower() not in ("transfer-encoding", "connection"):
                    self.send_header(key, val)
            self.end_headers()
            self.wfile.write(body)
            conn.close()
        except Exception as e:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(f"Proxy error: {e}".encode())

    def log_message(self, format, *args):
        pass  # Silence request logging.


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", LISTEN_PORT), VulnerableProxyHandler)
    print(f"Vulnerable proxy listening on :{LISTEN_PORT}", flush=True)
    server.serve_forever()
