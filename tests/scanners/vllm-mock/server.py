"""Mock vLLM-compatible HTTP server for testing.

Returns /v1/models JSON and /health responses that mimic a real vLLM instance,
without requiring a GPU.
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler

MODELS_RESPONSE = json.dumps({
    "object": "list",
    "data": [
        {
            "id": "mock-llama-7b",
            "object": "model",
            "created": 1700000000,
            "owned_by": "mock",
            "root": "mock-llama-7b",
            "parent": None,
            "permission": []
        }
    ]
})

HEALTH_RESPONSE = json.dumps({"status": "ok"})


class VLLMHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/v1/models":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(MODELS_RESPONSE.encode())
        elif self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(HEALTH_RESPONSE.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress noisy request logs
        pass


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8000), VLLMHandler)
    print("vLLM mock server listening on :8000")
    server.serve_forever()
