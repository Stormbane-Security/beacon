"""Minimal server vulnerable to CRLF injection in headers.

Uses raw socket writes to bypass Python 3.12+ send_header() sanitization,
simulating a real application that writes headers without sanitization
(e.g., Java servlets, Go net/http, PHP header(), Node.js).
"""
import socket
import threading
from urllib.parse import parse_qs, urlparse, unquote


def handle_client(conn):
    try:
        data = conn.recv(4096).decode("utf-8", errors="replace")
        if not data:
            return

        # Parse request line.
        lines = data.split("\r\n")
        method, path_full, _ = lines[0].split(" ", 2)

        parsed = urlparse(path_full)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path == "/health":
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            return

        # Vulnerable: reflects redirect parameter in Location header
        # without sanitizing CRLF characters.
        redirect = params.get("redirect", [""])[0]
        if not redirect:
            redirect = params.get("url", [""])[0]
        if not redirect:
            redirect = params.get("next", [""])[0]

        if redirect:
            # Raw header write — no sanitization of \r\n in value.
            response = (
                f"HTTP/1.1 302 Found\r\n"
                f"Location: {redirect}\r\n"
                f"Content-Length: 0\r\n"
                f"\r\n"
            )
            conn.sendall(response.encode("utf-8", errors="replace"))
            return

        # Vulnerable: reflects lang parameter in Set-Cookie header.
        lang = params.get("lang", [""])[0]
        if lang:
            response = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Type: text/html\r\n"
                f"Set-Cookie: lang={lang}; Path=/\r\n"
                f"Content-Length: 4\r\n"
                f"\r\n"
                f"ok\r\n"
            )
            conn.sendall(response.encode("utf-8", errors="replace"))
            return

        # Default response.
        body = b"<html><body>CRLF test server</body></html>"
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: text/html\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"\r\n"
        )
        conn.sendall(response.encode() + body)

    except Exception:
        pass
    finally:
        conn.close()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 8080))
    srv.listen(64)

    while True:
        conn, _ = srv.accept()
        t = threading.Thread(target=handle_client, args=(conn,), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
