#!/usr/bin/env python3
"""Minimal VNC server that sends RFB 3.8 handshake with security type None (1).

This lets Beacon's VNC auth probe detect port.vnc_no_auth without needing
a full desktop environment or X server.
"""

import socket
import struct
import sys

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 5900))
    srv.listen(5)
    print("VNC stub listening on :5900", flush=True)

    while True:
        conn, addr = srv.accept()
        try:
            # Server sends RFB version
            conn.sendall(b"RFB 003.008\n")

            # Read client version (12 bytes)
            data = conn.recv(12)
            if not data:
                conn.close()
                continue

            # Send security types: 1 type available, type 1 = None
            conn.sendall(struct.pack("!BB", 1, 1))

            # Read client's chosen security type (1 byte)
            data = conn.recv(1)
            if not data:
                conn.close()
                continue

            # SecurityResult: OK (0)
            conn.sendall(struct.pack("!I", 0))
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

if __name__ == "__main__":
    main()
