"""Minimal HTTP server that simulates NTLM authentication handshake.

On any GET request:
  - If no Authorization header or not NTLM: returns 401 with
    WWW-Authenticate: NTLM (prompting client to send Type 1).
  - If Authorization: NTLM <Type1>: returns 401 with
    WWW-Authenticate: NTLM <Type2> containing leaked domain/server info.

The Type 2 challenge is a valid NTLMSSP message that beacon's ntlm scanner
can parse to extract internal infrastructure information.
"""

import base64
import struct
from http.server import HTTPServer, BaseHTTPRequestHandler


def _utf16le(s: str) -> bytes:
    return s.encode("utf-16-le")


def build_type2() -> bytes:
    """Build a valid NTLM Type 2 (Challenge) message with target info."""
    domain = _utf16le("TESTCORP")
    server = _utf16le("EXCH-01")
    dns_domain = _utf16le("testcorp.local")
    dns_server = _utf16le("exch-01.testcorp.local")

    # Build target info block (AV_PAIRs)
    ti = b""
    # MsvAvNbDomainName (0x0002)
    ti += struct.pack("<HH", 0x0002, len(domain)) + domain
    # MsvAvNbComputerName (0x0001)
    ti += struct.pack("<HH", 0x0001, len(server)) + server
    # MsvAvDnsDomainName (0x0003)
    ti += struct.pack("<HH", 0x0003, len(dns_domain)) + dns_domain
    # MsvAvDnsComputerName (0x0004)
    ti += struct.pack("<HH", 0x0004, len(dns_server)) + dns_server
    # MsvAvEOL (0x0000)
    ti += struct.pack("<HH", 0x0000, 0)

    # Target name field
    target_name = domain

    # Fixed header size (without target name and target info)
    header_len = 48  # 8 sig + 4 type + 8 target_name_fields + 4 flags + 8 challenge + 8 reserved + 8 target_info_fields
    target_name_offset = header_len
    target_info_offset = header_len + len(target_name)

    msg = b"NTLMSSP\x00"                                    # Signature
    msg += struct.pack("<I", 2)                               # Type 2
    msg += struct.pack("<HHI", len(target_name), len(target_name), target_name_offset)  # Target name
    msg += struct.pack("<I", 0x00028233)                      # Flags
    msg += b"\x01\x23\x45\x67\x89\xab\xcd\xef"              # Challenge
    msg += b"\x00" * 8                                        # Reserved
    msg += struct.pack("<HHI", len(ti), len(ti), target_info_offset)  # Target info
    msg += target_name
    msg += ti

    return msg


TYPE2_B64 = base64.b64encode(build_type2()).decode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("NTLM "):
            # Client sent Type 1 negotiate — respond with Type 2 challenge
            self.send_response(401)
            self.send_header("WWW-Authenticate", f"NTLM {TYPE2_B64}")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            # No auth — prompt for NTLM
            self.send_response(401)
            self.send_header("WWW-Authenticate", "NTLM")
            self.send_header("Content-Length", "24")
            self.end_headers()
            self.wfile.write(b"Authentication required\n")

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), Handler)
    print("NTLM test server on :8080")
    server.serve_forever()
