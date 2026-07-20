"""
A real, minimal UDP+TCP+TLS SIP server — FOR TESTS ONLY.

Responds to real SIP OPTIONS and REGISTER requests over real UDP, TCP,
and TLS sockets, exactly like a real PBX would, with configurable
behavior so tests can exercise both a securely-configured target
(challenges REGISTER with 401) and a vulnerable one (accepts an
unauthenticated REGISTER with 200 OK) — matching the same "test
against a real protocol implementation, not a mock/assumption" pattern
already established across this whole portfolio (e.g. redteam-toolkit's
own tests/fixtures/mock_target).

TLS uses a real, openssl-generated self-signed certificate
(certs/cert.pem + certs/key.pem, checked into this fixtures directory,
not created on the fly) — this is a TEST-ONLY certificate for
127.0.0.1/localhost, never used for anything but this mock server.

UDP, TCP, and TLS each listen on their own independently-assigned
ephemeral port (self.port / self.tcp_port / self.tls_port) — real PBX
deployments commonly listen on the *same* port number across
transports, but since this mock uses OS-assigned ephemeral ports for
test isolation, there's no reliable way to request the identical
number across all three socket types, and no test here actually needs
that to be true.
"""

from __future__ import annotations

import re
import socket
import ssl
import threading
from pathlib import Path

_STATUS_LINE_RE = re.compile(r"^([A-Z]+)\s+sip:")
_CERTS_DIR = Path(__file__).parent / "certs"


class MockPBXServer:
    def __init__(
        self,
        host: str = "127.0.0.1",
        server_header: str = "Asterisk PBX 18.9.0",
        accept_unauthenticated_register: bool = False,
    ):
        self.host = host
        self.server_header = server_header
        self.accept_unauthenticated_register = accept_unauthenticated_register

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((host, 0))
        self.port = self._sock.getsockname()[1]

        self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_sock.bind((host, 0))
        self._tcp_sock.listen(8)
        self.tcp_port = self._tcp_sock.getsockname()[1]

        self._tls_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tls_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tls_sock.bind((host, 0))
        self._tls_sock.listen(8)
        self.tls_port = self._tls_sock.getsockname()[1]
        self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tls_context.load_cert_chain(
            certfile=str(_CERTS_DIR / "cert.pem"), keyfile=str(_CERTS_DIR / "key.pem")
        )

        self._running = False
        self._udp_thread: threading.Thread | None = None
        self._tcp_thread: threading.Thread | None = None
        self._tls_thread: threading.Thread | None = None

    def start(self) -> None:
        self._running = True
        self._udp_thread = threading.Thread(target=self._serve_udp_forever, daemon=True)
        self._udp_thread.start()
        self._tcp_thread = threading.Thread(target=self._serve_tcp_forever, daemon=True)
        self._tcp_thread.start()
        self._tls_thread = threading.Thread(target=self._serve_tls_forever, daemon=True)
        self._tls_thread.start()

    def stop(self) -> None:
        self._running = False
        self._sock.close()
        self._tcp_sock.close()
        self._tls_sock.close()

    def _serve_udp_forever(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(65535)
            except OSError:
                break  # socket closed
            try:
                response = self._handle(data)
                if response:
                    self._sock.sendto(response, addr)
            except Exception:
                pass  # a real PBX doesn't crash on a malformed probe; neither should this

    def _serve_tcp_forever(self) -> None:
        while self._running:
            try:
                conn, _addr = self._tcp_sock.accept()
            except OSError:
                break  # listening socket closed
            threading.Thread(target=self._handle_tcp_connection, args=(conn,), daemon=True).start()

    def _serve_tls_forever(self) -> None:
        while self._running:
            try:
                conn, _addr = self._tls_sock.accept()
            except OSError:
                break  # listening socket closed
            try:
                tls_conn = self._tls_context.wrap_socket(conn, server_side=True)
            except ssl.SSLError:
                conn.close()  # e.g. a plain (non-TLS) probe hit this port — not a crash-worthy event
                continue
            # Once handshaked, an SSLSocket exposes the same
            # settimeout/recv/sendall surface a plain TCP socket does,
            # so the exact same connection handler is reused unchanged.
            threading.Thread(target=self._handle_tcp_connection, args=(tls_conn,), daemon=True).start()

    def _handle_tcp_connection(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            data = self._read_one_tcp_message(conn)
            if not data:
                return
            response = self._handle(data)
            if response:
                conn.sendall(response)
        except Exception:
            pass  # a real PBX doesn't crash a listener thread on a malformed probe; neither should this
        finally:
            conn.close()

    @staticmethod
    def _read_one_tcp_message(conn: socket.socket) -> bytes:
        """Minimal Content-Length-aware framing for an incoming
        request — mirrors voipaudit's own client-side _read_sip_message
        in core/sip.py, but only needs to handle the small, fixed set
        of requests this mock understands, so it stays deliberately
        simpler (no shared deadline bookkeeping needed for a
        test-only server)."""
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(4096)
            if not chunk:
                return buf
            buf += chunk
        header_end = buf.find(b"\r\n\r\n")
        header_bytes = buf[:header_end]
        body_so_far = buf[header_end + 4:]

        match = re.search(rb"^content-length\s*:\s*(\d+)\s*$", header_bytes, re.IGNORECASE | re.MULTILINE)
        content_length = int(match.group(1)) if match else 0

        while len(body_so_far) < content_length:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body_so_far += chunk

        return buf[:header_end + 4] + body_so_far

    def _handle(self, data: bytes) -> bytes | None:
        text = data.decode("utf-8", errors="replace")
        first_line = text.split("\r\n")[0] if "\r\n" in text else text.split("\n")[0]
        headers = self._parse_headers(text)

        if first_line.startswith("OPTIONS "):
            return self._build_response(200, "OK", headers, extra_headers={
                "Server": self.server_header,
                "Allow": "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY",
            })

        if first_line.startswith("REGISTER "):
            if self.accept_unauthenticated_register:
                return self._build_response(200, "OK", headers, extra_headers={
                    "Server": self.server_header,
                    "Expires": headers.get("expires", "0"),
                })
            return self._build_response(401, "Unauthorized", headers, extra_headers={
                "Server": self.server_header,
                "WWW-Authenticate": (
                    'Digest realm="mock-pbx", nonce="deadbeef1234", algorithm=MD5'
                ),
            })

        return None  # unknown method — a real PBX would 501 this, not needed for current tests

    @staticmethod
    def _parse_headers(text: str) -> dict[str, str]:
        headers = {}
        lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
        for line in lines[1:]:
            if not line.strip():
                break
            if ":" not in line:
                continue
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        return headers

    def _build_response(
        self, status_code: int, reason: str, req_headers: dict[str, str],
        extra_headers: dict[str, str],
    ) -> bytes:
        lines = [f"SIP/2.0 {status_code} {reason}"]
        for h in ("via", "from", "to", "call-id", "cseq"):
            if h in req_headers:
                lines.append(f"{h.title()}: {req_headers[h]}")
        for k, v in extra_headers.items():
            lines.append(f"{k}: {v}")
        lines.append("Content-Length: 0")
        lines.append("")
        lines.append("")
        return "\r\n".join(lines).encode("utf-8")


def start_mock_pbx(**kwargs) -> MockPBXServer:
    server = MockPBXServer(**kwargs)
    server.start()
    return server
