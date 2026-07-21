"""
A dedicated mock INVITE responder — FOR TESTS ONLY.

Separate from tests/fixtures/mock_pbx/server.py (which handles the
simpler, single-request/single-response OPTIONS and REGISTER cases):
a real INVITE exchange is inherently multi-step and sometimes
asynchronous (a provisional response now, then either nothing more or
a final response later, then possibly a CANCEL/ACK/BYE follow-up to
react to) — different enough in shape that reusing the existing
single-response UDP handler would mean forcing an awkward fit rather
than a clean extension.

Behavior is selected per-destination-number (the request-URI's user
part), so a single running instance can simulate every scenario
safe_invite_probe needs to handle correctly within one test/plugin
run: outright rejection, ringing-then-silence (the key "dialplan
routes this" signal), an immediate answer, trying-then-silence, and
total silence.

Both UDP and TCP listeners are provided, sharing all response/behavior
logic through a generalized `sender` callable (bytes -> None) — so the
same behavior table works identically regardless of which transport a
test exercises. For TCP, the same connection used for the INVITE stays
open and is read from again for the CANCEL/ACK/BYE follow-up, matching
core/invite_probe.py's own _TCPTransport design of reusing one
connection throughout a probe.
"""

from __future__ import annotations

import re
import socket
import threading
import time
from collections.abc import Callable

_HEADER_RE = re.compile(r"^([A-Za-z-]+):\s*(.*)$")


class _TCPMessageReader:
    """Reads exactly one complete SIP message per read_one() call from
    a TCP stream, correctly bounded to header_end + Content-Length
    bytes and preserving any bytes read beyond that for the NEXT call.

    Confirmed a real, reproducible bug here in an earlier version that
    used a fresh, stateless buffer per call: when two messages (e.g. a
    real ACK immediately followed by BYE, sent as two separate
    sendall() calls but sometimes coalesced by the OS/network into one
    recv()) arrived together, the message-with-Content-Length:-0
    (ACK)'s "body" was computed as *everything after its header block*
    rather than bounded to its own (zero) Content-Length -- silently
    absorbing the next message's bytes into the current one's return
    value, with no persisted buffer to recover them from on the next
    call. Reproduced directly with server-side instrumentation
    (ACK consistently arrived, BYE intermittently vanished ~40% of the
    time) before finding and fixing the real cause here, not just
    adding a delay/retry that would have masked the actual bug."""

    def __init__(self, conn: socket.socket):
        self._conn = conn
        self._buf = b""

    def read_one(self) -> bytes:
        while b"\r\n\r\n" not in self._buf:
            try:
                chunk = self._conn.recv(4096)
            except (TimeoutError, OSError):
                return b""
            if not chunk:
                return b""
            self._buf += chunk

        header_end = self._buf.find(b"\r\n\r\n")
        header_bytes = self._buf[:header_end]
        match = re.search(rb"^content-length\s*:\s*(\d+)\s*$", header_bytes, re.IGNORECASE | re.MULTILINE)
        content_length = int(match.group(1)) if match else 0
        message_end = header_end + 4 + content_length

        while len(self._buf) < message_end:
            try:
                chunk = self._conn.recv(4096)
            except (TimeoutError, OSError):
                return b""
            if not chunk:
                return b""
            self._buf += chunk

        message, self._buf = self._buf[:message_end], self._buf[message_end:]
        return message


class MockInviteResponder:
    """destination_behaviors maps a destination-number substring (the
    request-URI's user part) to a behavior string:
    'reject' | 'ring_then_silence' | 'answer' | 'trying_then_silence' | 'silent'
    | 'answer_with_srtp' | 'answer_with_plain_rtp' | 'reject_srtp_488' | 'srtp_only_pbx'
    (the last one is offer-aware: rejects an SRTP-only offer with 488
    but answers a plain-RTP offer normally, for testing differential
    SRTP-support logic against a single destination).
    Any destination not matching a configured key defaults to 'reject'
    (SIP 404) — the safe, conservative default for an unrecognized
    test case."""

    def __init__(self, host: str = "127.0.0.1", destination_behaviors: dict[str, str] | None = None):
        self.host = host
        self.destination_behaviors = destination_behaviors or {}
        self.received_methods: list[str] = []  # for tests to assert what follow-up was actually sent
        self._lock = threading.Lock()
        self._running = False

        self._udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_sock.bind((host, 0))
        self.port = self._udp_sock.getsockname()[1]
        self._udp_thread: threading.Thread | None = None

        self._tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._tcp_sock.bind((host, 0))
        self._tcp_sock.listen(8)
        self.tcp_port = self._tcp_sock.getsockname()[1]
        self._tcp_thread: threading.Thread | None = None

    def start(self) -> None:
        self._running = True
        self._udp_thread = threading.Thread(target=self._serve_udp_forever, daemon=True)
        self._udp_thread.start()
        self._tcp_thread = threading.Thread(target=self._serve_tcp_forever, daemon=True)
        self._tcp_thread.start()

    def stop(self) -> None:
        self._running = False
        self._udp_sock.close()
        self._tcp_sock.close()

    def _serve_udp_forever(self) -> None:
        while self._running:
            try:
                data, addr = self._udp_sock.recvfrom(65535)
            except OSError:
                break

            def sender(payload: bytes, _addr=addr) -> None:
                self._udp_sock.sendto(payload, _addr)

            try:
                self._handle(data, sender)
            except Exception:
                pass

    def _serve_tcp_forever(self) -> None:
        while self._running:
            try:
                conn, _addr = self._tcp_sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle_tcp_connection, args=(conn,), daemon=True).start()

    def _handle_tcp_connection(self, conn: socket.socket) -> None:
        sender: Callable[[bytes], None] = conn.sendall
        reader = _TCPMessageReader(conn)
        try:
            conn.settimeout(10.0)  # generous -- a probe's INVITE + follow-up both arrive on this one connection
            while self._running:
                data = reader.read_one()
                if not data:
                    break  # peer closed the connection, or nothing more arrives
                self._handle(data, sender)
        except Exception:
            pass
        finally:
            conn.close()

    def _handle(self, data: bytes, sender: Callable[[bytes], None]) -> None:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
        first_line = lines[0]
        headers = self._parse_headers(lines[1:])
        method = first_line.split(" ", 1)[0]

        with self._lock:
            self.received_methods.append(method)

        if method != "INVITE":
            return  # CANCEL/ACK/BYE follow-ups are just recorded above, no response needed for these tests

        if "\r\n\r\n" in text:
            body = text.split("\r\n\r\n", 1)[1]
        else:
            body = ""

        request_uri = first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else ""
        behavior = "reject"
        for dest_substr, b in self.destination_behaviors.items():
            if dest_substr in request_uri:
                behavior = b
                break

        threading.Thread(target=self._run_behavior, args=(behavior, headers, sender, body), daemon=True).start()

    def _run_behavior(
        self, behavior: str, headers: dict[str, str], sender: Callable[[bytes], None], offer_body: str = "",
    ) -> None:
        if behavior == "silent":
            return
        if behavior == "reject":
            self._send_response(404, "Not Found", headers, sender)
        elif behavior == "ring_then_silence":
            self._send_response(180, "Ringing", headers, sender, to_tag="mockring")
        elif behavior == "trying_then_silence":
            self._send_response(100, "Trying", headers, sender)
        elif behavior == "answer":
            self._send_response(200, "OK", headers, sender, to_tag="mockans")
        elif behavior == "answer_with_srtp":
            sdp = self._build_answer_sdp("RTP/SAVP", with_crypto=True)
            self._send_response(200, "OK", headers, sender, to_tag="mocksrtp", sdp_body=sdp)
        elif behavior == "answer_with_plain_rtp":
            sdp = self._build_answer_sdp("RTP/AVP", with_crypto=False)
            self._send_response(200, "OK", headers, sender, to_tag="mockplain", sdp_body=sdp)
        elif behavior == "reject_srtp_488":
            # RFC 3261 §21.4.20: 488 Not Acceptable Here -- the standard
            # response when a UAS can't satisfy a media offer's
            # constraints (here, specifically: no SRTP support).
            self._send_response(488, "Not Acceptable Here", headers, sender)
        elif behavior == "srtp_only_pbx":
            # Offer-aware: a real, media-capability-limited PBX --
            # rejects an SRTP-only offer specifically (488), but
            # answers a plain-RTP offer normally. Used to test the
            # SRTP-checking plugin's differential logic for real,
            # since both probes target the SAME destination and can
            # only be told apart by what was actually offered.
            if "RTP/SAVP" in offer_body:
                self._send_response(488, "Not Acceptable Here", headers, sender)
            else:
                sdp = self._build_answer_sdp("RTP/AVP", with_crypto=False)
                self._send_response(200, "OK", headers, sender, to_tag="mockplainonly", sdp_body=sdp)

    @staticmethod
    def _build_answer_sdp(transport: str, with_crypto: bool) -> str:
        lines = [
            "v=0",
            "o=mockpbx 111111 222222 IN IP4 127.0.0.1",
            "s=-",
            "c=IN IP4 127.0.0.1",
            "t=0 0",
            f"m=audio 20000 {transport} 0",
            "a=rtpmap:0 PCMU/8000",
        ]
        if with_crypto:
            lines.append("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:ZmFrZWtleW1hdGVyaWFsZm9ydGVzdGluZ29ubHk=")
        return "\r\n".join(lines) + "\r\n"

    @staticmethod
    def _send_response(
        status: int, reason: str, req_headers: dict[str, str], sender: Callable[[bytes], None],
        to_tag: str | None = None, sdp_body: str | None = None,
    ) -> None:
        to_header = req_headers.get("to", "")
        if to_tag and "tag=" not in to_header:
            to_header = f"{to_header};tag={to_tag}"
        body_bytes = sdp_body.encode() if sdp_body else b""
        lines = [
            f"SIP/2.0 {status} {reason}",
            f"From: {req_headers.get('from', '')}",
            f"To: {to_header}",
            f"Call-ID: {req_headers.get('call-id', '')}",
            f"CSeq: {req_headers.get('cseq', '1 INVITE')}",
        ]
        if sdp_body:
            lines.append("Content-Type: application/sdp")
        lines.append(f"Content-Length: {len(body_bytes)}")
        lines.append("")
        try:
            sender("\r\n".join(lines).encode() + b"\r\n" + body_bytes)
        except OSError:
            pass

    @staticmethod
    def _parse_headers(lines: list[str]) -> dict[str, str]:
        headers = {}
        for line in lines:
            if not line.strip():
                break
            m = _HEADER_RE.match(line)
            if m:
                headers[m.group(1).lower()] = m.group(2).strip()
        return headers

    def wait_for_methods(self, expected: list[str], timeout: float = 3.0) -> bool:
        """Polls received_methods until every method in `expected` has
        been seen (in any order) or the timeout elapses — used by
        tests to confirm a real CANCEL/ACK/BYE actually arrived after
        an asynchronous provisional response, without a fixed sleep."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if all(m in self.received_methods for m in expected):
                    return True
            time.sleep(0.02)
        with self._lock:
            return all(m in self.received_methods for m in expected)


def start_mock_invite_responder(**kwargs) -> MockInviteResponder:
    server = MockInviteResponder(**kwargs)
    server.start()
    return server
