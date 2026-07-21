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
"""

from __future__ import annotations

import re
import socket
import threading
import time

_HEADER_RE = re.compile(r"^([A-Za-z-]+):\s*(.*)$")


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
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((host, 0))
        self.port = self._sock.getsockname()[1]
        self._running = False
        self._thread: threading.Thread | None = None
        self.received_methods: list[str] = []  # for tests to assert what follow-up was actually sent
        self._lock = threading.Lock()

    def start(self) -> None:
        self._running = True
        self._thread = threading.Thread(target=self._serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._sock.close()

    def _serve_forever(self) -> None:
        while self._running:
            try:
                data, addr = self._sock.recvfrom(65535)
            except OSError:
                break
            try:
                self._handle(data, addr)
            except Exception:
                pass

    def _handle(self, data: bytes, addr) -> None:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
        first_line = lines[0]
        headers = self._parse_headers(lines[1:])
        method = first_line.split(" ", 1)[0]

        with self._lock:
            self.received_methods.append(method)

        if method != "INVITE":
            return  # CANCEL/ACK/BYE follow-ups are just recorded above, no response needed for these tests

        # Body is whatever follows the first blank line -- real
        # framing (Content-Length-aware reassembly) isn't needed here
        # since every test using this fixture sends a single-datagram
        # UDP INVITE with the whole SDP body already present.
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

        threading.Thread(target=self._run_behavior, args=(behavior, headers, addr, body), daemon=True).start()

    def _run_behavior(self, behavior: str, headers: dict[str, str], addr, offer_body: str = "") -> None:
        if behavior == "silent":
            return
        if behavior == "reject":
            self._send_response(404, "Not Found", headers, addr)
        elif behavior == "ring_then_silence":
            self._send_response(180, "Ringing", headers, addr, to_tag="mockring")
        elif behavior == "trying_then_silence":
            self._send_response(100, "Trying", headers, addr)
        elif behavior == "answer":
            self._send_response(200, "OK", headers, addr, to_tag="mockans")
        elif behavior == "answer_with_srtp":
            sdp = self._build_answer_sdp("RTP/SAVP", with_crypto=True)
            self._send_response(200, "OK", headers, addr, to_tag="mocksrtp", sdp_body=sdp)
        elif behavior == "answer_with_plain_rtp":
            sdp = self._build_answer_sdp("RTP/AVP", with_crypto=False)
            self._send_response(200, "OK", headers, addr, to_tag="mockplain", sdp_body=sdp)
        elif behavior == "reject_srtp_488":
            # RFC 3261 §21.4.20: 488 Not Acceptable Here -- the standard
            # response when a UAS can't satisfy a media offer's
            # constraints (here, specifically: no SRTP support).
            self._send_response(488, "Not Acceptable Here", headers, addr)
        elif behavior == "srtp_only_pbx":
            # Offer-aware: a real, media-capability-limited PBX --
            # rejects an SRTP-only offer specifically (488), but
            # answers a plain-RTP offer normally. Used to test the
            # SRTP-checking plugin's differential logic for real,
            # since both probes target the SAME destination and can
            # only be told apart by what was actually offered.
            if "RTP/SAVP" in offer_body:
                self._send_response(488, "Not Acceptable Here", headers, addr)
            else:
                sdp = self._build_answer_sdp("RTP/AVP", with_crypto=False)
                self._send_response(200, "OK", headers, addr, to_tag="mockplainonly", sdp_body=sdp)

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

    def _send_response(
        self, status: int, reason: str, req_headers: dict[str, str], addr,
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
            self._sock.sendto("\r\n".join(lines).encode() + b"\r\n" + body_bytes, addr)
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
