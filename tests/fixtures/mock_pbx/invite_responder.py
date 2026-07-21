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
    'reject' | 'ring_then_silence' | 'answer' | 'trying_then_silence' | 'silent'.
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

        request_uri = first_line.split(" ")[1] if len(first_line.split(" ")) > 1 else ""
        behavior = "reject"
        for dest_substr, b in self.destination_behaviors.items():
            if dest_substr in request_uri:
                behavior = b
                break

        threading.Thread(target=self._run_behavior, args=(behavior, headers, addr), daemon=True).start()

    def _run_behavior(self, behavior: str, headers: dict[str, str], addr) -> None:
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

    def _send_response(self, status: int, reason: str, req_headers: dict[str, str], addr, to_tag: str | None = None) -> None:
        to_header = req_headers.get("to", "")
        if to_tag and "tag=" not in to_header:
            to_header = f"{to_header};tag={to_tag}"
        lines = [
            f"SIP/2.0 {status} {reason}",
            f"From: {req_headers.get('from', '')}",
            f"To: {to_header}",
            f"Call-ID: {req_headers.get('call-id', '')}",
            f"CSeq: {req_headers.get('cseq', '1 INVITE')}",
            "Content-Length: 0",
            "", "",
        ]
        try:
            self._sock.sendto("\r\n".join(lines).encode(), addr)
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
