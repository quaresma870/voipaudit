"""
Transfer-callback confirmation — a single-shot, temporary SIP UAS this
tool runs itself, used only by refer_transfer_abuse's optional
--confirm-transfer-reachable mode.

Why this exists: safe_transfer_probe's default REFER always targets a
synthetic, fictional extension ON THE TARGET ITSELF (see that
function's own docstring) — this proves the target ACCEPTS an
unauthenticated REFER at the signalling level (a 202/NOTIFY), but not
that it will actually place a new call toward an ARBITRARY, externally
-reachable destination of the referrer's choosing. That stronger claim
needs a genuinely different design: point Refer-To at an address THIS
TOOL is listening on instead, and observe whether the target really
does send a new INVITE there. If it does, that is direct, unambiguous
proof — not inferred from signalling — that an unauthenticated REFER
can make the target place a call to anywhere the caller names.

This is, if anything, SAFER than the synthetic-extension default: the
"transferred call" comes back to infrastructure this tool already
controls rather than being placed toward any number at all (fictional
or otherwise) on the target's own network, and this listener never
lets a confirmed callback actually ring or answer — it responds with
603 Decline the instant it's identified, exactly like every other
probe in this toolkit reacts to a real signal at the earliest possible
moment rather than letting anything actually connect.
"""

from __future__ import annotations

import datetime
import ipaddress
import re
import secrets
import socket
import ssl
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from voipaudit.core.sip_message import SIPMessage, parse_sip_message

_CONTENT_LENGTH_RE = re.compile(rb"^content-length\s*:\s*(\d+)\s*$", re.IGNORECASE | re.MULTILINE)


def generate_callback_token() -> str:
    """A per-run random correlation token embedded in the Refer-To
    user part, so an incoming INVITE can be confirmed as genuinely the
    expected transfer callback and not unrelated traffic hitting the
    same port."""
    return f"voipaudit-transfer-confirm-{secrets.token_hex(6)}"


def detect_local_ip_for_target(target_host: str, target_port: int) -> str:
    """The standard no-packets-sent trick for finding which local IP
    the OS would use to reach a given remote host: connect()-ing a UDP
    socket only consults the routing table and binds a local address —
    it never actually transmits anything, since UDP is connectionless.
    Only a reasonable DEFAULT for engagements where the operator's
    machine is directly routable from the target (the common case for
    on-site/internal engagements); --callback-host exists specifically
    to override this for NAT/firewalled setups where it isn't."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((target_host, target_port))
        return sock.getsockname()[0]
    finally:
        sock.close()


def _generate_ephemeral_self_signed_cert(host: str) -> tuple[bytes, bytes]:
    """A short-lived, self-signed certificate for the TLS variant of
    this listener — generated fresh per run, never persisted. There is
    no pre-existing trusted certificate for an arbitrary operator's
    callback address, and self-signed certificates are already the
    normal, expected case throughout this toolkit's own TLS handling
    (see core/sip.py's --insecure precedent) for exactly this kind of
    ad hoc, authorized-engagement usage."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
    )
    try:
        san = x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))])
    except ValueError:
        san = x509.SubjectAlternativeName([x509.DNSName(host)])
    cert = builder.add_extension(san, critical=False).sign(key, hashes.SHA256())

    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    return cert_pem, key_pem


def _build_decline_response(msg: SIPMessage) -> bytes:
    """RFC 3261 §21.4.24: 603 Decline — the standard final response for
    "this destination permanently refuses this call", sent the instant
    the incoming INVITE is confirmed to be the expected callback. A
    to-tag is added if the request didn't already carry one, matching
    how every other UAS response in this toolkit's test fixtures
    behaves for a fresh (not-yet-dialogued) INVITE."""
    to_header = msg.header("to", "")
    if "tag=" not in to_header:
        to_header = f"{to_header};tag={secrets.token_hex(8)}"
    lines = [
        "SIP/2.0 603 Decline",
        f"Via: {msg.header('via', '')}",
        f"From: {msg.header('from', '')}",
        f"To: {to_header}",
        f"Call-ID: {msg.header('call-id', '')}",
        f"CSeq: {msg.header('cseq', '')}",
        "Content-Length: 0",
        "", "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def _read_one_message(conn: socket.socket, deadline: float) -> bytes:
    """Content-Length-aware TCP/TLS framing, mirroring the same
    pattern already used throughout core/sip.py and core/invite_probe.py
    (an already-audited, proven approach — not reinvented here)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return b""
        conn.settimeout(max(0.01, remaining))
        try:
            chunk = conn.recv(4096)
        except OSError:
            return b""
        if not chunk:
            return b""
        buf += chunk

    header_end = buf.find(b"\r\n\r\n")
    header_bytes = buf[:header_end]
    match = _CONTENT_LENGTH_RE.search(header_bytes)
    content_length = int(match.group(1)) if match else 0
    body_so_far = buf[header_end + 4:]

    while len(body_so_far) < content_length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        conn.settimeout(max(0.01, remaining))
        try:
            chunk = conn.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        body_so_far += chunk

    return buf[:header_end + 4] + body_so_far


@dataclass
class TransferCallbackResult:
    received: bool = False
    from_header: str | None = None
    contact_header: str | None = None
    user_agent: str | None = None


class TransferCallbackListener:
    """A single-shot SIP UAS: binds one socket, waits (in a background
    thread, started on __enter__ so its bound host/port are known
    before the caller builds a Refer-To pointing at them) for exactly
    one incoming INVITE whose request-URI contains `expected_token`,
    declines it immediately, and records evidence. Deliberately does
    NOT try to accept/serve more than one call — this exists to answer
    one yes/no question for one probe run, not to be a real UAS."""

    def __init__(self, host: str, port: int, transport: str, expected_token: str, timeout: float):
        self.transport = transport
        self.expected_token = expected_token
        self.timeout = timeout
        self.result = TransferCallbackResult()
        self._cert_dir: tempfile.TemporaryDirectory | None = None
        self._tls_context: ssl.SSLContext | None = None
        self._thread: threading.Thread | None = None

        if transport == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind((host, port))
        elif transport in ("tcp", "tls"):
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((host, port))
            self._sock.listen(1)
        else:
            raise ValueError(f"Unsupported transport {transport!r}: must be 'udp', 'tcp', or 'tls'")

        self.host = host
        self.port = self._sock.getsockname()[1]

        if transport == "tls":
            cert_pem, key_pem = _generate_ephemeral_self_signed_cert(host)
            self._cert_dir = tempfile.TemporaryDirectory()
            cert_path = Path(self._cert_dir.name) / "cert.pem"
            key_path = Path(self._cert_dir.name) / "key.pem"
            cert_path.write_bytes(cert_pem)
            key_path.write_bytes(key_pem)
            self._tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._tls_context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

    def __enter__(self) -> TransferCallbackListener:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        if self._thread:
            self._thread.join(timeout=self.timeout + 1.0)
        try:
            self._sock.close()
        except OSError:
            pass
        if self._cert_dir:
            self._cert_dir.cleanup()

    def _run(self) -> None:
        deadline = time.monotonic() + self.timeout
        try:
            if self.transport == "udp":
                self._run_udp(deadline)
            else:
                self._run_tcp_or_tls(deadline)
        except OSError:
            pass  # listener socket closed out from under us, or a transport-level error -- nothing more to do

    def _run_udp(self, deadline: float) -> None:
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            self._sock.settimeout(max(0.01, remaining))
            try:
                data, addr = self._sock.recvfrom(65535)
            except (TimeoutError, OSError):
                return
            if self._handle(data, lambda resp, _addr=addr: self._sock.sendto(resp, _addr)):
                return

    def _run_tcp_or_tls(self, deadline: float) -> None:
        remaining = deadline - time.monotonic()
        self._sock.settimeout(max(0.01, remaining))
        try:
            conn, _addr = self._sock.accept()
        except (TimeoutError, OSError):
            return
        try:
            if self.transport == "tls":
                assert self._tls_context is not None
                conn.settimeout(max(0.01, deadline - time.monotonic()))
                conn = self._tls_context.wrap_socket(conn, server_side=True)
            data = _read_one_message(conn, deadline)
            if data:
                self._handle(data, conn.sendall)
        except OSError:
            pass
        finally:
            conn.close()

    def _handle(self, data: bytes, sender) -> bool:
        try:
            msg = parse_sip_message(data)
        except Exception:
            return False
        if not msg.is_request or msg.method != "INVITE":
            return False
        if self.expected_token not in (msg.request_uri or ""):
            return False

        self.result.received = True
        self.result.from_header = msg.header("from")
        self.result.contact_header = msg.header("contact")
        self.result.user_agent = msg.header("user-agent")

        try:
            sender(_build_decline_response(msg))
        except OSError:
            pass
        return True
