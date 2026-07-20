"""
Raw SIP (RFC 3261) protocol primitives — message construction, UDP, TCP,
and TLS transport, response parsing.

Deliberately built on raw sockets and hand-constructed SIP messages
rather than a heavy SIP stack (e.g. pjsua2, which needs PJSIP compiled
natively) — matching this portfolio's established preference for
understanding exactly what's on the wire (see redteam-toolkit's raw
HTTP request building via urllib for the same philosophy applied to
HTTP). SIP is a text protocol closely related to HTTP in shape (a
start line, colon-separated headers, a blank line, an optional body),
so this is a small, auditable amount of code, not a real
protocol-stack undertaking.

Three transports are supported, since all three are common in
real-world SIP deployments — UDP for most trunk/PBX signalling, TCP
for messages too large for a single UDP datagram, and TLS (SIPS) for
encrypted signalling. TLS is layered directly on top of the TCP
transport's own connection + stream-framing logic (an SSL-wrapped
socket exposes the same connect()/sendall()/recv() surface as a plain
one), so it needed no separate message-framing implementation of its
own — only the socket wrapping and certificate-verification handling
are new. The Via header's transport token must match what's actually
used (RFC 3261 §18.2.2 — a mismatch is a real, detectable protocol
violation some SBC/PBX implementations reject or mishandle).
"""

from __future__ import annotations

import re
import secrets
import socket
import ssl
import time
from dataclasses import dataclass, field

_VALID_TRANSPORTS = ("udp", "tcp", "tls")


class SipTimeout(Exception):
    """No response received within the configured timeout, or (TCP
    only) the connection was actively refused — both are the expected,
    common outcome for a closed/firewalled/non-SIP port, not
    necessarily an error worth surfacing loudly to the caller. TCP's
    connection-refused is folded into this same exception rather than
    a separate one: from a caller's perspective both mean "no SIP
    response was obtained," and the message text still says which one
    actually happened."""


@dataclass
class SipMessage:
    """A parsed SIP response. status_code/reason_phrase are only
    populated for a status-line response (what every request in this
    module expects back) — this module doesn't need to parse SIP
    *requests* (e.g. an incoming INVITE), only responses to requests
    this tool itself sends."""
    status_code: int
    reason_phrase: str
    headers: dict[str, str] = field(default_factory=dict)
    raw: str = ""
    tls_info: dict | None = None
    """Populated only when the response was received over TLS —
    certificate subject/issuer/expiry and the negotiated protocol
    version/cipher, the basis of the transport_security plugin's
    checks. None for UDP/TCP responses."""

    def header(self, name: str, default: str | None = None) -> str | None:
        """Case-insensitive header lookup — SIP header names are
        case-insensitive per RFC 3261 §7.3.1, and real-world PBX/SBC
        implementations are inconsistent about casing (Server vs
        server, User-Agent vs User-agent)."""
        return self.headers.get(name.lower(), default)


def _gen_branch() -> str:
    # RFC 3261 §8.1.1.7: the branch parameter MUST begin with the magic
    # cookie "z9hG4bK" to be RFC 3261-compliant (distinguishes this
    # from RFC 2543 implementations) — a real, meaningful detail, not
    # arbitrary decoration, since some SBC/PBX implementations reject
    # or specially handle non-compliant branch values.
    return "z9hG4bK" + secrets.token_hex(8)


def _gen_tag() -> str:
    return secrets.token_hex(8)


def _gen_call_id(local_host: str) -> str:
    return f"{secrets.token_hex(12)}@{local_host}"


def _check_transport(transport: str) -> str:
    t = transport.lower()
    if t not in _VALID_TRANSPORTS:
        raise ValueError(f"Unsupported transport {transport!r}: must be one of {_VALID_TRANSPORTS}")
    return t


def build_options_request(
    target_host: str,
    target_port: int,
    local_host: str,
    local_port: int,
    user_agent: str = "voipaudit/0.1",
    transport: str = "udp",
) -> bytes:
    """OPTIONS is the standard, universally-supported SIP 'ping' — RFC
    3261 §11 explicitly describes it as a way to query a server's
    capabilities without establishing a session or side effects (no
    dialog is created, unlike INVITE/REGISTER), making it the safest
    possible first probe against an unknown target. The response's
    Server/User-Agent header commonly reveals the PBX software and
    version — the basis of the pbx_fingerprint module."""
    transport = _check_transport(transport)
    branch = _gen_branch()
    tag = _gen_tag()
    call_id = _gen_call_id(local_host)
    target_uri = f"sip:{target_host}:{target_port}"

    lines = [
        f"OPTIONS {target_uri} SIP/2.0",
        f"Via: SIP/2.0/{transport.upper()} {local_host}:{local_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <sip:voipaudit@{local_host}>;tag={tag}",
        f"To: <{target_uri}>",
        f"Call-ID: {call_id}",
        "CSeq: 1 OPTIONS",
        f"Contact: <sip:voipaudit@{local_host}:{local_port};transport={transport}>",
        f"User-Agent: {user_agent}",
        "Content-Length: 0",
        "", "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def build_register_request(
    target_host: str,
    target_port: int,
    local_host: str,
    local_port: int,
    aor_user: str = "voipaudit-probe",
    expires: int = 0,
    user_agent: str = "voipaudit/0.1",
    transport: str = "udp",
) -> bytes:
    """A REGISTER with no Authorization header at all — the correctly
    configured response to this is 401/407 with a WWW-Authenticate/
    Proxy-Authenticate challenge (RFC 3261 §22.1). A PBX that instead
    responds 200 OK is accepting an unauthenticated registration —
    exactly what register_exposed checks for. expires=0 deliberately
    requests immediate de-registration rather than a real,
    long-lived registration, so that even in the worst case (the
    target genuinely accepts this), nothing persists after the probe
    completes.
    """
    transport = _check_transport(transport)
    branch = _gen_branch()
    tag = _gen_tag()
    call_id = _gen_call_id(local_host)
    aor_uri = f"sip:{aor_user}@{target_host}"

    lines = [
        f"REGISTER sip:{target_host}:{target_port} SIP/2.0",
        f"Via: SIP/2.0/{transport.upper()} {local_host}:{local_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <{aor_uri}>;tag={tag}",
        f"To: <{aor_uri}>",
        f"Call-ID: {call_id}",
        "CSeq: 1 REGISTER",
        f"Contact: <sip:{aor_user}@{local_host}:{local_port};transport={transport}>",
        f"Expires: {expires}",
        f"User-Agent: {user_agent}",
        "Content-Length: 0",
        "", "",
    ]
    return "\r\n".join(lines).encode("utf-8")


_STATUS_LINE_RE = re.compile(r"^SIP/2\.0\s+(\d{3})\s*(.*)$")
_CONTENT_LENGTH_RE = re.compile(rb"^content-length\s*:\s*(\d+)\s*$", re.IGNORECASE | re.MULTILINE)


def parse_sip_response(raw: bytes, tls_info: dict | None = None) -> SipMessage:
    """Parses a SIP response's status line and headers. Deliberately
    does not attempt to interpret the body itself — no probe in this
    module needs one, and SIP bodies (typically SDP) have their own
    separate, non-trivial grammar out of scope here. (The body's raw
    bytes, if any, are still included in .raw for callers that want to
    inspect it manually.)"""
    text = raw.decode("utf-8", errors="replace")
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")

    if not lines:
        raise ValueError("Empty SIP response")

    match = _STATUS_LINE_RE.match(lines[0].strip())
    if not match:
        raise ValueError(f"Not a valid SIP status line: {lines[0]!r}")

    status_code = int(match.group(1))
    reason_phrase = match.group(2).strip()

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line.strip():
            break  # blank line = end of headers
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    return SipMessage(
        status_code=status_code, reason_phrase=reason_phrase, headers=headers, raw=text,
        tls_info=tls_info,
    )


def send_sip_request(
    message: bytes,
    target_host: str,
    target_port: int,
    timeout: float = 3.0,
    local_port: int = 0,
    transport: str = "udp",
    tls_verify: bool = True,
) -> SipMessage:
    """Sends a single SIP message and waits for one response, over
    UDP, TCP, or TLS. Raises SipTimeout if nothing usable comes back
    within `timeout` seconds — the expected, common outcome for a
    closed, filtered, or non-SIP port, deliberately a distinct
    exception from a real protocol/parse error so callers can tell
    "target didn't answer" apart from "target answered with something
    we couldn't parse".

    tls_verify=False skips certificate validation — needed to reach a
    target with a self-signed or otherwise unverifiable certificate at
    all, an extremely common situation for exactly the kind of
    authorized internal engagements this tool exists for (matching the
    same --insecure precedent already established in the sibling
    redteam-toolkit repo). This never silently downgrades security: it
    only affects whether THIS client verifies the target's own
    certificate, not whether the target itself has weak TLS
    configured — that's exactly what transport_security's own findings
    check for, using the very information tls_verify=False makes it
    possible to reach in the first place."""
    transport = _check_transport(transport)
    if transport == "udp":
        return _send_udp(message, target_host, target_port, timeout, local_port)
    if transport == "tcp":
        return _send_tcp(message, target_host, target_port, timeout, local_port)
    return _send_tls(message, target_host, target_port, timeout, local_port, tls_verify)


def _send_udp(message: bytes, target_host: str, target_port: int, timeout: float, local_port: int) -> SipMessage:
    """UDP is connectionless and datagram-framed: one sendto() puts
    exactly one datagram on the wire, and one recvfrom() reliably
    returns exactly one complete datagram back — no message-framing
    logic is needed, unlike TCP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.bind(("0.0.0.0", local_port))
        sock.sendto(message, (target_host, target_port))
        try:
            data, _addr = sock.recvfrom(65535)
        except TimeoutError:
            raise SipTimeout(
                f"No SIP response from {target_host}:{target_port} (UDP) within {timeout}s"
            ) from None
        return parse_sip_response(data)
    finally:
        sock.close()


def _send_tcp(message: bytes, target_host: str, target_port: int, timeout: float, local_port: int) -> SipMessage:
    """TCP is connection-oriented and stream-framed: unlike UDP, a
    single recv() call has no guaranteed relationship to message
    boundaries — the response has to be read incrementally and framed
    correctly (headers up to the blank line, then exactly
    Content-Length more bytes for any body), via _read_sip_message."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        if local_port:
            sock.bind(("0.0.0.0", local_port))
        try:
            sock.connect((target_host, target_port))
        except (TimeoutError, ConnectionRefusedError, OSError) as exc:
            raise SipTimeout(
                f"Could not establish a TCP connection to {target_host}:{target_port}: {exc}"
            ) from None

        sock.sendall(message)
        try:
            data = _read_sip_message(sock, timeout)
        except TimeoutError:
            raise SipTimeout(
                f"No SIP response from {target_host}:{target_port} (TCP) within {timeout}s"
            ) from None
        if not data:
            raise SipTimeout(
                f"{target_host}:{target_port} (TCP) closed the connection with no SIP response"
            )
        return parse_sip_response(data)
    finally:
        sock.close()


def _build_tls_context(verify: bool) -> ssl.SSLContext:
    if verify:
        return ssl.create_default_context()
    # Deliberately mirrors the exact --insecure precedent already
    # established in the sibling redteam-toolkit repo's
    # Engagement.ssl_context() — needed to reach a target with a
    # self-signed or otherwise unverifiable certificate at all, an
    # extremely common situation for exactly the kind of authorized
    # internal engagements this tool exists for. This does not affect
    # what cipher/protocol the TLS handshake itself negotiates, only
    # whether this client validates the target's certificate chain.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _extract_tls_info(ssl_sock: ssl.SSLSocket, verify: bool) -> dict:
    """Pulls certificate and negotiated-connection details off an
    already-handshaked TLS socket — the basis of transport_security's
    checks (expired/self-signed certificate, weak protocol version).
    getpeercert() only returns a decoded certificate dict when
    verify_mode required one to be presented and validated
    (CERT_REQUIRED, the default) — with verification disabled
    (tls_verify=False) it returns an empty dict instead, even though a
    certificate genuinely was presented. This is by design in Python's
    ssl module (documented: "If the certificate was not validated, the
    dict is empty") — there is no verify_mode that gets both "don't
    refuse an unverifiable target" and "still populate the parsed
    dict." Confirmed this was a real, not theoretical, problem: it
    means transport_security's own certificate-expiry check would
    silently never fire for any target scanned with this plugin's own
    default tls_verify=False, exactly the setting the plugin needs to
    even reach a self-signed target at all — found by actually running
    the plugin against the real mock PBX and noticing the expected
    certificate-expiry finding never appeared, not by reasoning about
    the ssl module's behavior in the abstract.

    Fixed by parsing the certificate's raw DER bytes directly via the
    `cryptography` library instead, using getpeercert(binary_form=True)
    (which — unlike the dict form — IS populated regardless of
    verify_mode) as the input. This works identically whether or not
    verification succeeded."""
    cert_der = ssl_sock.getpeercert(binary_form=True)
    info = {
        "protocol_version": ssl_sock.version(),
        "cipher": ssl_sock.cipher(),
        "certificate_verified": verify,
        "certificate_present": cert_der is not None,
    }
    if cert_der:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(cert_der)
        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
        info["not_before"] = cert.not_valid_before_utc.isoformat()
        info["not_after"] = cert.not_valid_after_utc.isoformat()
    return info


def _send_tls(
    message: bytes, target_host: str, target_port: int, timeout: float,
    local_port: int, tls_verify: bool,
) -> SipMessage:
    """TLS is layered directly on top of a TCP connection — an
    SSL-wrapped socket exposes the same connect()/sendall()/recv()
    surface as a plain TCP one, so _read_sip_message's stream-framing
    logic is reused unchanged, not reimplemented."""
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if local_port:
        raw_sock.bind(("0.0.0.0", local_port))
    raw_sock.settimeout(timeout)

    ctx = _build_tls_context(tls_verify)
    sock = ctx.wrap_socket(raw_sock, server_hostname=target_host)
    try:
        try:
            sock.connect((target_host, target_port))
        except ssl.SSLCertVerificationError as exc:
            raise SipTimeout(
                f"TLS certificate verification failed for {target_host}:{target_port}: {exc}. "
                f"Pass tls_verify=False (--insecure) if this is a known, authorized self-signed target."
            ) from None
        except (TimeoutError, ConnectionRefusedError, OSError) as exc:
            raise SipTimeout(
                f"Could not establish a TLS connection to {target_host}:{target_port}: {exc}"
            ) from None

        tls_info = _extract_tls_info(sock, tls_verify)

        sock.sendall(message)
        try:
            data = _read_sip_message(sock, timeout)
        except TimeoutError:
            raise SipTimeout(
                f"No SIP response from {target_host}:{target_port} (TLS) within {timeout}s"
            ) from None
        if not data:
            raise SipTimeout(
                f"{target_host}:{target_port} (TLS) closed the connection with no SIP response"
            )
        return parse_sip_response(data, tls_info=tls_info)
    finally:
        sock.close()


def _read_sip_message(sock: socket.socket, timeout: float) -> bytes:
    """Reads exactly one complete SIP message from a TCP stream: keeps
    calling recv() until the blank line ending the headers has
    arrived, parses Content-Length from what's been read so far, then
    keeps reading until that many body bytes have also arrived.
    Respects the overall `timeout` across the whole read, not per
    individual recv() call, so a target that dribbles bytes one at a
    time can't use that to bypass the configured timeout."""
    deadline = time.monotonic() + timeout
    buf = b""

    # Phase 1: read until the blank line ending the headers.
    while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out reading SIP headers")
        sock.settimeout(remaining)
        chunk = sock.recv(4096)
        if not chunk:
            return buf  # connection closed — return whatever we have (may be empty)
        buf += chunk

    header_end = buf.find(b"\r\n\r\n")
    header_terminator_len = 4
    if header_end == -1:
        header_end = buf.find(b"\n\n")
        header_terminator_len = 2

    header_bytes = buf[:header_end]
    body_so_far = buf[header_end + header_terminator_len:]

    match = _CONTENT_LENGTH_RE.search(header_bytes)
    content_length = int(match.group(1)) if match else 0

    # Phase 2: read any remaining body bytes not already captured above.
    while len(body_so_far) < content_length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("timed out reading SIP message body")
        sock.settimeout(remaining)
        chunk = sock.recv(4096)
        if not chunk:
            break  # connection closed early — return what we have
        body_so_far += chunk

    return buf[:header_end] + buf[header_end:header_end + header_terminator_len] + body_so_far
