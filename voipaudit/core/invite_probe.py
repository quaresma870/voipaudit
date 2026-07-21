"""
Real SIP INVITE probing — the single most safety-critical module in
this toolkit.

Every other probe voipaudit sends (OPTIONS, REGISTER) has no real-world
side effect beyond the target's own logging/alerting. An INVITE is
categorically different: it can make a real phone ring, and in the
worst case be answered and start accruing real per-minute cost. This
is why invite-tier sits above active-tier in the Authorization/
Engagement model (see core/authorization.py's REQUIRED_INVITE_ACKNOWLEDGMENT
and core/engagement.py's confirm_invite_tier) rather than being folded
into active-tier as just another probe.

The core safety technique: as soon as ANY response arrives that
indicates the call is actually being routed somewhere (180 Ringing,
183 Session Progress, or a 2xx answer), immediately send CANCEL (or,
for the rare case of an instant 2xx answer, ACK followed immediately
by BYE) — the goal is never to observe "does the call complete," only
"does the dialplan route this destination at all," which is fully
answered by the FIRST routing-indicating response. A hard, short
timeout applies throughout, so even a target that never responds at
all can't make this probe hang.

UDP, TCP, and TLS are all supported (transport='udp' default, 'tcp', or
'tls') via a shared _Transport abstraction — the response-handling
state machine above is completely transport-agnostic, so the
CANCEL/ACK+BYE safety logic can't diverge between transports. TLS is
layered directly on top of _TCPTransport's own connection +
stream-framing logic, exactly as core/sip.py's own _send_tls already
does for single-request/response probes — only the handshake/
certificate-verification setup and a best-effort graceful close_notify
before teardown are TLS-specific.
"""

from __future__ import annotations

import re
import secrets
import socket
import ssl
import time
from dataclasses import dataclass, field

from voipaudit.core.sdp import SDPMediaInfo, parse_sdp
from voipaudit.core.sip import _build_tls_context
from voipaudit.core.sip_message import SIPMessage, parse_sip_message

# The longest this probe will ever wait, end to end, for a target that
# never sends anything at all -- deliberately short. A real, working
# dialplan responds (even just 100 Trying) within a few hundred
# milliseconds on almost any real network; there's no legitimate
# reason to wait longer than this for a security probe whose only
# purpose is observing routing behavior, not completing a real call.
DEFAULT_TOTAL_TIMEOUT = 4.0

# Once ANY response has been seen (even just 100 Trying, which alone
# doesn't yet indicate routing), how much longer to wait for something
# more definitive before giving up and cancelling anyway -- keeps a
# target that acknowledges receipt but never progresses further from
# consuming the full DEFAULT_TOTAL_TIMEOUT unnecessarily.
DEFAULT_GRACE_AFTER_FIRST_RESPONSE = 1.5

# RFC 3261 §21.1: 180 Ringing and 183 Session Progress are the two
# provisional responses that specifically indicate the call is being
# routed to and presented at a destination -- 100 Trying alone means
# only "the server received this," not "it's being routed anywhere."
_ROUTING_INDICATING_PROVISIONAL_CODES = (180, 183)


class InviteProbeError(Exception):
    """Raised for a genuine transport-level failure (couldn't even
    send the INVITE, or the socket errored outright) — distinct from
    every other outcome (no response, rejected, routed-then-cancelled),
    which are all valid, informative RESULTS this probe exists to
    produce, not errors."""


@dataclass
class InviteProbeResult:
    responses_seen: list[SIPMessage] = field(default_factory=list)
    appears_routed: bool = False       # saw 180/183, or a 2xx
    final_status_code: int | None = None
    cancelled: bool = False
    acked_and_byed: bool = False
    timed_out_with_no_response: bool = False
    answer_sdp: SDPMediaInfo | None = None  # parsed from the last response that carried an SDP body, if any

    @property
    def rejected_outright(self) -> bool:
        """A final, non-2xx response with NO routing-indicating
        provisional ever seen first — the dialplan refused this
        destination immediately, the safe/expected outcome for a
        properly restricted PBX."""
        return (
            not self.appears_routed
            and self.final_status_code is not None
            and self.final_status_code >= 300
        )


def _gen_branch() -> str:
    return "z9hG4bK" + secrets.token_hex(8)


def _gen_tag() -> str:
    return secrets.token_hex(8)


def _gen_call_id(local_host: str) -> str:
    return f"{secrets.token_hex(12)}@{local_host}"


def build_invite(
    target_host: str, target_port: int, local_host: str, local_port: int,
    from_user: str, to_user: str, branch: str, from_tag: str, call_id: str,
    user_agent: str = "voipaudit/0.1", sdp_body: str | None = None, transport: str = "udp",
    p_asserted_identity: str | None = None,
) -> bytes:
    """No SDP body by default — most callers (toll_fraud_exposure) only
    need to observe how the dialplan/routing responds to the
    request-URI's destination, which doesn't depend on media
    negotiation at all, and omitting SDP entirely is the more
    conservative choice when it isn't needed: nothing claims any
    intent to actually exchange media. sdp_body is used specifically
    by the SRTP-checking plugin, which genuinely needs a real media
    offer in the INVITE to observe what the far end negotiates back —
    same immediate-cancel safety reflex applies regardless of whether
    SDP is present.

    p_asserted_identity (RFC 3325) is used specifically by the
    caller_id_spoofing plugin: normally only ever inserted by a node
    INSIDE a trusted SIP network (a "Spec(T)" trust domain) to assert a
    caller's verified identity to other trusted nodes — an untrusted,
    unauthenticated party (like this tool, sending a bare INVITE with
    no prior registration) supplying its OWN P-Asserted-Identity is
    exactly the differential probe: does the target simply trust
    whatever identity is self-asserted, or does it strip/reject a
    self-supplied one from an untrusted source the way RFC 3325 assumes
    it should.

    transport sets the Via header's transport token (RFC 3261
    §18.2.2 — must reflect the transport actually used, the same
    real, meaningful detail already applied throughout core/sip.py's
    own OPTIONS/REGISTER message builders)."""
    to_uri = f"sip:{to_user}@{target_host}"
    body_bytes = sdp_body.encode("utf-8") if sdp_body else b""
    lines = [
        f"INVITE {to_uri} SIP/2.0",
        f"Via: SIP/2.0/{transport.upper()} {local_host}:{local_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <sip:{from_user}@{local_host}>;tag={from_tag}",
        f"To: <{to_uri}>",
        f"Call-ID: {call_id}",
        "CSeq: 1 INVITE",
        f"Contact: <sip:{from_user}@{local_host}:{local_port}>",
        f"User-Agent: {user_agent}",
    ]
    if p_asserted_identity:
        lines.append(f"P-Asserted-Identity: <sip:{p_asserted_identity}@{local_host}>")
    if sdp_body:
        lines.append("Content-Type: application/sdp")
    lines.append(f"Content-Length: {len(body_bytes)}")
    lines.append("")
    header_bytes = "\r\n".join(lines).encode("utf-8") + b"\r\n"
    return header_bytes + body_bytes


def build_cancel(
    target_host: str, target_port: int, local_host: str, local_port: int,
    from_user: str, to_user: str, branch: str, from_tag: str, call_id: str,
    transport: str = "udp",
) -> bytes:
    """RFC 3261 §9.1: CANCEL MUST use the exact same branch, Call-ID,
    From (with tag), and CSeq NUMBER as the request being cancelled —
    only the method changes (CANCEL, not INVITE) and To must NOT carry
    a tag (the dialog was never established)."""
    to_uri = f"sip:{to_user}@{target_host}"
    lines = [
        f"CANCEL {to_uri} SIP/2.0",
        f"Via: SIP/2.0/{transport.upper()} {local_host}:{local_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <sip:{from_user}@{local_host}>;tag={from_tag}",
        f"To: <{to_uri}>",
        f"Call-ID: {call_id}",
        "CSeq: 1 CANCEL",
        "Content-Length: 0",
        "", "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def build_ack(
    target_host: str, target_port: int, local_host: str, local_port: int,
    from_user: str, to_user: str, branch: str, from_tag: str, to_tag: str, call_id: str,
    transport: str = "udp",
) -> bytes:
    """Sent only in the rare case the target answers (2xx) before the
    probe can cancel — RFC 3261 requires ACK for every 2xx response to
    an INVITE regardless of what happens next, so this always precedes
    the immediate follow-up BYE below, never skipped."""
    to_uri = f"sip:{to_user}@{target_host}"
    lines = [
        f"ACK {to_uri} SIP/2.0",
        f"Via: SIP/2.0/{transport.upper()} {local_host}:{local_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <sip:{from_user}@{local_host}>;tag={from_tag}",
        f"To: <{to_uri}>;tag={to_tag}",
        f"Call-ID: {call_id}",
        "CSeq: 1 ACK",
        "Content-Length: 0",
        "", "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def build_bye(
    target_host: str, target_port: int, local_host: str, local_port: int,
    from_user: str, to_user: str, from_tag: str, to_tag: str, call_id: str,
    transport: str = "udp", cseq_number: int = 2,
) -> bytes:
    """Ends a call that was unexpectedly answered, immediately after
    the mandatory ACK above — a fresh branch (BYE is a new
    transaction, unlike CANCEL which must reuse the INVITE's). cseq_number
    defaults to 2 (the first in-dialog request after the INVITE's own
    CSeq 1) but must be bumped by callers that already sent one other
    in-dialog request first (e.g. safe_transfer_probe's REFER, CSeq 2,
    making its own final BYE CSeq 3) — CSeq MUST strictly increase
    within a dialog per RFC 3261 §12.2.1.1, and reusing an already-spent
    number is a real protocol violation some targets would reject or
    mishandle, not merely a cosmetic detail."""
    to_uri = f"sip:{to_user}@{target_host}"
    branch = _gen_branch()
    lines = [
        f"BYE {to_uri} SIP/2.0",
        f"Via: SIP/2.0/{transport.upper()} {local_host}:{local_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <sip:{from_user}@{local_host}>;tag={from_tag}",
        f"To: <{to_uri}>;tag={to_tag}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq_number} BYE",
        "Content-Length: 0",
        "", "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def build_refer(
    target_host: str, target_port: int, local_host: str, local_port: int,
    from_user: str, to_user: str, from_tag: str, to_tag: str, call_id: str,
    refer_to_user: str, transport: str = "udp", cseq_number: int = 2,
    refer_to_host: str | None = None, refer_to_port: int | None = None,
) -> bytes:
    """RFC 3515: REFER within the dialog already established by a
    successfully-answered INVITE — reuses that dialog's Call-ID/
    From-tag/To-tag (a fresh branch, since REFER is its own
    transaction) and the next CSeq number in the dialog's sequence
    (the INVITE itself was CSeq 1). Refer-To names the transfer
    target — by default (refer_to_host=None) this is always a
    synthetic, fictional extension ON THE TARGET ITSELF, never a
    caller-supplied real destination (see safe_transfer_probe's own
    docstring). refer_to_host/refer_to_port instead point Refer-To at
    an address THIS TOOL is listening on, used only by
    safe_transfer_probe's optional --confirm-transfer-reachable mode
    (core/transfer_confirm.py) to observe a real callback rather than
    inferring acceptance from signalling alone."""
    to_uri = f"sip:{to_user}@{target_host}"
    branch = _gen_branch()
    refer_to_host_used = refer_to_host or target_host
    if refer_to_port:
        refer_to_uri = f"sip:{refer_to_user}@{refer_to_host_used}:{refer_to_port}"
    else:
        refer_to_uri = f"sip:{refer_to_user}@{refer_to_host_used}"
    if refer_to_host and transport != "udp":
        # Hints the target to dial the callback back on the SAME
        # transport this REFER itself arrived over -- standard SIP URI
        # transport parameter usage (RFC 3261 §19.1.1), only meaningful
        # when Refer-To points somewhere other than the target's own
        # default listener.
        refer_to_uri += f";transport={transport}"
    lines = [
        f"REFER {to_uri} SIP/2.0",
        f"Via: SIP/2.0/{transport.upper()} {local_host}:{local_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <sip:{from_user}@{local_host}>;tag={from_tag}",
        f"To: <{to_uri}>;tag={to_tag}",
        f"Call-ID: {call_id}",
        f"CSeq: {cseq_number} REFER",
        f"Refer-To: <{refer_to_uri}>",
        f"Contact: <sip:{from_user}@{local_host}:{local_port}>",
        "Content-Length: 0",
        "", "",
    ]
    return "\r\n".join(lines).encode("utf-8")


def build_ok_response(msg: SIPMessage) -> bytes:
    """A bare 200 OK for an in-dialog REQUEST this tool receives (the
    only one expected during safe_transfer_probe is a NOTIFY reporting
    REFER progress, RFC 3515 §2.4.2 — responding is mandatory
    regardless of what it reports). A SIP response's Via/From/To/
    Call-ID/CSeq are copied verbatim from the request that triggered
    it (RFC 3261 §8.2.6.2 — unlike a new in-dialog REQUEST, a response
    never swaps From/To), so no tag bookkeeping of our own is needed
    here at all."""
    lines = [
        "SIP/2.0 200 OK",
        f"Via: {msg.header('via', '')}",
        f"From: {msg.header('from', '')}",
        f"To: {msg.header('to', '')}",
        f"Call-ID: {msg.header('call-id', '')}",
        f"CSeq: {msg.header('cseq', '')}",
        "Content-Length: 0",
        "", "",
    ]
    return "\r\n".join(lines).encode("utf-8")


class _Transport:
    """A minimal send/receive_one/close interface shared by the UDP
    and TCP implementations below."""

    local_port: int

    def send(self, data: bytes) -> None:
        raise NotImplementedError

    def receive_one(self, timeout: float) -> bytes | None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class _UDPTransport(_Transport):
    def __init__(self, target_host: str, target_port: int, local_port: int):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("0.0.0.0", local_port))
        self._target = (target_host, target_port)
        self.local_port = self._sock.getsockname()[1]

    def send(self, data: bytes) -> None:
        self._sock.sendto(data, self._target)

    def receive_one(self, timeout: float) -> bytes | None:
        self._sock.settimeout(max(0.01, timeout))
        try:
            data, _addr = self._sock.recvfrom(65535)
            return data
        except (TimeoutError, OSError):
            return None

    def close(self) -> None:
        self._sock.close()


class _TCPTransport(_Transport):
    """Connects once, reuses the same connection for the INVITE and
    every follow-up (CANCEL, or ACK+BYE) — the common, interoperable
    behavior for SIP-over-TCP, and simpler than reconnecting per
    message. Framing mirrors core/sip.py's own _read_sip_message
    (Content-Length-aware, buffering any bytes read past the current
    message's end for the next receive_one() call)."""

    def __init__(self, target_host: str, target_port: int, local_port: int, connect_timeout: float):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if local_port:
            self._sock.bind(("0.0.0.0", local_port))
        self._sock.settimeout(connect_timeout)
        self._sock.connect((target_host, target_port))
        self.local_port = self._sock.getsockname()[1]
        self._buf = b""

    def send(self, data: bytes) -> None:
        self._sock.sendall(data)

    def receive_one(self, timeout: float) -> bytes | None:
        deadline = time.monotonic() + timeout
        while b"\r\n\r\n" not in self._buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self._sock.settimeout(max(0.01, remaining))
            try:
                chunk = self._sock.recv(4096)
            except (TimeoutError, OSError):
                return None
            if not chunk:
                return None
            self._buf += chunk

        header_end = self._buf.find(b"\r\n\r\n")
        header_bytes = self._buf[:header_end]
        match = re.search(rb"^content-length\s*:\s*(\d+)\s*$", header_bytes, re.IGNORECASE | re.MULTILINE)
        content_length = int(match.group(1)) if match else 0
        message_end = header_end + 4 + content_length

        while len(self._buf) < message_end:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self._sock.settimeout(max(0.01, remaining))
            try:
                chunk = self._sock.recv(4096)
            except (TimeoutError, OSError):
                return None
            if not chunk:
                return None
            self._buf += chunk

        message, self._buf = self._buf[:message_end], self._buf[message_end:]
        return message

    def close(self) -> None:
        # Confirmed a real, reproducible bug here (not theoretical):
        # calling close() immediately after the final send() (e.g.
        # BYE, sent right before this) intermittently dropped that
        # last message -- reproduced directly with server-side
        # instrumentation showing ACK always arrived but BYE didn't
        # ~40% of the time. A plain close() on a socket that may still
        # have unread incoming data buffered, or hasn't fully flushed
        # its own outstanding writes, can trigger an abrupt RST
        # instead of a graceful FIN, which can discard recently-sent,
        # not-yet-acknowledged data. shutdown(SHUT_WR) signals "no
        # more data from me" gracefully first, giving the OS a proper
        # chance to flush pending writes before the socket is actually
        # torn down -- the same class of fix already needed (for TLS's
        # own unwrap()-before-close()) in the sibling camara-audit
        # repo's mock gateway.
        try:
            self._sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass  # already closed or reset by the peer -- nothing more to gracefully signal
        self._sock.close()


class _TLSTransport(_TCPTransport):
    """TLS (SIPS) layered directly on top of _TCPTransport: an
    SSL-wrapped socket exposes the same sendall()/recv() surface as a
    plain TCP one, so send()/receive_one() are inherited completely
    unchanged from _TCPTransport — only connection setup (the TLS
    handshake and certificate-verification handling, mirroring
    core/sip.py's _build_tls_context exactly, same --insecure
    precedent) and teardown are TLS-specific."""

    def __init__(
        self, target_host: str, target_port: int, local_port: int, connect_timeout: float,
        tls_verify: bool = True,
    ):
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if local_port:
            raw_sock.bind(("0.0.0.0", local_port))
        raw_sock.settimeout(connect_timeout)
        ctx = _build_tls_context(tls_verify)
        self._sock = ctx.wrap_socket(raw_sock, server_hostname=target_host)
        self._sock.connect((target_host, target_port))
        self.local_port = self._sock.getsockname()[1]
        self._buf = b""

    def close(self) -> None:
        # Best-effort graceful TLS close_notify before tearing down --
        # the same class of fix _TCPTransport's own shutdown(SHUT_WR)-
        # before-close() already applies at the plain-TCP level (see
        # ROADMAP.md's v0.6.0 entry), just at the TLS layer instead. A
        # peer that doesn't complete the close_notify handshake (many
        # won't, for a connection that's about to be abandoned anyway)
        # is not an error worth surfacing -- the probe result itself is
        # already meaningful regardless of how gracefully this closes.
        try:
            self._sock.settimeout(1.0)
            self._sock.unwrap()
        except (OSError, ValueError):
            pass
        self._sock.close()


def _open_transport(
    transport: str, target_host: str, target_port: int, local_port: int, connect_timeout: float,
    tls_verify: bool = True,
) -> _Transport:
    if transport == "udp":
        return _UDPTransport(target_host, target_port, local_port)
    if transport == "tcp":
        return _TCPTransport(target_host, target_port, local_port, connect_timeout)
    if transport == "tls":
        return _TLSTransport(target_host, target_port, local_port, connect_timeout, tls_verify=tls_verify)
    raise ValueError(f"Unsupported transport {transport!r}: must be 'udp', 'tcp', or 'tls'")


def safe_invite_probe(
    target_host: str,
    target_port: int,
    to_user: str,
    from_user: str = "voipaudit-probe",
    local_host: str = "0.0.0.0",
    local_port: int = 0,
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
    grace_after_first_response: float = DEFAULT_GRACE_AFTER_FIRST_RESPONSE,
    sdp_offer: str | None = None,
    transport: str = "udp",
    connect_timeout: float = 3.0,
    tls_verify: bool = True,
    p_asserted_identity: str | None = None,
) -> InviteProbeResult:
    """Sends one real INVITE and reacts to whatever comes back,
    cancelling (or ACK+BYE-ing) at the earliest possible moment that
    tells us what we need to know. This is a single, self-contained
    exchange — no retries, no repeated attempts against the same
    destination within this call (a caller wanting multiple
    destinations tested calls this once per destination, each a fully
    independent, individually-timed probe).

    transport selects 'udp' (default), 'tcp', or 'tls' — the
    response-handling logic below (deciding when to CANCEL/ACK+BYE) is
    completely unchanged across all three; only how bytes are sent/
    received differs, isolated entirely in the _Transport
    implementations above. For TCP/TLS, connect_timeout bounds the
    initial connection attempt specifically, separate from
    total_timeout (which bounds waiting for a SIP response once
    connected). tls_verify (transport='tls' only) mirrors core/sip.py's
    own --insecure handling exactly: False skips certificate
    verification, needed to reach a target with a self-signed or
    otherwise unverifiable certificate at all.

    sdp_offer is optional and unused by default (toll_fraud_exposure's
    routing-only checks don't need one) — passed by the SRTP-checking
    plugin, which needs a real media offer to observe what the far end
    negotiates back. Every response carrying a body is parsed as SDP
    and the last one seen is exposed via result.answer_sdp, regardless
    of whether sdp_offer was given (a target could in principle include
    SDP in an unsolicited early-media response even to an offer-less
    INVITE, though this is rare).

    p_asserted_identity is optional and unused by default — passed by
    the caller_id_spoofing plugin (see build_invite's own docstring)."""
    branch = _gen_branch()
    from_tag = _gen_tag()
    call_id = _gen_call_id(local_host if local_host != "0.0.0.0" else "voipaudit")

    result = InviteProbeResult()
    try:
        conn = _open_transport(
            transport, target_host, target_port, local_port, connect_timeout, tls_verify=tls_verify,
        )
    except ssl.SSLCertVerificationError as exc:
        raise InviteProbeError(
            f"TLS certificate verification failed for {target_host}:{target_port}: {exc}. "
            f"Pass tls_verify=False (--insecure) if this is a known, authorized self-signed target."
        ) from exc
    except (OSError, ValueError) as exc:
        raise InviteProbeError(
            f"Could not establish a {transport.upper()} connection to {target_host}:{target_port}: {exc}"
        ) from exc

    try:
        invite = build_invite(
            target_host, target_port, local_host, conn.local_port,
            from_user, to_user, branch, from_tag, call_id, sdp_body=sdp_offer, transport=transport,
            p_asserted_identity=p_asserted_identity,
        )
        try:
            conn.send(invite)
        except OSError as exc:
            raise InviteProbeError(f"Could not send INVITE to {target_host}:{target_port}: {exc}") from exc

        deadline = time.monotonic() + total_timeout
        to_tag: str | None = None

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            data = conn.receive_one(remaining)
            if data is None:
                break

            try:
                msg = parse_sip_message(data)
            except Exception:
                continue  # not a parseable SIP message -- ignore and keep waiting
            if msg.is_request or msg.call_id != call_id:
                continue  # unrelated traffic hitting the same connection/port

            result.responses_seen.append(msg)
            if msg.body and msg.body.strip():
                result.answer_sdp = parse_sdp(msg.body)
            status = msg.status_code or 0

            if status in _ROUTING_INDICATING_PROVISIONAL_CODES:
                result.appears_routed = True
                _send_cancel_and_drain(conn, target_host, target_port, local_host, conn.local_port,
                                        from_user, to_user, branch, from_tag, call_id, result, transport)
                return result

            if 200 <= status < 300:
                result.appears_routed = True
                result.final_status_code = status
                to_tag = _extract_to_tag(msg)
                if to_tag:
                    _send_ack_and_bye(conn, target_host, target_port, local_host, conn.local_port,
                                       from_user, to_user, branch, from_tag, to_tag, call_id, result, transport)
                return result

            if status >= 300:
                result.final_status_code = status
                return result

            # 100 Trying or another 1xx that isn't routing-indicating:
            # keep waiting, but only for the shorter grace period from
            # here, not the full original timeout.
            deadline = min(deadline, time.monotonic() + grace_after_first_response)

        result.timed_out_with_no_response = not result.responses_seen
        if result.responses_seen and not result.final_status_code and not result.appears_routed:
            # Got at least a 100 Trying but nothing more definitive
            # within the grace period -- cancel to be safe, even
            # though nothing routing-indicating was ever confirmed.
            _send_cancel_and_drain(conn, target_host, target_port, local_host, conn.local_port,
                                    from_user, to_user, branch, from_tag, call_id, result, transport)
        return result
    finally:
        conn.close()


def _send_cancel_and_drain(
    conn: _Transport, target_host: str, target_port: int, local_host: str, local_port: int,
    from_user: str, to_user: str, branch: str, from_tag: str, call_id: str, result: InviteProbeResult,
    transport: str,
) -> None:
    cancel = build_cancel(
        target_host, target_port, local_host, local_port, from_user, to_user, branch, from_tag, call_id,
        transport=transport,
    )
    try:
        conn.send(cancel)
        result.cancelled = True
    except OSError:
        pass  # best-effort -- the probe result itself is already meaningful regardless


def _send_ack_and_bye(
    conn: _Transport, target_host: str, target_port: int, local_host: str, local_port: int,
    from_user: str, to_user: str, branch: str, from_tag: str, to_tag: str, call_id: str,
    result: InviteProbeResult, transport: str,
) -> None:
    ack = build_ack(
        target_host, target_port, local_host, local_port, from_user, to_user, branch, from_tag, to_tag, call_id,
        transport=transport,
    )
    bye = build_bye(
        target_host, target_port, local_host, local_port, from_user, to_user, from_tag, to_tag, call_id,
        transport=transport,
    )
    try:
        conn.send(ack)
        conn.send(bye)
        result.acked_and_byed = True
    except OSError:
        pass


def _extract_to_tag(msg: SIPMessage) -> str | None:
    to_header = msg.header("to", "")
    if "tag=" not in to_header:
        return None
    return to_header.split("tag=", 1)[1].split(";")[0].strip()


# The REFER-based transfer probe's Refer-To destination is deliberately
# hardcoded, not caller-configurable, to a synthetic/fictional
# extension -- see safe_transfer_probe's own docstring for the full
# safety reasoning (this probe has no way to cancel whatever call the
# TARGET itself places as a result of an honored REFER, unlike every
# other check in this module). Mirrors toll_fraud_exposure's own
# reserved-for-fictional-use test-number convention.
REFER_TRANSFER_TEST_EXTENSION = "voipaudit-refer-test-5550100"

# How long to wait, after sending the REFER itself, for either a final
# response to the REFER transaction or an in-dialog NOTIFY reporting
# transfer progress -- deliberately short and separate from
# total_timeout (which only bounds the initial INVITE wait), since by
# this point a real dialog is already open and every additional second
# is additional exposure for a probe that has already committed to
# letting a call connect.
DEFAULT_REFER_WAIT_TIMEOUT = 2.0


@dataclass
class TransferProbeResult:
    dialog_established: bool = False
    invite_final_status_code: int | None = None
    refer_sent: bool = False
    refer_final_status_code: int | None = None
    notify_received: bool = False
    notify_sipfrag: str | None = None
    bye_sent: bool = False
    # Only ever populated when callback_host was given (--confirm-
    # transfer-reachable) -- direct, observed evidence rather than
    # inferred from signalling. See core/transfer_confirm.py.
    callback_confirmed: bool = False
    callback_from: str | None = None
    callback_user_agent: str | None = None

    @property
    def refer_appears_honored(self) -> bool:
        """True if the target's own signalling indicates the REFER was
        accepted and, per any NOTIFY received, at least attempted --
        the real, actionable signal this probe exists to produce when
        no callback confirmation was requested, independent of whether
        the resulting transfer itself actually succeeded (this probe
        has no way to observe that without callback_confirmed, and
        Refer-To is a synthetic extension by default — see this
        module's own docstring)."""
        if self.refer_final_status_code is not None and 200 <= self.refer_final_status_code < 300:
            return True
        return bool(self.notify_sipfrag)


def safe_transfer_probe(
    target_host: str,
    target_port: int,
    to_user: str,
    from_user: str = "voipaudit-probe",
    local_host: str = "0.0.0.0",
    local_port: int = 0,
    total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
    grace_after_first_response: float = DEFAULT_GRACE_AFTER_FIRST_RESPONSE,
    transport: str = "udp",
    connect_timeout: float = 3.0,
    tls_verify: bool = True,
    refer_wait_timeout: float = DEFAULT_REFER_WAIT_TIMEOUT,
    callback_host: str | None = None,
    callback_port: int = 0,
) -> TransferProbeResult:
    """Tests whether the target honors an in-dialog REFER (RFC 3515
    call transfer) from an unauthenticated caller — the toll-fraud-via-
    transfer question, distinct from toll_fraud_exposure's own direct-
    INVITE-toward-a-high-risk-destination question, since some
    dialplans restrict direct outbound dialing more tightly than
    transfer-initiated calls.

    This is the first invite-tier probe in this module that lets a call
    actually CONNECT (a real 2xx answer) rather than cancelling at the
    very first routing-indicating response — a materially higher-risk
    step than every other check here, so read this docstring in full
    before using it, and before changing anything about its safety
    reflexes below.

    Why REFER can't reuse safe_invite_probe's immediate-CANCEL reflex:
    that reflex works because every call this tool ever places is one
    IT sent (via this same connection/dialog), so cancelling or
    hanging up is always within this tool's own control. Once a target
    HONORS a REFER by placing a new call toward the Refer-To
    destination, that new call is the TARGET's own outbound call, on
    its own dialog this probe was never a party to — there is no
    message this probe could send to cancel it. This is exactly why
    REFER_TRANSFER_TEST_EXTENSION (the Refer-To target) is a hardcoded,
    synthetic, fictional extension rather than a caller-supplied
    parameter: even in the worst case (the target blindly honors the
    transfer), the result is, at most, an internal dial attempt toward
    a number that almost certainly doesn't exist — never a real,
    billable, external destination this tool has no way to undo.

    The flow: INVITE -> (only if answered) ACK -> REFER -> a bounded
    wait for either a final response to the REFER transaction itself or
    an in-dialog NOTIFY reporting transfer progress (responded to with
    a bare 200 OK per RFC 3515's own requirement, regardless of what it
    reports) -> BYE, unconditionally, ending this dialog as promptly as
    every other probe in this module already does. If the original
    INVITE is never answered (rejected outright, silent, or only
    ringing-then-silence), there is no dialog to test REFER against at
    all — the same CANCEL-on-routing-indicating-response reflex from
    safe_invite_probe applies identically for that case, and the
    result simply reports dialog_established=False, refer_sent=False.

    callback_host (None by default) switches Refer-To from the
    synthetic-extension default to core/transfer_confirm.py's
    TransferCallbackListener, bound at callback_host:callback_port —
    an address THIS TOOL is listening on, so a real callback INVITE
    from the target (if the REFER is actually honored, not just
    acknowledged) can be directly observed rather than inferred from
    signalling alone. See that module's own docstring for the full
    reasoning and why this is, if anything, a SAFER variant than the
    default rather than a riskier one."""
    branch = _gen_branch()
    from_tag = _gen_tag()
    call_id = _gen_call_id(local_host if local_host != "0.0.0.0" else "voipaudit")

    result = TransferProbeResult()
    to_tag: str | None = None
    callback_listener = None
    try:
        conn = _open_transport(
            transport, target_host, target_port, local_port, connect_timeout, tls_verify=tls_verify,
        )
    except ssl.SSLCertVerificationError as exc:
        raise InviteProbeError(
            f"TLS certificate verification failed for {target_host}:{target_port}: {exc}. "
            f"Pass tls_verify=False (--insecure) if this is a known, authorized self-signed target."
        ) from exc
    except (OSError, ValueError) as exc:
        raise InviteProbeError(
            f"Could not establish a {transport.upper()} connection to {target_host}:{target_port}: {exc}"
        ) from exc

    try:
        invite = build_invite(
            target_host, target_port, local_host, conn.local_port,
            from_user, to_user, branch, from_tag, call_id, transport=transport,
        )
        try:
            conn.send(invite)
        except OSError as exc:
            raise InviteProbeError(f"Could not send INVITE to {target_host}:{target_port}: {exc}") from exc

        deadline = time.monotonic() + total_timeout
        answered = False

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            data = conn.receive_one(remaining)
            if data is None:
                break
            try:
                msg = parse_sip_message(data)
            except Exception:
                continue
            if msg.is_request or msg.call_id != call_id:
                continue
            status = msg.status_code or 0

            if status in _ROUTING_INDICATING_PROVISIONAL_CODES:
                # Routed, but not yet answered -- no dialog exists to
                # test REFER against without a real 2xx, so this is
                # exactly safe_invite_probe's own CANCEL case.
                cancel = build_cancel(
                    target_host, target_port, local_host, conn.local_port,
                    from_user, to_user, branch, from_tag, call_id, transport=transport,
                )
                try:
                    conn.send(cancel)
                except OSError:
                    pass
                return result

            if 200 <= status < 300:
                result.invite_final_status_code = status
                to_tag = _extract_to_tag(msg)
                answered = bool(to_tag)
                break

            if status >= 300:
                result.invite_final_status_code = status
                return result  # rejected outright -- no dialog, nothing to test

            deadline = min(deadline, time.monotonic() + grace_after_first_response)

        if not answered:
            return result  # never answered (or answered without an extractable To-tag) -- nothing to test

        result.dialog_established = True

        # RFC 3261: ACK is mandatory for every 2xx response to an
        # INVITE, regardless of what happens next.
        ack = build_ack(
            target_host, target_port, local_host, conn.local_port,
            from_user, to_user, branch, from_tag, to_tag, call_id, transport=transport,
        )
        try:
            conn.send(ack)
        except OSError:
            return result  # can't even ACK -- nothing more to safely attempt

        refer_to_user = REFER_TRANSFER_TEST_EXTENSION
        refer_to_host = None
        refer_to_port = None
        if callback_host is not None:
            from voipaudit.core.transfer_confirm import (
                TransferCallbackListener,
                generate_callback_token,
            )

            refer_to_user = generate_callback_token()
            callback_listener = TransferCallbackListener(
                callback_host, callback_port, transport, refer_to_user, timeout=refer_wait_timeout,
            )
            refer_to_host = callback_listener.host
            refer_to_port = callback_listener.port

        refer = build_refer(
            target_host, target_port, local_host, conn.local_port,
            from_user, to_user, from_tag, to_tag, call_id,
            refer_to_user=refer_to_user, transport=transport, cseq_number=2,
            refer_to_host=refer_to_host, refer_to_port=refer_to_port,
        )
        if callback_listener is not None:
            # Started as close as possible to actually sending the
            # REFER, not any earlier -- every second counted against
            # refer_wait_timeout should be time the target could
            # plausibly be reacting to the REFER, not time spent
            # earlier in the INVITE/ACK exchange.
            callback_listener.__enter__()
        try:
            conn.send(refer)
            result.refer_sent = True
        except OSError:
            return result

        refer_deadline = time.monotonic() + refer_wait_timeout
        while time.monotonic() < refer_deadline:
            remaining = refer_deadline - time.monotonic()
            data = conn.receive_one(remaining)
            if data is None:
                break
            try:
                msg = parse_sip_message(data)
            except Exception:
                continue
            if msg.call_id != call_id:
                continue

            if msg.is_request and msg.method == "NOTIFY":
                result.notify_received = True
                result.notify_sipfrag = msg.body.strip() if msg.body else None
                try:
                    conn.send(build_ok_response(msg))
                except OSError:
                    pass
                continue  # keep waiting out the remaining budget for the REFER's own final response too

            if not msg.is_request and result.refer_final_status_code is None:
                result.refer_final_status_code = msg.status_code

        return result
    finally:
        if callback_listener is not None:
            # __exit__ joins the listener's background thread (bounded
            # by its own timeout, already elapsed or nearly so by this
            # point since it runs for the same refer_wait_timeout
            # window) before its result is read.
            callback_listener.__exit__(None, None, None)
            result.callback_confirmed = callback_listener.result.received
            result.callback_from = callback_listener.result.from_header
            result.callback_user_agent = callback_listener.result.user_agent
        if result.dialog_established and to_tag:
            bye = build_bye(
                target_host, target_port, local_host, conn.local_port,
                from_user, to_user, from_tag, to_tag, call_id, transport=transport,
                cseq_number=3 if result.refer_sent else 2,
            )
            try:
                conn.send(bye)
                result.bye_sent = True
            except OSError:
                pass
        conn.close()
