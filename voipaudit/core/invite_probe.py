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

UDP and TCP are both supported (transport='udp' default, or 'tcp') via
a shared _Transport abstraction — the response-handling state machine
above is completely transport-agnostic, so the CANCEL/ACK+BYE safety
logic can't diverge between the two paths. TLS (SIPS) INVITE transport
remains a tracked gap for now (see ROADMAP.md).
"""

from __future__ import annotations

import re
import secrets
import socket
import time
from dataclasses import dataclass, field

from voipaudit.core.sdp import SDPMediaInfo, parse_sdp
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
    transport: str = "udp",
) -> bytes:
    """Ends a call that was unexpectedly answered, immediately after
    the mandatory ACK above — a fresh branch (BYE is a new
    transaction, unlike CANCEL which must reuse the INVITE's)."""
    to_uri = f"sip:{to_user}@{target_host}"
    branch = _gen_branch()
    lines = [
        f"BYE {to_uri} SIP/2.0",
        f"Via: SIP/2.0/{transport.upper()} {local_host}:{local_port};branch={branch}",
        "Max-Forwards: 70",
        f"From: <sip:{from_user}@{local_host}>;tag={from_tag}",
        f"To: <{to_uri}>;tag={to_tag}",
        f"Call-ID: {call_id}",
        "CSeq: 2 BYE",
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


def _open_transport(
    transport: str, target_host: str, target_port: int, local_port: int, connect_timeout: float,
) -> _Transport:
    if transport == "udp":
        return _UDPTransport(target_host, target_port, local_port)
    if transport == "tcp":
        return _TCPTransport(target_host, target_port, local_port, connect_timeout)
    raise ValueError(f"Unsupported transport {transport!r}: must be 'udp' or 'tcp'")


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
) -> InviteProbeResult:
    """Sends one real INVITE and reacts to whatever comes back,
    cancelling (or ACK+BYE-ing) at the earliest possible moment that
    tells us what we need to know. This is a single, self-contained
    exchange — no retries, no repeated attempts against the same
    destination within this call (a caller wanting multiple
    destinations tested calls this once per destination, each a fully
    independent, individually-timed probe).

    transport selects 'udp' (default) or 'tcp' — the response-handling
    logic below (deciding when to CANCEL/ACK+BYE) is completely
    unchanged between the two; only how bytes are sent/received
    differs, isolated entirely in the _Transport implementations
    above. For TCP, connect_timeout bounds the initial connection
    attempt specifically, separate from total_timeout (which bounds
    waiting for a SIP response once connected).

    sdp_offer is optional and unused by default (toll_fraud_exposure's
    routing-only checks don't need one) — passed by the SRTP-checking
    plugin, which needs a real media offer to observe what the far end
    negotiates back. Every response carrying a body is parsed as SDP
    and the last one seen is exposed via result.answer_sdp, regardless
    of whether sdp_offer was given (a target could in principle include
    SDP in an unsolicited early-media response even to an offer-less
    INVITE, though this is rare)."""
    branch = _gen_branch()
    from_tag = _gen_tag()
    call_id = _gen_call_id(local_host if local_host != "0.0.0.0" else "voipaudit")

    result = InviteProbeResult()
    try:
        conn = _open_transport(transport, target_host, target_port, local_port, connect_timeout)
    except (OSError, ValueError) as exc:
        raise InviteProbeError(
            f"Could not establish a {transport.upper()} connection to {target_host}:{target_port}: {exc}"
        ) from exc

    try:
        invite = build_invite(
            target_host, target_port, local_host, conn.local_port,
            from_user, to_user, branch, from_tag, call_id, sdp_body=sdp_offer, transport=transport,
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
