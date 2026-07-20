"""
General-purpose SIP (RFC 3261) message parsing — for arbitrary captured
traffic (pcap files), not the active-scanning request/response pairing
core/sip.py already handles.

Deliberately a separate module from core/sip.py rather than extending
it: core/sip.py's SipMessage type specifically represents *a response
to a request this tool itself sent* (status_code/reason_phrase always
populated, never a request line) — reusing it here would mean adding
request-line fields that are meaningless for every existing caller.
This module's SIPMessage instead represents *any* SIP message seen on
the wire, request or response, since pcap traffic is a full bidirectional
conversation this tool didn't initiate at all.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_REQUEST_LINE_RE = re.compile(r"^([A-Z]+)\s+(\S+)\s+SIP/2\.0$")
_STATUS_LINE_RE = re.compile(r"^SIP/2\.0\s+(\d{3})\s*(.*)$")
# A tag is a real, meaningful correlation key: RFC 3261 requires each
# side of a dialog to generate its own tag, and 'To' only gains one
# once the dialog is established (the first request has no To tag,
# every response and subsequent request does) -- not extracted here
# since call correlation in this module keys on Call-ID alone, which
# is sufficient for CDR-shaped duration/disposition analysis without
# needing full dialog-leg disambiguation.
_URI_USER_RE = re.compile(r"sip:([^@;>]+)@")


class SIPParseError(ValueError):
    """Raised when a chunk of bytes doesn't parse as a SIP message at
    all — used by pcap_parser.py to distinguish real SIP payloads from
    unrelated traffic sharing a port, not to reject slightly malformed
    but genuine SIP traffic."""


@dataclass
class SIPMessage:
    is_request: bool
    method: str | None = None          # requests only, e.g. "INVITE"
    request_uri: str | None = None     # requests only
    status_code: int | None = None     # responses only
    reason_phrase: str | None = None   # responses only
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def header(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name.lower(), default)

    @property
    def call_id(self) -> str | None:
        return self.header("call-id")

    @property
    def cseq_number(self) -> int | None:
        cseq = self.header("cseq")
        if not cseq:
            return None
        try:
            return int(cseq.strip().split()[0])
        except (ValueError, IndexError):
            return None

    @property
    def cseq_method(self) -> str | None:
        cseq = self.header("cseq")
        if not cseq:
            return None
        parts = cseq.strip().split()
        return parts[1] if len(parts) > 1 else None

    @property
    def from_user(self) -> str | None:
        m = _URI_USER_RE.search(self.header("from", ""))
        return m.group(1) if m else None

    @property
    def to_user(self) -> str | None:
        m = _URI_USER_RE.search(self.header("to", ""))
        return m.group(1) if m else None


def parse_sip_message(raw: bytes | str) -> SIPMessage:
    """Parses a single SIP message (request or response). Raises
    SIPParseError if the first line isn't a recognizable SIP request
    or status line — the expected, common outcome when scanning
    arbitrary UDP/TCP payloads that happen to share a port with real
    SIP traffic but aren't SIP at all."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines or not lines[0].strip():
        raise SIPParseError("Empty message")

    first_line = lines[0].strip()

    status_match = _STATUS_LINE_RE.match(first_line)
    request_match = _REQUEST_LINE_RE.match(first_line)

    if status_match:
        is_request = False
        method = request_uri = None
        status_code = int(status_match.group(1))
        reason_phrase = status_match.group(2).strip()
    elif request_match:
        is_request = True
        method = request_match.group(1)
        request_uri = request_match.group(2)
        status_code = reason_phrase = None
    else:
        raise SIPParseError(f"Not a recognizable SIP request or status line: {first_line!r}")

    headers: dict[str, str] = {}
    body_start_idx = len(lines)
    for i, line in enumerate(lines[1:], start=1):
        if not line.strip():
            body_start_idx = i + 1
            break
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    body = "\n".join(lines[body_start_idx:])

    return SIPMessage(
        is_request=is_request, method=method, request_uri=request_uri,
        status_code=status_code, reason_phrase=reason_phrase,
        headers=headers, body=body,
    )
