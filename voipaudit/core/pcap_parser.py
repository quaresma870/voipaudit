"""
Pcap parsing and SIP call session reconstruction.

The point of this module: toll-fraud CDR analysis (analyzers/toll_fraud.py)
was originally built against Asterisk's own CDR CSV format only —
useful for Asterisk-based PBX deployments, but most SBC vendors
(Kamailio, OpenSIPS, Oracle/Acme Packet, AudioCodes, Ribbon, and many
more) don't produce that specific CSV shape at all. What every one of
them DOES produce, if you can capture the traffic, is real SIP packets
on the wire — identical in shape regardless of vendor, since SIP
itself is the standard, not any particular CDR export format. Parsing
pcap captures directly makes toll-fraud analysis (and any other
CDR-based check) work against effectively any SBC/PBX, not just
Asterisk, without needing per-vendor CDR format support at all.

Call session reconstruction correlates SIP messages by Call-ID (RFC
3261 §8.1.1.4: Call-ID MUST be identical for all requests/responses
within a dialog) into a normalized CDRRecord — the exact same
dataclass core/cdr.py already produces from Asterisk CSV, so
analyzers/toll_fraud.py's analyze_toll_fraud() works completely
unchanged against pcap-derived data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from voipaudit.core.cdr import CDRRecord
from voipaudit.core.sip_message import SIPMessage, SIPParseError, parse_sip_message


class PcapParseError(Exception):
    """Raised when the pcap file itself can't be read at all (missing
    file, corrupt capture) — distinct from a pcap that reads fine but
    simply contains no SIP traffic, which is a valid (if empty) result."""


@dataclass
class _TimestampedMessage:
    timestamp: datetime
    message: SIPMessage


@dataclass
class _Dialog:
    call_id: str
    messages: list[_TimestampedMessage] = field(default_factory=list)


def _extract_udp_payloads(pcap_path: str) -> list[tuple[datetime, bytes]]:
    """Reads every UDP packet's payload from the pcap, paired with its
    capture timestamp."""
    try:
        from scapy.all import IP, UDP, rdpcap
    except ImportError as exc:
        raise PcapParseError(
            "The 'scapy' package is required for pcap parsing but isn't installed."
        ) from exc

    try:
        packets = rdpcap(pcap_path)
    except (OSError, Exception) as exc:  # scapy raises varied exception types for a bad file
        raise PcapParseError(f"Could not read pcap file {pcap_path!r}: {exc}") from exc

    payloads = []
    for pkt in packets:
        if IP in pkt and UDP in pkt and pkt[UDP].payload:
            ts = datetime.fromtimestamp(float(pkt.time), tz=UTC)
            payloads.append((ts, bytes(pkt[UDP].payload)))
    return payloads


def _extract_tcp_sip_messages(pcap_path: str) -> list[_TimestampedMessage]:
    """TCP is a byte stream, not datagram-framed like UDP — one packet
    doesn't reliably correspond to one SIP message (a message can be
    split across several packets, or several messages coalesced into
    one). This reassembles each unidirectional TCP flow's byte stream
    in sequence-number order, then extracts complete SIP messages from
    it via Content-Length framing, mirroring the exact same framing
    logic core/sip.py's own _read_sip_message already uses for live
    TCP scanning — the only difference here is reading from an
    already-fully-captured buffer instead of a live socket.

    Grouped by UNIDIRECTIONAL flow (src_ip, src_port, dst_ip, dst_port)
    deliberately, not by bidirectional connection: each direction of a
    TCP connection has its own independent sequence-number space and
    needs reassembling separately, and since SIP messages are
    self-contained regardless of direction (a request stream carries
    INVITE/ACK/BYE, a response stream carries SIP/2.0 status lines),
    there's no need to interleave the two directions for parsing."""
    try:
        from scapy.all import IP, TCP, rdpcap
    except ImportError as exc:
        raise PcapParseError(
            "The 'scapy' package is required for pcap parsing but isn't installed."
        ) from exc

    try:
        packets = rdpcap(pcap_path)
    except (OSError, Exception) as exc:
        raise PcapParseError(f"Could not read pcap file {pcap_path!r}: {exc}") from exc

    streams: dict[tuple, list[tuple[int, float, bytes]]] = {}
    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        payload = bytes(pkt[TCP].payload)
        if not payload:
            continue  # a pure ACK or other zero-payload segment -- nothing to reassemble
        flow_key = (pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)
        streams.setdefault(flow_key, []).append((pkt[TCP].seq, float(pkt.time), payload))

    messages: list[_TimestampedMessage] = []
    for segments in streams.values():
        # Real captures are very often already in order, but sorting
        # by TCP sequence number is what makes reassembly correct
        # regardless -- a segment retransmission or a capture that
        # merely recorded packets slightly out of arrival order would
        # otherwise corrupt the reassembled stream.
        segments.sort(key=lambda s: s[0])
        messages.extend(_reassemble_stream_into_messages(segments))
    return messages


def _reassemble_stream_into_messages(segments: list[tuple[int, float, bytes]]) -> list[_TimestampedMessage]:
    buf = b""
    # Tracks, for each byte offset already appended to buf, which
    # segment's timestamp contributed it -- so each extracted message
    # can be timestamped by when its FIRST byte actually arrived on
    # the wire, not just whichever segment happened to complete it.
    offset_timestamps: list[tuple[int, float]] = []
    for _seq, ts, payload in segments:
        offset_timestamps.append((len(buf), ts))
        buf += payload

    messages: list[_TimestampedMessage] = []
    cursor = 0
    while True:
        header_end = buf.find(b"\r\n\r\n", cursor)
        if header_end == -1:
            break  # no complete header block left in the buffer -- a partial message trailing off, discarded

        header_bytes = buf[cursor:header_end]
        match = re.search(rb"^content-length\s*:\s*(\d+)\s*$", header_bytes, re.IGNORECASE | re.MULTILINE)
        content_length = int(match.group(1)) if match else 0

        body_start = header_end + 4
        body_end = body_start + content_length
        if body_end > len(buf):
            break  # the body hasn't fully arrived in this stream yet -- discarded rather than guessed at

        raw_message = buf[cursor:body_end]
        message_ts = _timestamp_for_offset(offset_timestamps, cursor)
        try:
            parsed = parse_sip_message(raw_message)
            messages.append(_TimestampedMessage(timestamp=message_ts, message=parsed))
        except SIPParseError:
            pass  # not a real SIP message after all -- skip and continue past it

        cursor = body_end

    return messages


def _timestamp_for_offset(offset_timestamps: list[tuple[int, float]], offset: int) -> datetime:
    """The timestamp of whichever segment's byte range contains
    `offset` — i.e. when the first byte of a message-at-this-offset
    actually arrived, not an average or the stream's overall start."""
    best = offset_timestamps[0][1]
    for seg_offset, ts in offset_timestamps:
        if seg_offset <= offset:
            best = ts
        else:
            break
    return datetime.fromtimestamp(best, tz=UTC)


def parse_pcap_sip_messages(pcap_path: str) -> list[_TimestampedMessage]:
    """Extracts every parseable SIP message from a pcap file, across
    both UDP and TCP transports, in capture order. Payloads that don't
    parse as SIP (any other traffic sharing the capture) are silently
    skipped — this is the expected, common case for a real
    SPAN-port/tcpdump capture, not an error."""
    messages: list[_TimestampedMessage] = []

    for ts, payload in _extract_udp_payloads(pcap_path):
        try:
            msg = parse_sip_message(payload)
        except SIPParseError:
            continue
        messages.append(_TimestampedMessage(timestamp=ts, message=msg))

    messages.extend(_extract_tcp_sip_messages(pcap_path))

    messages.sort(key=lambda tm: tm.timestamp)
    return messages


# Final (non-provisional) SIP response classes, per RFC 3261 §21: 1xx
# is provisional ("still working on it"), 2xx/3xx/4xx/5xx/6xx are all
# final outcomes for a transaction.
_ANSWERED = "ANSWERED"
_FAILED = "FAILED"
_BUSY = "BUSY"
_NO_ANSWER = "NO ANSWER"

_FAILURE_DISPOSITION_BY_CODE_PREFIX = {
    "486": _BUSY,   # Busy Here
    "600": _BUSY,   # Busy Everywhere
}


def build_call_records(messages: list[_TimestampedMessage]) -> list[CDRRecord]:
    """Groups messages into per-Call-ID dialogs and reconstructs each
    into a CDRRecord, using the same disposition/duration concepts
    Asterisk's own CDR uses (billsec = time from answer to end;
    duration = time from invite to end) so analyze_toll_fraud() needs
    no changes at all to work against this data."""
    dialogs: dict[str, _Dialog] = {}
    for tm in messages:
        call_id = tm.message.call_id
        if not call_id:
            continue
        dialogs.setdefault(call_id, _Dialog(call_id=call_id)).messages.append(tm)

    records: list[CDRRecord] = []
    for dialog in dialogs.values():
        record = _build_single_call_record(dialog)
        if record:
            records.append(record)
    return records


def _build_single_call_record(dialog: _Dialog) -> CDRRecord | None:
    msgs = sorted(dialog.messages, key=lambda tm: tm.timestamp)

    invite = next((tm for tm in msgs if tm.message.is_request and tm.message.method == "INVITE"), None)
    if invite is None:
        return None  # no INVITE in this dialog at all — nothing CDR-shaped to report (e.g. a stray OPTIONS/REGISTER dialog)

    invite_cseq = invite.message.cseq_number

    # The final (non-1xx) response to the INVITE transaction specifically
    # (matched by CSeq number + method, not just "any response in this
    # dialog" — a dialog can carry many transactions, e.g. INVITE then
    # a later re-INVITE or BYE, each with their own CSeq).
    final_response = None
    for tm in msgs:
        m = tm.message
        if m.is_request or m.cseq_method != "INVITE" or m.cseq_number != invite_cseq:
            continue
        if m.status_code and m.status_code >= 200:
            final_response = tm
            if m.status_code < 300:
                break  # a 2xx is the definitive final answer; stop looking
            # a non-2xx final response might still be superseded by a
            # later, different final response in some real retry
            # scenarios -- keep scanning in case, but this is already
            # a reasonable, real final outcome if nothing else follows.

    bye = next(
        (tm for tm in msgs if tm.message.is_request and tm.message.method == "BYE"), None,
    )

    start = invite.timestamp
    src = invite.message.from_user or "unknown"
    dst = invite.message.to_user or invite.message.request_uri or "unknown"

    if final_response and final_response.message.status_code and final_response.message.status_code < 300:
        answer = final_response.timestamp
        end = bye.timestamp if bye else final_response.timestamp
        billsec = max(0, int((end - answer).total_seconds()))
        duration = max(0, int((end - start).total_seconds()))
        disposition = _ANSWERED
    else:
        answer = None
        end = final_response.timestamp if final_response else start
        billsec = 0
        duration = max(0, int((end - start).total_seconds()))
        code = str(final_response.message.status_code) if final_response else None
        disposition = _FAILURE_DISPOSITION_BY_CODE_PREFIX.get(code, _FAILED) if code else _NO_ANSWER

    return CDRRecord(
        accountcode="", src=src, dst=dst, dcontext="pcap", clid=src,
        channel="", dstchannel="", lastapp="", lastdata="",
        start=start, answer=answer, end=end, duration=duration, billsec=billsec,
        disposition=disposition, amaflags="DOCUMENTATION", uniqueid=dialog.call_id,
    )


def parse_pcap_to_call_records(pcap_path: str) -> list[CDRRecord]:
    """The main entry point: pcap file -> list[CDRRecord], ready to
    pass directly into analyze_toll_fraud()."""
    messages = parse_pcap_sip_messages(pcap_path)
    return build_call_records(messages)
