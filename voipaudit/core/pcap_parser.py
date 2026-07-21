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
    capture timestamp. TCP SIP transport is a documented, tracked
    limitation for this first version — see ROADMAP.md; the
    overwhelming majority of real-world SIP trunk traffic (and
    therefore what a SPAN-port/tcpdump capture actually contains) is
    UDP."""
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


def parse_pcap_sip_messages(pcap_path: str) -> list[_TimestampedMessage]:
    """Extracts every parseable SIP message from a pcap file, in
    capture order. Payloads that don't parse as SIP (any other UDP
    traffic sharing the capture) are silently skipped — this is the
    expected, common case for a real SPAN-port capture, not an error."""
    messages = []
    for ts, payload in _extract_udp_payloads(pcap_path):
        try:
            msg = parse_sip_message(payload)
        except SIPParseError:
            continue
        messages.append(_TimestampedMessage(timestamp=ts, message=msg))
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
