"""
Tests for general SIP message parsing (core/sip_message.py) and pcap
call-session reconstruction (core/pcap_parser.py).

pcap files are generated programmatically within these tests using
real scapy-crafted SIP packets, rather than committing binary fixture
files — this keeps exactly what SIP traffic each test exercises
visible in the test itself, and avoids any binary-diff opacity in
version control for a file format most reviewers can't read directly
anyway.
"""

from __future__ import annotations

import time

import pytest

from voipaudit.core.sip_message import SIPParseError, parse_sip_message

pytest.importorskip("scapy", reason="pcap tests require the optional 'pcap' extra (scapy)")

from scapy.all import IP, UDP, Ether, wrpcap  # noqa: E402

from voipaudit.core.pcap_parser import parse_pcap_to_call_records  # noqa: E402


class TestSIPMessageParsing:
    def test_parses_request_line(self):
        raw = (
            b"INVITE sip:bob@example.com SIP/2.0\r\n"
            b"From: <sip:alice@example.com>;tag=abc\r\n"
            b"To: <sip:bob@example.com>\r\n"
            b"Call-ID: xyz123\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        msg = parse_sip_message(raw)
        assert msg.is_request is True
        assert msg.method == "INVITE"
        assert msg.request_uri == "sip:bob@example.com"
        assert msg.call_id == "xyz123"
        assert msg.cseq_number == 1
        assert msg.cseq_method == "INVITE"
        assert msg.from_user == "alice"
        assert msg.to_user == "bob"

    def test_parses_status_line(self):
        raw = (
            b"SIP/2.0 486 Busy Here\r\n"
            b"From: <sip:alice@example.com>;tag=abc\r\n"
            b"To: <sip:bob@example.com>;tag=def\r\n"
            b"Call-ID: xyz123\r\n"
            b"CSeq: 1 INVITE\r\n\r\n"
        )
        msg = parse_sip_message(raw)
        assert msg.is_request is False
        assert msg.status_code == 486
        assert msg.reason_phrase == "Busy Here"

    def test_non_sip_payload_raises(self):
        with pytest.raises(SIPParseError):
            parse_sip_message(b"GET / HTTP/1.1\r\n\r\n")

    def test_empty_payload_raises(self):
        with pytest.raises(SIPParseError):
            parse_sip_message(b"")

    def test_header_lookup_case_insensitive(self):
        raw = b"SIP/2.0 200 OK\r\nCall-ID: abc\r\n\r\n"
        msg = parse_sip_message(raw)
        assert msg.header("call-id") == "abc"
        assert msg.header("CALL-ID") == "abc"


def _write_pcap(packets, path):
    wrpcap(str(path), packets)


def _sip_packet(payload: str, t_offset: float, base_time: float, src: str, dst: str):
    pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=5060, dport=5060) / payload.encode()
    pkt.time = base_time + t_offset
    return pkt


class TestPcapCallReconstruction:
    """Each test crafts real SIP packets via scapy, writes a real pcap,
    then confirms the reconstructed CDRRecord matches the scenario —
    the same real 'build it, then verify against the real thing'
    method used throughout this whole portfolio, applied to pcap
    parsing specifically since a real cluster/gateway isn't the
    relevant 'real thing' here, a real pcap file is."""

    def test_answered_call_with_bye_reconstructed_correctly(self, tmp_path):
        base = time.time()
        call_id = "call1@test"
        invite = (
            f"INVITE sip:1002@192.168.1.20 SIP/2.0\r\nFrom: <sip:1001@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:1002@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        )
        ok = (
            f"SIP/2.0 200 OK\r\nFrom: <sip:1001@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:1002@192.168.1.20>;tag=b1\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        )
        bye = (
            f"BYE sip:1001@192.168.1.10 SIP/2.0\r\nFrom: <sip:1002@192.168.1.20>;tag=b1\r\n"
            f"To: <sip:1001@192.168.1.10>;tag=a1\r\nCall-ID: {call_id}\r\nCSeq: 1 BYE\r\nContent-Length: 0\r\n\r\n"
        )

        packets = [
            _sip_packet(invite, 0.0, base, "192.168.1.10", "192.168.1.20"),
            _sip_packet(ok, 10.0, base, "192.168.1.20", "192.168.1.10"),
            _sip_packet(bye, 30.0, base, "192.168.1.20", "192.168.1.10"),
        ]
        pcap_path = tmp_path / "call.pcap"
        _write_pcap(packets, pcap_path)

        records = parse_pcap_to_call_records(str(pcap_path))
        assert len(records) == 1
        r = records[0]
        assert r.src == "1001"
        assert r.dst == "1002"
        assert r.disposition == "ANSWERED"
        assert r.duration == 30
        assert r.billsec == 20  # answered at +10s, ended at +30s

    def test_busy_call_never_answered(self, tmp_path):
        base = time.time()
        call_id = "call2@test"
        invite = (
            f"INVITE sip:1003@192.168.1.20 SIP/2.0\r\nFrom: <sip:1001@192.168.1.10>;tag=a2\r\n"
            f"To: <sip:1003@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        )
        busy = (
            f"SIP/2.0 486 Busy Here\r\nFrom: <sip:1001@192.168.1.10>;tag=a2\r\n"
            f"To: <sip:1003@192.168.1.20>;tag=b2\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        )
        packets = [
            _sip_packet(invite, 0.0, base, "192.168.1.10", "192.168.1.20"),
            _sip_packet(busy, 2.0, base, "192.168.1.20", "192.168.1.10"),
        ]
        pcap_path = tmp_path / "busy.pcap"
        _write_pcap(packets, pcap_path)

        records = parse_pcap_to_call_records(str(pcap_path))
        assert len(records) == 1
        assert records[0].disposition == "BUSY"
        assert records[0].billsec == 0
        assert records[0].duration == 2

    def test_no_response_at_all_is_no_answer(self, tmp_path):
        base = time.time()
        call_id = "call3@test"
        invite = (
            f"INVITE sip:1004@192.168.1.20 SIP/2.0\r\nFrom: <sip:1001@192.168.1.10>;tag=a3\r\n"
            f"To: <sip:1004@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        )
        packets = [_sip_packet(invite, 0.0, base, "192.168.1.10", "192.168.1.20")]
        pcap_path = tmp_path / "noanswer.pcap"
        _write_pcap(packets, pcap_path)

        records = parse_pcap_to_call_records(str(pcap_path))
        assert len(records) == 1
        assert records[0].disposition == "NO ANSWER"
        assert records[0].billsec == 0

    def test_multiple_independent_calls_correlated_separately(self, tmp_path):
        """Two entirely separate calls (different Call-IDs) in the
        same capture must be reconstructed as two independent records,
        not merged or confused with each other."""
        base = time.time()
        packets = []
        for i, call_id in enumerate(["callA@test", "callB@test"]):
            invite = (
                f"INVITE sip:200{i}@192.168.1.20 SIP/2.0\r\nFrom: <sip:100{i}@192.168.1.10>;tag=a{i}\r\n"
                f"To: <sip:200{i}@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
            )
            ok = (
                f"SIP/2.0 200 OK\r\nFrom: <sip:100{i}@192.168.1.10>;tag=a{i}\r\n"
                f"To: <sip:200{i}@192.168.1.20>;tag=b{i}\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
            )
            packets.append(_sip_packet(invite, i * 100, base, "192.168.1.10", "192.168.1.20"))
            packets.append(_sip_packet(ok, i * 100 + 1, base, "192.168.1.20", "192.168.1.10"))

        pcap_path = tmp_path / "two_calls.pcap"
        _write_pcap(packets, pcap_path)

        records = parse_pcap_to_call_records(str(pcap_path))
        assert len(records) == 2
        srcs = {r.src for r in records}
        assert srcs == {"1000", "1001"}

    def test_non_sip_udp_traffic_in_capture_ignored_not_fatal(self, tmp_path):
        """Real SPAN-port captures contain plenty of non-SIP UDP
        traffic (DNS, NTP, etc.) sharing the wire — must be silently
        skipped, not treated as a parse failure."""
        base = time.time()
        call_id = "call4@test"
        invite = (
            f"INVITE sip:1005@192.168.1.20 SIP/2.0\r\nFrom: <sip:1001@192.168.1.10>;tag=a4\r\n"
            f"To: <sip:1005@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        )
        ok = (
            f"SIP/2.0 200 OK\r\nFrom: <sip:1001@192.168.1.10>;tag=a4\r\n"
            f"To: <sip:1005@192.168.1.20>;tag=b4\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        )
        packets = [
            _sip_packet(invite, 0.0, base, "192.168.1.10", "192.168.1.20"),
            # Some unrelated, non-SIP UDP traffic mixed into the same capture
            (Ether() / IP(src="192.168.1.30", dst="8.8.8.8") / UDP(sport=53000, dport=53) / b"\x00\x01\x00\x00not really dns either"),
            _sip_packet(ok, 1.0, base, "192.168.1.20", "192.168.1.10"),
        ]
        pcap_path = tmp_path / "mixed.pcap"
        _write_pcap(packets, pcap_path)

        records = parse_pcap_to_call_records(str(pcap_path))
        assert len(records) == 1
        assert records[0].disposition == "ANSWERED"

    def test_missing_pcap_file_raises_pcap_parse_error(self):
        from voipaudit.core.pcap_parser import PcapParseError

        with pytest.raises(PcapParseError):
            parse_pcap_to_call_records("/nonexistent/path/to/file.pcap")

    def test_empty_pcap_produces_no_records_not_crash(self, tmp_path):
        pcap_path = tmp_path / "empty.pcap"
        _write_pcap([], pcap_path)
        records = parse_pcap_to_call_records(str(pcap_path))
        assert records == []

    def test_integrates_with_toll_fraud_analyzer_unchanged(self, tmp_path):
        """The whole point of this feature: pcap-derived CDRRecords
        must work with analyze_toll_fraud() with zero changes to that
        function, confirming it's a genuine drop-in alternative data
        source, not a parallel/divergent analysis path."""
        from voipaudit.analyzers.toll_fraud import analyze_toll_fraud

        base = time.time()
        call_id = "call5@test"
        # +252 (Somalia) is a real entry in HIGH_RISK_PREFIXES
        invite = (
            f"INVITE sip:252611111111@192.168.1.20 SIP/2.0\r\nFrom: <sip:2003@192.168.1.10>;tag=a5\r\n"
            f"To: <sip:252611111111@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        )
        ok = (
            f"SIP/2.0 200 OK\r\nFrom: <sip:2003@192.168.1.10>;tag=a5\r\n"
            f"To: <sip:252611111111@192.168.1.20>;tag=b5\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        )
        packets = [
            _sip_packet(invite, 0.0, base, "192.168.1.10", "192.168.1.20"),
            _sip_packet(ok, 3.0, base, "192.168.1.20", "192.168.1.10"),
        ]
        pcap_path = tmp_path / "toll_fraud.pcap"
        _write_pcap(packets, pcap_path)

        records = parse_pcap_to_call_records(str(pcap_path))
        result = analyze_toll_fraud(records, source_label="test.pcap")
        assert any(f.severity.value == "CRITICAL" and "+252" in f.title for f in result.findings)
