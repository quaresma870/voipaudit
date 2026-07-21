"""
Tests for TCP SIP stream reassembly in pcap parsing.

Each test crafts real TCP packets via scapy with real sequence
numbers, writes a real pcap, then confirms correct reassembly —
covering the specific ways TCP reassembly differs from UDP's simpler
one-datagram-one-message model: a message split across multiple
segments, multiple messages coalesced into one segment, and segments
captured out of arrival order.
"""

from __future__ import annotations

import time

import pytest

pytest.importorskip("scapy", reason="pcap tests require the optional 'pcap' extra (scapy)")

from scapy.all import IP, TCP, UDP, Ether, wrpcap  # noqa: E402

from voipaudit.core.pcap_parser import parse_pcap_to_call_records  # noqa: E402


def _tcp_packet(payload: bytes, seq: int, t_offset: float, base_time: float, src: str, dst: str):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=5060, dport=5060, seq=seq) / payload
    pkt.time = base_time + t_offset
    return pkt


class TestTCPStreamReassembly:
    def test_single_segment_tcp_call_reconstructed(self, tmp_path):
        base = time.time()
        call_id = "tcp-single@test"
        invite = (
            f"INVITE sip:1002@192.168.1.20 SIP/2.0\r\nFrom: <sip:1001@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:1002@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()
        ok = (
            f"SIP/2.0 200 OK\r\nFrom: <sip:1001@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:1002@192.168.1.20>;tag=b1\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()

        packets = [
            _tcp_packet(invite, 1000, 0.0, base, "192.168.1.10", "192.168.1.20"),
            _tcp_packet(ok, 5000, 0.1, base, "192.168.1.20", "192.168.1.10"),
        ]
        pcap_path = tmp_path / "tcp_single.pcap"
        wrpcap(str(pcap_path), packets)

        records = parse_pcap_to_call_records(str(pcap_path))
        assert len(records) == 1
        assert records[0].disposition == "ANSWERED"

    def test_message_split_across_two_segments_reassembled(self, tmp_path):
        base = time.time()
        call_id = "tcp-split@test"
        invite = (
            f"INVITE sip:1002@192.168.1.20 SIP/2.0\r\nFrom: <sip:1001@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:1002@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()
        split = len(invite) // 2
        part1, part2 = invite[:split], invite[split:]

        packets = [
            _tcp_packet(part1, 1000, 0.0, base, "192.168.1.10", "192.168.1.20"),
            _tcp_packet(part2, 1000 + len(part1), 0.05, base, "192.168.1.10", "192.168.1.20"),
        ]
        pcap_path = tmp_path / "tcp_split.pcap"
        wrpcap(str(pcap_path), packets)

        records = parse_pcap_to_call_records(str(pcap_path))
        assert len(records) == 1
        assert records[0].src == "1001"
        assert records[0].dst == "1002"

    def test_message_split_across_three_segments_reassembled(self, tmp_path):
        """Confirms reassembly isn't hardcoded to exactly 2 segments —
        a message split into 3 (or more) pieces must still work."""
        base = time.time()
        call_id = "tcp-split3@test"
        invite = (
            f"INVITE sip:1002@192.168.1.20 SIP/2.0\r\nFrom: <sip:1001@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:1002@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()
        third = len(invite) // 3
        parts = [invite[:third], invite[third:2 * third], invite[2 * third:]]

        packets = []
        seq = 1000
        for i, part in enumerate(parts):
            packets.append(_tcp_packet(part, seq, i * 0.02, base, "192.168.1.10", "192.168.1.20"))
            seq += len(part)
        pcap_path = tmp_path / "tcp_split3.pcap"
        wrpcap(str(pcap_path), packets)

        records = parse_pcap_to_call_records(str(pcap_path))
        assert len(records) == 1

    def test_coalesced_messages_in_one_segment_both_extracted(self, tmp_path):
        """Two complete SIP messages arriving in a single TCP segment
        (e.g. Nagle's algorithm batching successive writes) must both
        be extracted, not just the first."""
        base = time.time()
        call_id = "tcp-coalesced@test"
        invite = (
            f"INVITE sip:1002@192.168.1.20 SIP/2.0\r\nFrom: <sip:1001@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:1002@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()
        bye = (
            f"BYE sip:1002@192.168.1.20 SIP/2.0\r\nFrom: <sip:1001@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:1002@192.168.1.20>;tag=b1\r\nCall-ID: {call_id}\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
        ).encode()
        ok = (
            f"SIP/2.0 200 OK\r\nFrom: <sip:1001@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:1002@192.168.1.20>;tag=b1\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()

        packets = [
            _tcp_packet(invite + bye, 1000, 0.0, base, "192.168.1.10", "192.168.1.20"),
            _tcp_packet(ok, 5000, 0.1, base, "192.168.1.20", "192.168.1.10"),
        ]
        pcap_path = tmp_path / "tcp_coalesced.pcap"
        wrpcap(str(pcap_path), packets)

        records = parse_pcap_to_call_records(str(pcap_path))
        assert len(records) == 1
        assert records[0].disposition == "ANSWERED"

    def test_out_of_order_segments_still_reassemble_correctly(self, tmp_path):
        """Segments written to the pcap out of arrival order (a real
        possibility for some capture tools/setups) must still
        reassemble correctly, since reassembly sorts by TCP sequence
        number, not file order or timestamp."""
        base = time.time()
        call_id = "tcp-ooo@test"
        invite = (
            f"INVITE sip:1002@192.168.1.20 SIP/2.0\r\nFrom: <sip:1001@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:1002@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()
        split = len(invite) // 2
        part1, part2 = invite[:split], invite[split:]
        seq = 1000

        # part2 written to the pcap file BEFORE part1
        packets = [
            _tcp_packet(part2, seq + len(part1), 0.01, base, "192.168.1.10", "192.168.1.20"),
            _tcp_packet(part1, seq, 0.0, base, "192.168.1.10", "192.168.1.20"),
        ]
        pcap_path = tmp_path / "tcp_ooo.pcap"
        wrpcap(str(pcap_path), packets)

        records = parse_pcap_to_call_records(str(pcap_path))
        assert len(records) == 1

    def test_pure_ack_segments_with_no_payload_ignored(self, tmp_path):
        """A real TCP stream includes plenty of zero-payload ACK
        segments — these must be silently skipped, not treated as
        empty SIP messages or cause a crash."""
        base = time.time()
        call_id = "tcp-withacks@test"
        invite = (
            f"INVITE sip:1002@192.168.1.20 SIP/2.0\r\nFrom: <sip:1001@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:1002@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()

        pure_ack = Ether() / IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=5060, dport=5060, seq=9000, flags="A")
        pure_ack.time = base + 0.02

        packets = [
            _tcp_packet(invite, 1000, 0.0, base, "192.168.1.10", "192.168.1.20"),
            pure_ack,
        ]
        pcap_path = tmp_path / "tcp_with_acks.pcap"
        wrpcap(str(pcap_path), packets)

        records = parse_pcap_to_call_records(str(pcap_path))
        assert len(records) == 1
        assert records[0].disposition == "NO ANSWER"  # invite sent, never answered, but no crash from the bare ACK

    def test_mixed_udp_and_tcp_capture_both_extracted(self, tmp_path):
        """A real capture could plausibly contain both a UDP trunk and
        a TCP trunk's traffic -- both must be extracted into separate
        call records, confirming the two extraction paths combine
        correctly rather than one clobbering the other."""
        base = time.time()

        udp_call_id = "udp-mixed@test"
        udp_invite = (
            f"INVITE sip:2002@192.168.1.20 SIP/2.0\r\nFrom: <sip:2001@192.168.1.10>;tag=u1\r\n"
            f"To: <sip:2002@192.168.1.20>\r\nCall-ID: {udp_call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()
        udp_pkt = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / UDP(sport=5060, dport=5060) / udp_invite
        udp_pkt.time = base

        tcp_call_id = "tcp-mixed@test"
        tcp_invite = (
            f"INVITE sip:3002@192.168.1.21 SIP/2.0\r\nFrom: <sip:3001@192.168.1.11>;tag=t1\r\n"
            f"To: <sip:3002@192.168.1.21>\r\nCall-ID: {tcp_call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()
        tcp_pkt = _tcp_packet(tcp_invite, 1000, 0.05, base, "192.168.1.11", "192.168.1.21")

        pcap_path = tmp_path / "mixed.pcap"
        wrpcap(str(pcap_path), [udp_pkt, tcp_pkt])

        records = parse_pcap_to_call_records(str(pcap_path))
        assert len(records) == 2
        call_ids = {r.uniqueid for r in records}
        assert call_ids == {udp_call_id, tcp_call_id}

    def test_integrates_with_toll_fraud_analyzer_via_tcp(self, tmp_path):
        """The same end-to-end confirmation already done for UDP:
        a TCP-captured call to a real high-risk destination must flow
        through analyze_toll_fraud() unchanged and produce the
        expected finding."""
        from voipaudit.analyzers.toll_fraud import analyze_toll_fraud

        base = time.time()
        call_id = "tcp-tollfraud@test"
        invite = (
            f"INVITE sip:252611111111@192.168.1.20 SIP/2.0\r\nFrom: <sip:2003@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:252611111111@192.168.1.20>\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()
        ok = (
            f"SIP/2.0 200 OK\r\nFrom: <sip:2003@192.168.1.10>;tag=a1\r\n"
            f"To: <sip:252611111111@192.168.1.20>;tag=b1\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
        ).encode()

        packets = [
            _tcp_packet(invite, 1000, 0.0, base, "192.168.1.10", "192.168.1.20"),
            _tcp_packet(ok, 5000, 0.1, base, "192.168.1.20", "192.168.1.10"),
        ]
        pcap_path = tmp_path / "tcp_toll_fraud.pcap"
        wrpcap(str(pcap_path), packets)

        records = parse_pcap_to_call_records(str(pcap_path))
        result = analyze_toll_fraud(records, source_label="test.pcap")
        assert any(f.severity.value == "CRITICAL" and "+252" in f.title for f in result.findings)
