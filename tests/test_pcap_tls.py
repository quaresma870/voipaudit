"""
Tests for TLS-carried SIP traffic decryption in pcap parsing
(core/pcap_parser.py's _extract_tls_sip_messages/_decrypt_tls_flow).

Each test builds a real TLS 1.2 session (real client, real server,
real AEAD encryption, via tests/fixtures/mock_pbx/tls_pcap.py) into a
real pcap + SSLKEYLOGFILE pair, then confirms parse_pcap_to_call_records
correctly decrypts and reconstructs the call -- not a hand-approximated
ciphertext or a mocked decryption step.
"""

from __future__ import annotations

import pytest

pytest.importorskip("scapy", reason="pcap tests require the optional 'pcap' extra (scapy)")

from tests.fixtures.mock_pbx.tls_pcap import capture_tls12_pcap  # noqa: E402
from voipaudit.core.pcap_parser import (  # noqa: E402
    PcapParseError,
    parse_pcap_sip_messages,
    parse_pcap_to_call_records,
)

_INVITE = (
    b"INVITE sip:1002@192.168.1.20 SIP/2.0\r\n"
    b"From: <sip:1001@192.168.1.10>;tag=a1\r\n"
    b"To: <sip:1002@192.168.1.20>\r\n"
    b"Call-ID: tls-call@test\r\n"
    b"CSeq: 1 INVITE\r\n"
    b"Content-Length: 0\r\n\r\n"
)
_RESP_180 = (
    b"SIP/2.0 180 Ringing\r\n"
    b"From: <sip:1001@192.168.1.10>;tag=a1\r\n"
    b"To: <sip:1002@192.168.1.20>;tag=b1\r\n"
    b"Call-ID: tls-call@test\r\n"
    b"CSeq: 1 INVITE\r\n"
    b"Content-Length: 0\r\n\r\n"
)
_BYE = (
    b"BYE sip:1002@192.168.1.20 SIP/2.0\r\n"
    b"From: <sip:1001@192.168.1.10>;tag=a1\r\n"
    b"To: <sip:1002@192.168.1.20>;tag=b1\r\n"
    b"Call-ID: tls-call@test\r\n"
    b"CSeq: 2 BYE\r\n"
    b"Content-Length: 0\r\n\r\n"
)
_RESP_200 = (
    b"SIP/2.0 200 OK\r\n"
    b"From: <sip:1001@192.168.1.10>;tag=a1\r\n"
    b"To: <sip:1002@192.168.1.20>;tag=b1\r\n"
    b"Call-ID: tls-call@test\r\n"
    b"CSeq: 2 BYE\r\n"
    b"Content-Length: 0\r\n\r\n"
)


class TestTLSPcapDecryption:
    def test_call_decrypted_and_reconstructed_with_keylog(self, tmp_path):
        pcap_path, keylog_path = capture_tls12_pcap(tmp_path, [(_INVITE, _RESP_180), (_BYE, _RESP_200)])

        records = parse_pcap_to_call_records(str(pcap_path), tls_keylog=str(keylog_path))
        assert len(records) == 1
        assert records[0].uniqueid == "tls-call@test"
        assert records[0].src == "1001"
        assert records[0].dst == "1002"

    def test_without_keylog_tls_traffic_silently_yields_nothing(self, tmp_path):
        """The default, opt-in behavior: without --tls-keylog / tls_keylog,
        TLS-carried SIP traffic must be silently skipped (same as any
        other undecryptable traffic), not crash or raise."""
        pcap_path, _keylog_path = capture_tls12_pcap(tmp_path, [(_INVITE, _RESP_180), (_BYE, _RESP_200)])

        records = parse_pcap_to_call_records(str(pcap_path))
        assert records == []

    def test_wrong_keylog_yields_nothing_not_garbage(self, tmp_path):
        """A keylog from a DIFFERENT TLS session (wrong client_random)
        must not produce garbage/wrong plaintext parsed as if it were
        real SIP -- decryption should simply fail closed for every
        record, same as no keylog at all."""
        pcap_path, _real_keylog = capture_tls12_pcap(tmp_path / "session_a", [(_INVITE, _RESP_180)])
        _other_pcap, wrong_keylog = capture_tls12_pcap(tmp_path / "session_b", [(_INVITE, _RESP_180)])

        records = parse_pcap_to_call_records(str(pcap_path), tls_keylog=str(wrong_keylog))
        assert records == []

    def test_missing_keylog_file_raises_pcap_parse_error(self, tmp_path):
        pcap_path, _keylog_path = capture_tls12_pcap(tmp_path, [(_INVITE, _RESP_180)])

        with pytest.raises(PcapParseError):
            parse_pcap_to_call_records(str(pcap_path), tls_keylog=str(tmp_path / "does-not-exist.txt"))

    def test_application_data_record_split_across_two_segments_reassembled(self, tmp_path):
        """Confirms the new TLS-record reassembly logic (record header's
        own length field, buffered across TCP segments) -- mirrors
        test_pcap_tcp.py's existing plain-TCP "message split across
        segments" test, but at the TLS record layer instead of the SIP
        Content-Length layer."""
        pcap_path, keylog_path = capture_tls12_pcap(
            tmp_path, [(_INVITE, _RESP_180), (_BYE, _RESP_200)],
            split_client_record_index=0,  # split the INVITE's application-data record
        )

        records = parse_pcap_to_call_records(str(pcap_path), tls_keylog=str(keylog_path))
        assert len(records) == 1
        assert records[0].uniqueid == "tls-call@test"

    def test_messages_extracted_in_correct_order(self, tmp_path):
        pcap_path, keylog_path = capture_tls12_pcap(tmp_path, [(_INVITE, _RESP_180), (_BYE, _RESP_200)])

        messages = parse_pcap_sip_messages(str(pcap_path), tls_keylog=str(keylog_path))
        assert len(messages) == 4
        kinds = [
            (tm.message.method if tm.message.is_request else tm.message.status_code)
            for tm in messages
        ]
        assert kinds == ["INVITE", 180, "BYE", 200]

    def test_integrates_with_toll_fraud_analyzer(self, tmp_path):
        """The same end-to-end confirmation already done for UDP/TCP: a
        TLS-captured call to a real high-risk destination must flow
        through analyze_toll_fraud() unchanged and produce the expected
        finding."""
        from voipaudit.analyzers.toll_fraud import analyze_toll_fraud

        invite = (
            b"INVITE sip:252611111111@192.168.1.20 SIP/2.0\r\n"
            b"From: <sip:2003@192.168.1.10>;tag=a1\r\n"
            b"To: <sip:252611111111@192.168.1.20>\r\n"
            b"Call-ID: tls-tollfraud@test\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        ok = (
            b"SIP/2.0 200 OK\r\n"
            b"From: <sip:2003@192.168.1.10>;tag=a1\r\n"
            b"To: <sip:252611111111@192.168.1.20>;tag=b1\r\n"
            b"Call-ID: tls-tollfraud@test\r\n"
            b"CSeq: 1 INVITE\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        pcap_path, keylog_path = capture_tls12_pcap(tmp_path, [(invite, ok)])

        records = parse_pcap_to_call_records(str(pcap_path), tls_keylog=str(keylog_path))
        result = analyze_toll_fraud(records, source_label="test-tls.pcap")
        assert any(f.severity.value == "CRITICAL" and "+252" in f.title for f in result.findings)
