"""
Tests for core/sdp.py (SDP construction/parsing) and the srtp_check
plugin — the plugin tested against the real, offer-aware mock INVITE
responder (tests/fixtures/mock_pbx/invite_responder.py), confirming
the differential SRTP-vs-plain-RTP logic works against genuinely
different behavior based on what was actually offered, not just a
fixed per-destination response.
"""

from __future__ import annotations

import datetime
from pathlib import Path

from tests.fixtures.mock_pbx.invite_responder import start_mock_invite_responder
from voipaudit.core.authorization import REQUIRED_INVITE_ACKNOWLEDGMENT
from voipaudit.core.engagement import Engagement
from voipaudit.core.sdp import build_audio_offer_sdp, parse_sdp


def _write_auth_yaml(path: Path, **overrides) -> None:
    now = datetime.datetime.now(datetime.UTC)
    defaults = {
        "engagement_id": "test-srtp-2026",
        "authorized_by": "Jane Doe",
        "authorized_contact_email": "jane@example.com",
        "client": "Example Corp",
        "scope": {
            "targets": ["127.0.0.1"],
            "excluded_targets": [],
            "allowed_categories": ["recon", "active", "invite"],
        },
        "window": {
            "start": (now - datetime.timedelta(hours=1)).isoformat(),
            "end": (now + datetime.timedelta(days=1)).isoformat(),
        },
        "confirmation_phrase": "I confirm authorization for test-srtp-2026",
        "invite_tier_acknowledgment": REQUIRED_INVITE_ACKNOWLEDGMENT,
    }
    defaults.update(overrides)
    import yaml
    path.write_text(yaml.safe_dump(defaults))


class TestSDPBuildAndParse:
    def test_srtp_offer_has_savp_transport_and_crypto(self):
        offer = build_audio_offer_sdp("192.168.1.10", 10000, transport="RTP/SAVP")
        info = parse_sdp(offer)
        assert info.media_type == "audio"
        assert info.is_srtp is True
        assert info.has_crypto_attribute is True
        assert info.crypto_suites_offered == ["AES_CM_128_HMAC_SHA1_80"]

    def test_plain_rtp_offer_has_avp_transport_no_crypto(self):
        offer = build_audio_offer_sdp("192.168.1.10", 10000, transport="RTP/AVP")
        info = parse_sdp(offer)
        assert info.is_srtp is False
        assert info.has_crypto_attribute is False

    def test_offer_is_well_formed_sdp(self):
        offer = build_audio_offer_sdp("192.168.1.10", 10000)
        assert offer.startswith("v=0\r\n")
        assert "m=audio 10000" in offer
        assert offer.endswith("\r\n")

    def test_crypto_key_material_is_valid_base64_of_correct_length(self):
        import base64

        offer = build_audio_offer_sdp("192.168.1.10", 10000, transport="RTP/SAVP")
        crypto_line = next(line for line in offer.split("\r\n") if line.startswith("a=crypto:"))
        inline_part = crypto_line.split("inline:")[1]
        decoded = base64.b64decode(inline_part)
        # AES_CM_128_HMAC_SHA1_80 uses a 16-byte master key + 14-byte
        # salt = 30 bytes total, per RFC 4568's standard sizing.
        assert len(decoded) == 30

    def test_parse_sdp_ignores_unrelated_lines(self):
        body = "v=0\r\no=x 1 1 IN IP4 1.2.3.4\r\ns=-\r\nc=IN IP4 1.2.3.4\r\nt=0 0\r\nm=audio 5000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n"
        info = parse_sdp(body)
        assert info.transport == "RTP/AVP"
        assert info.crypto_suites_offered == []

    def test_parse_sdp_handles_multiple_crypto_lines(self):
        body = (
            "v=0\r\nm=audio 5000 RTP/SAVP 0\r\n"
            "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAAA\r\n"
            "a=crypto:2 AES_CM_128_HMAC_SHA1_32 inline:BBBB\r\n"
        )
        info = parse_sdp(body)
        assert info.crypto_suites_offered == ["AES_CM_128_HMAC_SHA1_80", "AES_CM_128_HMAC_SHA1_32"]

    def test_empty_body_produces_empty_info(self):
        info = parse_sdp("")
        assert info.media_type is None
        assert info.is_srtp is False


class TestSRTPCheckPlugin:
    def _engagement(self, tmp_path) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        eng = Engagement.load(path, tmp_path / "test.audit.jsonl")
        eng.confirm_active_tier("test-srtp-2026")
        eng.confirm_invite_tier("test-srtp-2026")
        return eng

    def test_srtp_supported_reports_info(self, tmp_path):
        from voipaudit.plugins.srtp_check import SRTPCheckModule

        server = start_mock_invite_responder(destination_behaviors={
            "voipaudit-srtp-test": "answer_with_srtp",
        })
        try:
            eng = self._engagement(tmp_path)
            result = SRTPCheckModule(eng, timeout=3.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].severity.value == "INFO"
            assert "supported" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_differential_detects_srtp_not_supported(self, tmp_path):
        """The core scenario this plugin's whole design exists for:
        a PBX that answers plain RTP normally but specifically rejects
        an SRTP-only offer to the SAME destination — the offer-aware
        mock responder genuinely inspects what was sent, not just
        which destination was dialed, confirming the plugin's
        differential logic works against real varying behavior."""
        from voipaudit.plugins.srtp_check import SRTPCheckModule

        server = start_mock_invite_responder(destination_behaviors={
            "voipaudit-srtp-test": "srtp_only_pbx",
        })
        try:
            eng = self._engagement(tmp_path)
            result = SRTPCheckModule(eng, timeout=3.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].severity.value == "MEDIUM"
            assert "not supported" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_unreachable_destination_reports_inconclusive_not_false_positive(self, tmp_path):
        """Regression-style test confirming the design intent: an
        unreachable destination (both offers rejected identically)
        must NOT be reported as 'SRTP not supported' -- that would be
        a real false positive conflating destination reachability with
        media capability."""
        from voipaudit.plugins.srtp_check import SRTPCheckModule

        server = start_mock_invite_responder()  # no behaviors configured -> everything rejects
        try:
            eng = self._engagement(tmp_path)
            result = SRTPCheckModule(eng, timeout=3.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert result.findings[0].severity.value == "INFO"
            assert "inconclusive" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_custom_to_user_respected(self, tmp_path):
        from voipaudit.plugins.srtp_check import SRTPCheckModule

        server = start_mock_invite_responder(destination_behaviors={
            "custom-extension-42": "answer_with_srtp",
        })
        try:
            eng = self._engagement(tmp_path)
            result = SRTPCheckModule(eng, timeout=3.0, to_user="custom-extension-42").run(
                f"127.0.0.1:{server.port}"
            )
            assert result.error is None
            assert result.findings[0].severity.value == "INFO"
        finally:
            server.stop()

    def test_out_of_scope_target_refused_before_any_invite_sent(self, tmp_path):
        from voipaudit.plugins.srtp_check import SRTPCheckModule

        eng = self._engagement(tmp_path)
        result = SRTPCheckModule(eng, timeout=2.0).run("10.0.0.99:5060")
        assert result.error is not None
        assert "scope" in result.error.lower()

    def test_cannot_run_without_invite_tier_confirmed(self, tmp_path):
        from voipaudit.plugins.srtp_check import SRTPCheckModule

        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        eng = Engagement.load(path, tmp_path / "test.audit.jsonl")
        # deliberately NOT confirming active or invite tier
        result = SRTPCheckModule(eng, timeout=2.0).run("127.0.0.1:5060")
        assert result.error is not None
        assert "not confirmed" in result.error.lower()
