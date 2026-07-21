"""
Tests for the caller_id_spoofing plugin — a differential check
comparing a baseline identity against a spoofed one (From-header AND
P-Asserted-Identity), tested against the mock invite responder's
identity-aware behavior (reject_self_spoofed_identity), which
genuinely inspects the claimed identity rather than responding
identically regardless — mirroring the offer-aware SRTP test pattern.
"""

from __future__ import annotations

import datetime
from pathlib import Path

from tests.fixtures.mock_pbx.invite_responder import start_mock_invite_responder
from voipaudit.core.authorization import REQUIRED_INVITE_ACKNOWLEDGMENT
from voipaudit.core.engagement import Engagement


def _write_auth_yaml(path: Path, **overrides) -> None:
    now = datetime.datetime.now(datetime.UTC)
    defaults = {
        "engagement_id": "test-spoof-2026",
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
        "confirmation_phrase": "I confirm authorization for test-spoof-2026",
        "invite_tier_acknowledgment": REQUIRED_INVITE_ACKNOWLEDGMENT,
    }
    defaults.update(overrides)
    import yaml
    path.write_text(yaml.safe_dump(defaults))


class TestCallerIDSpoofingPlugin:
    def _engagement(self, tmp_path) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        eng = Engagement.load(path, tmp_path / "test.audit.jsonl")
        eng.confirm_active_tier("test-spoof-2026")
        eng.confirm_invite_tier("test-spoof-2026")
        return eng

    def test_no_differentiation_reports_medium(self, tmp_path):
        """The mock's plain destination-keyed behaviors (e.g.
        ring_then_silence) don't look at the caller's identity at all
        -- exactly the "no differentiation" case, and the honest,
        non-overclaimed MEDIUM severity this plugin uses for it."""
        from voipaudit.plugins.caller_id_spoofing import CallerIDSpoofingModule

        server = start_mock_invite_responder(destination_behaviors={
            "voipaudit-spoof-test": "ring_then_silence",
        })
        try:
            eng = self._engagement(tmp_path)
            result = CallerIDSpoofingModule(eng, timeout=3.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].severity.value == "MEDIUM"
            assert "no" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_differentiated_handling_reports_info(self, tmp_path):
        """The identity-aware mock behavior specifically rejects a
        self-spoofed identity while routing a normal one -- the
        "identity checks appear present" (safe/expected) outcome."""
        from voipaudit.plugins.caller_id_spoofing import CallerIDSpoofingModule

        server = start_mock_invite_responder(destination_behaviors={
            "voipaudit-spoof-test": "reject_self_spoofed_identity",
        })
        try:
            eng = self._engagement(tmp_path)
            result = CallerIDSpoofingModule(eng, timeout=3.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].severity.value == "INFO"
            assert "differently" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_unreachable_destination_reports_inconclusive(self, tmp_path):
        from voipaudit.plugins.caller_id_spoofing import CallerIDSpoofingModule

        server = start_mock_invite_responder()  # no behaviors -> everything rejects (404) for both probes
        try:
            eng = self._engagement(tmp_path)
            result = CallerIDSpoofingModule(eng, timeout=3.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert result.findings[0].severity.value == "INFO"
            assert "inconclusive" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_custom_spoof_from_respected(self, tmp_path):
        """--spoof-from lets an engagement target a SPECIFIC known
        identity instead of the "destination calling itself" default
        -- confirms the plugin genuinely uses it, not just the
        default."""
        from voipaudit.plugins.caller_id_spoofing import CallerIDSpoofingModule

        server = start_mock_invite_responder(destination_behaviors={
            "voipaudit-spoof-test": "reject_self_spoofed_identity",
        })
        try:
            eng = self._engagement(tmp_path)
            # spoof_from does NOT match the destination itself here,
            # so the identity-aware mock behavior won't reject it --
            # both probes should route identically (MEDIUM), proving
            # spoof_from (not the default self-spoof) was what got sent.
            result = CallerIDSpoofingModule(
                eng, timeout=3.0, spoof_from="some-other-extension",
            ).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert result.findings[0].severity.value == "MEDIUM"
        finally:
            server.stop()

    def test_out_of_scope_target_refused_before_any_invite_sent(self, tmp_path):
        from voipaudit.plugins.caller_id_spoofing import CallerIDSpoofingModule

        eng = self._engagement(tmp_path)
        result = CallerIDSpoofingModule(eng, timeout=2.0).run("10.0.0.99:5060")
        assert result.error is not None
        assert "scope" in result.error.lower()

    def test_cannot_run_without_invite_tier_confirmed(self, tmp_path):
        from voipaudit.plugins.caller_id_spoofing import CallerIDSpoofingModule

        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        eng = Engagement.load(path, tmp_path / "test.audit.jsonl")
        result = CallerIDSpoofingModule(eng, timeout=2.0).run("127.0.0.1:5060")
        assert result.error is not None
        assert "not confirmed" in result.error.lower()
