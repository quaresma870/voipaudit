"""
Tests for the refer_transfer_abuse plugin — checks whether the target
honors an in-dialog REFER (call transfer) from an unauthenticated
caller, tested against the mock invite responder's REFER/NOTIFY-aware
behaviors.
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
        "engagement_id": "test-transfer-2026",
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
        "confirmation_phrase": "I confirm authorization for test-transfer-2026",
        "invite_tier_acknowledgment": REQUIRED_INVITE_ACKNOWLEDGMENT,
    }
    defaults.update(overrides)
    import yaml
    path.write_text(yaml.safe_dump(defaults))


class TestReferTransferAbusePlugin:
    def _engagement(self, tmp_path) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        eng = Engagement.load(path, tmp_path / "test.audit.jsonl")
        eng.confirm_active_tier("test-transfer-2026")
        eng.confirm_invite_tier("test-transfer-2026")
        return eng

    def test_honored_transfer_reports_high(self, tmp_path):
        from voipaudit.plugins.refer_transfer_abuse import ReferTransferAbuseModule

        server = start_mock_invite_responder(destination_behaviors={
            "voipaudit-transfer-test": "answer_then_refer_accepted",
        })
        try:
            eng = self._engagement(tmp_path)
            result = ReferTransferAbuseModule(eng, timeout=3.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].severity.value == "HIGH"
            assert "honor" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_confirmed_reachable_transfer_reports_critical(self, tmp_path):
        """--confirm-transfer-reachable against a target that actually
        honors the transfer (places a real callback INVITE) must
        escalate to CRITICAL, the direct-proof outcome."""
        from voipaudit.plugins.refer_transfer_abuse import ReferTransferAbuseModule

        server = start_mock_invite_responder(destination_behaviors={
            "voipaudit-transfer-test": "answer_then_honor_transfer",
        })
        try:
            eng = self._engagement(tmp_path)
            result = ReferTransferAbuseModule(
                eng, timeout=3.0, refer_wait_timeout=2.0,
                confirm_reachable=True, callback_host="127.0.0.1",
            ).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].severity.value == "CRITICAL"
            assert "confirmed" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_confirm_reachable_but_only_acknowledged_stays_high(self, tmp_path):
        """--confirm-transfer-reachable against a target that only
        acknowledges the REFER (202 + NOTIFY) without ever actually
        placing the callback must stay at HIGH, not escalate --
        confirms the plugin genuinely checks callback_confirmed, not
        just whether confirm mode was requested."""
        from voipaudit.plugins.refer_transfer_abuse import ReferTransferAbuseModule

        server = start_mock_invite_responder(destination_behaviors={
            "voipaudit-transfer-test": "answer_then_refer_accepted",
        })
        try:
            eng = self._engagement(tmp_path)
            result = ReferTransferAbuseModule(
                eng, timeout=3.0, refer_wait_timeout=1.5,
                confirm_reachable=True, callback_host="127.0.0.1",
            ).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert result.findings[0].severity.value == "HIGH"
        finally:
            server.stop()

    def test_rejected_transfer_reports_info(self, tmp_path):
        from voipaudit.plugins.refer_transfer_abuse import ReferTransferAbuseModule

        server = start_mock_invite_responder(destination_behaviors={
            "voipaudit-transfer-test": "answer_then_refer_rejected",
        })
        try:
            eng = self._engagement(tmp_path)
            result = ReferTransferAbuseModule(eng, timeout=3.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].severity.value == "INFO"
            assert "not honored" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_unanswered_destination_reports_inconclusive(self, tmp_path):
        from voipaudit.plugins.refer_transfer_abuse import ReferTransferAbuseModule

        server = start_mock_invite_responder()  # no behaviors -> everything rejects, never answers
        try:
            eng = self._engagement(tmp_path)
            result = ReferTransferAbuseModule(eng, timeout=3.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert result.findings[0].severity.value == "INFO"
            assert "inconclusive" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_out_of_scope_target_refused_before_any_invite_sent(self, tmp_path):
        from voipaudit.plugins.refer_transfer_abuse import ReferTransferAbuseModule

        eng = self._engagement(tmp_path)
        result = ReferTransferAbuseModule(eng, timeout=2.0).run("10.0.0.99:5060")
        assert result.error is not None
        assert "scope" in result.error.lower()

    def test_cannot_run_without_invite_tier_confirmed(self, tmp_path):
        from voipaudit.plugins.refer_transfer_abuse import ReferTransferAbuseModule

        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        eng = Engagement.load(path, tmp_path / "test.audit.jsonl")
        result = ReferTransferAbuseModule(eng, timeout=2.0).run("127.0.0.1:5060")
        assert result.error is not None
        assert "not confirmed" in result.error.lower()
