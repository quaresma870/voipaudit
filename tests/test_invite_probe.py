"""
Tests for the invite-tier safety infrastructure: the 3-layer
authorization/confirmation model (written acknowledgment in
authorization.yml -> confirm_active_tier -> confirm_invite_tier), and
safe_invite_probe's response-driven immediate-cancel/ack-bye behavior,
tested against a real dedicated mock INVITE responder over real UDP
sockets — the most safety-critical code in this whole toolkit, so
tested more thoroughly than most.
"""

from __future__ import annotations

import datetime
import time
from pathlib import Path

import pytest

from tests.fixtures.mock_pbx.invite_responder import start_mock_invite_responder
from voipaudit.core.authorization import (
    REQUIRED_INVITE_ACKNOWLEDGMENT,
    AuthorizationError,
    load_authorization,
)
from voipaudit.core.engagement import (
    Engagement,
    InviteTierNotConfirmed,
)
from voipaudit.core.invite_probe import safe_invite_probe


def _write_auth_yaml(path: Path, **overrides) -> None:
    now = datetime.datetime.now(datetime.UTC)
    defaults = {
        "engagement_id": "test-invite-2026",
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
        "confirmation_phrase": "I confirm authorization for test-invite-2026",
        "invite_tier_acknowledgment": REQUIRED_INVITE_ACKNOWLEDGMENT,
    }
    defaults.update(overrides)
    import yaml
    path.write_text(yaml.safe_dump(defaults))


class TestInviteTierAuthorization:
    def test_invite_category_without_acknowledgment_rejected(self, tmp_path):
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path, invite_tier_acknowledgment=None)
        with pytest.raises(AuthorizationError, match="invite_tier_acknowledgment"):
            load_authorization(path)

    def test_invite_category_with_wrong_acknowledgment_text_rejected(self, tmp_path):
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path, invite_tier_acknowledgment="I agree to this")
        with pytest.raises(AuthorizationError, match="does not exactly match"):
            load_authorization(path)

    def test_invite_category_with_exact_acknowledgment_accepted(self, tmp_path):
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        auth = load_authorization(path)
        assert auth.invite_tier_acknowledgment == REQUIRED_INVITE_ACKNOWLEDGMENT

    def test_no_invite_category_does_not_require_acknowledgment(self, tmp_path):
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path, scope={
            "targets": ["127.0.0.1"], "excluded_targets": [], "allowed_categories": ["recon"],
        }, invite_tier_acknowledgment=None)
        auth = load_authorization(path)  # must not raise
        assert auth.invite_tier_acknowledgment is None


class TestInviteTierEngagementEscalation:
    def _engagement(self, tmp_path, **overrides) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path, **overrides)
        return Engagement.load(path, tmp_path / "test.audit.jsonl")

    def test_invite_tier_refused_without_active_tier_confirmed_first(self, tmp_path):
        eng = self._engagement(tmp_path)
        with pytest.raises(InviteTierNotConfirmed, match="active-tier"):
            eng.confirm_invite_tier("test-invite-2026")

    def test_invite_tier_succeeds_after_active_tier_confirmed(self, tmp_path):
        eng = self._engagement(tmp_path)
        eng.confirm_active_tier("test-invite-2026")
        eng.confirm_invite_tier("test-invite-2026")  # must not raise
        assert eng._invite_tier_confirmed is True

    def test_invite_tier_refused_without_invite_in_allowed_categories(self, tmp_path):
        eng = self._engagement(tmp_path, scope={
            "targets": ["127.0.0.1"], "excluded_targets": [], "allowed_categories": ["recon", "active"],
        }, invite_tier_acknowledgment=None)
        eng.confirm_active_tier("test-invite-2026")
        with pytest.raises(InviteTierNotConfirmed, match="allowed_categories"):
            eng.confirm_invite_tier("test-invite-2026")

    def test_invite_tier_refused_with_wrong_typed_engagement_id(self, tmp_path):
        eng = self._engagement(tmp_path)
        eng.confirm_active_tier("test-invite-2026")
        with pytest.raises(InviteTierNotConfirmed, match="does not match"):
            eng.confirm_invite_tier("wrong-id")

    def test_authorize_action_invite_category_gated_correctly(self, tmp_path):
        from voipaudit.core.engagement import ScopeViolation

        eng = self._engagement(tmp_path)
        with pytest.raises(ScopeViolation, match="invite-tier not confirmed"):
            eng.authorize_action("toll_fraud_exposure", "127.0.0.1", "sip_invite_probe", category="invite")

        eng.confirm_active_tier("test-invite-2026")
        eng.confirm_invite_tier("test-invite-2026")
        eng.authorize_action("toll_fraud_exposure", "127.0.0.1", "sip_invite_probe", category="invite")  # must not raise


class TestSafeInviteProbe:
    """Tested against a real dedicated mock INVITE responder over real
    UDP sockets, covering every response pattern safe_invite_probe
    needs to react to correctly."""

    def test_outright_rejection_not_flagged_as_routed_no_cancel_sent(self):
        server = start_mock_invite_responder(destination_behaviors={"reject1": "reject"})
        try:
            result = safe_invite_probe("127.0.0.1", server.port, "reject1", total_timeout=3.0)
            assert result.appears_routed is False
            assert result.rejected_outright is True
            assert result.final_status_code == 404
            assert result.cancelled is False
            time.sleep(0.3)
            assert "CANCEL" not in server.received_methods
        finally:
            server.stop()

    def test_ringing_then_silence_detected_as_routed_and_cancelled_immediately(self):
        server = start_mock_invite_responder(destination_behaviors={"ring1": "ring_then_silence"})
        try:
            start = time.monotonic()
            result = safe_invite_probe("127.0.0.1", server.port, "ring1", total_timeout=4.0)
            elapsed = time.monotonic() - start

            assert result.appears_routed is True
            assert result.cancelled is True
            # The whole point: must react immediately on seeing 180,
            # not wait anywhere near the full 4s timeout.
            assert elapsed < 1.0
            assert server.wait_for_methods(["INVITE", "CANCEL"], timeout=2.0)
        finally:
            server.stop()

    def test_immediate_answer_triggers_ack_then_bye(self):
        server = start_mock_invite_responder(destination_behaviors={"answer1": "answer"})
        try:
            result = safe_invite_probe("127.0.0.1", server.port, "answer1", total_timeout=3.0)
            assert result.appears_routed is True
            assert result.final_status_code == 200
            assert result.acked_and_byed is True
            assert server.wait_for_methods(["INVITE", "ACK", "BYE"], timeout=2.0)
        finally:
            server.stop()

    def test_trying_then_silence_waits_grace_period_then_cancels(self):
        server = start_mock_invite_responder(destination_behaviors={"trying1": "trying_then_silence"})
        try:
            start = time.monotonic()
            result = safe_invite_probe(
                "127.0.0.1", server.port, "trying1", total_timeout=4.0, grace_after_first_response=1.0,
            )
            elapsed = time.monotonic() - start

            # 100 Trying alone doesn't confirm routing -- but the probe
            # still cancels as a safety fallback after the grace period.
            assert result.appears_routed is False
            assert result.cancelled is True
            assert 0.9 < elapsed < 2.5  # roughly the grace period, not the full 4s timeout
        finally:
            server.stop()

    def test_total_silence_times_out_cleanly(self):
        import socket

        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(("127.0.0.1", 0))
        port = silent.getsockname()[1]
        try:
            start = time.monotonic()
            result = safe_invite_probe("127.0.0.1", port, "silent1", total_timeout=1.5)
            elapsed = time.monotonic() - start
            assert result.timed_out_with_no_response is True
            assert result.appears_routed is False
            assert 1.4 < elapsed < 2.5
        finally:
            silent.close()

    def test_multiple_destinations_against_same_running_responder_behave_independently(self):
        """Confirms the mock responder's per-destination behavior
        selection works correctly for a sequence of different probes
        against ONE running instance -- exactly what
        toll_fraud_exposure does across several destinations."""
        server = start_mock_invite_responder(destination_behaviors={
            "destA": "reject",
            "destB": "ring_then_silence",
            "destC": "answer",
        })
        try:
            r_a = safe_invite_probe("127.0.0.1", server.port, "destA", total_timeout=3.0)
            r_b = safe_invite_probe("127.0.0.1", server.port, "destB", total_timeout=3.0)
            r_c = safe_invite_probe("127.0.0.1", server.port, "destC", total_timeout=3.0)

            assert r_a.rejected_outright is True
            assert r_b.appears_routed is True and r_b.cancelled is True
            assert r_c.appears_routed is True and r_c.acked_and_byed is True
        finally:
            server.stop()


class TestTollFraudExposurePlugin:
    def _engagement(self, tmp_path) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        eng = Engagement.load(path, tmp_path / "test.audit.jsonl")
        eng.confirm_active_tier("test-invite-2026")
        eng.confirm_invite_tier("test-invite-2026")
        return eng

    def test_permissive_dialplan_flagged_critical(self, tmp_path):
        from voipaudit.analyzers.toll_fraud import HIGH_RISK_PREFIXES
        from voipaudit.plugins.toll_fraud_exposure import TollFraudExposureModule

        first_prefix = next(iter(HIGH_RISK_PREFIXES))
        server = start_mock_invite_responder(destination_behaviors={
            first_prefix + "5550100": "ring_then_silence",
        })
        try:
            eng = self._engagement(tmp_path)
            plugin = TollFraudExposureModule(eng, timeout=3.0, max_destinations=1)
            result = plugin.run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].severity.value == "CRITICAL"
            assert first_prefix in result.findings[0].title
        finally:
            server.stop()

    def test_restrictive_dialplan_reports_info_not_critical(self, tmp_path):
        from voipaudit.plugins.toll_fraud_exposure import TollFraudExposureModule

        # No destination_behaviors configured at all -- every destination
        # falls through to the mock's own safe default ('reject').
        server = start_mock_invite_responder()
        try:
            eng = self._engagement(tmp_path)
            plugin = TollFraudExposureModule(eng, timeout=3.0, max_destinations=2)
            result = plugin.run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert all(f.severity.value == "INFO" for f in result.findings)
        finally:
            server.stop()

    def test_respects_max_destinations_cap(self, tmp_path):
        from voipaudit.plugins.toll_fraud_exposure import TollFraudExposureModule

        server = start_mock_invite_responder()
        try:
            eng = self._engagement(tmp_path)
            plugin = TollFraudExposureModule(eng, timeout=2.0, max_destinations=2)
            result = plugin.run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert len(result.findings) == 2
        finally:
            server.stop()

    def test_out_of_scope_target_refused_before_any_invite_sent(self, tmp_path):
        from voipaudit.plugins.toll_fraud_exposure import TollFraudExposureModule

        eng = self._engagement(tmp_path)
        result = TollFraudExposureModule(eng, timeout=2.0, max_destinations=1).run("10.0.0.99:5060")
        assert result.error is not None
        assert "scope" in result.error.lower()

    def test_cannot_run_without_invite_tier_confirmed(self, tmp_path):
        """Confirms the plugin itself genuinely calls authorize_action
        with category='invite' -- not just that Engagement's gate
        works in isolation (already covered above)."""
        from voipaudit.plugins.toll_fraud_exposure import TollFraudExposureModule

        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        eng = Engagement.load(path, tmp_path / "test.audit.jsonl")
        # deliberately NOT confirming active or invite tier
        result = TollFraudExposureModule(eng, timeout=2.0, max_destinations=1).run("127.0.0.1:5060")
        assert result.error is not None
        assert "not confirmed" in result.error.lower()
