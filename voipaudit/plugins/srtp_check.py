"""
SRTP media encryption check — invite tier (same 3-layer confirmation
as toll_fraud_exposure: written acknowledgment, active-tier confirmed
first, then invite-tier confirmed).

transport_security already covers *signalling* encryption (TLS/SIPS).
Media (RTP) encryption is a separate concern this module checks: does
the target actually negotiate SRTP (RTP/SAVP, RFC 3711) when offered,
or does it only ever support plaintext RTP?

The core design challenge: a rejected SRTP-only offer could mean
either "this target doesn't support SRTP" or "this destination doesn't
exist/route at all" — indistinguishable from a single probe alone.
This module uses a DIFFERENTIAL test to tell them apart: it sends both
an SRTP-only offer AND a plain-RTP-only offer to the SAME destination,
and compares outcomes. If plain RTP routes successfully but SRTP is
specifically rejected, that's real, defensible evidence about media
capability, not destination reachability — independent of whether the
tested destination is a "real" extension or a generic placeholder.
Results are still strongest against a genuinely valid, reachable
destination, but this differential design produces meaningful findings
even without prior knowledge of one.
"""

from __future__ import annotations

import time
from typing import Any

from voipaudit.core.invite_probe import InviteProbeError, safe_invite_probe
from voipaudit.core.models import Finding, FindingCategory, Severity
from voipaudit.core.sdp import build_audio_offer_sdp
from voipaudit.plugins.base import BasePlugin
from voipaudit.plugins.pbx_fingerprint import _split_host_port

# Same reasoning as toll_fraud_exposure's own probe pacing: a firm,
# mandatory pause between the two real INVITEs this module sends,
# independent of the shared global rate budget.
_SECONDS_BETWEEN_PROBES = 2.0

_DEFAULT_TEST_USER = "voipaudit-srtp-test"


class SRTPCheckModule(BasePlugin):
    name = "srtp_check"
    category = "invite"

    def __init__(self, engagement, timeout: float = 4.0, to_user: str = _DEFAULT_TEST_USER):
        super().__init__(engagement)
        self.timeout = timeout
        self.to_user = to_user

    def scan(self, target: str, **kwargs: Any) -> list[Finding]:
        host, port = _split_host_port(target)
        self.engagement.authorize_action(self.name, host, "sip_invite_srtp_probe", category=self.category)

        srtp_offer = build_audio_offer_sdp(host, 10000, transport="RTP/SAVP")
        try:
            srtp_result = safe_invite_probe(
                host, port, to_user=self.to_user, total_timeout=self.timeout, sdp_offer=srtp_offer,
            )
        except InviteProbeError as exc:
            return [Finding(
                module=self.name, title="Could not probe SRTP support", severity=Severity.INFO,
                category=FindingCategory.INVITE, target=target, description=str(exc),
            )]

        time.sleep(_SECONDS_BETWEEN_PROBES)

        plain_offer = build_audio_offer_sdp(host, 10000, transport="RTP/AVP")
        try:
            plain_result = safe_invite_probe(
                host, port, to_user=self.to_user, total_timeout=self.timeout, sdp_offer=plain_offer,
            )
        except InviteProbeError as exc:
            return [Finding(
                module=self.name, title="Could not probe plain-RTP baseline", severity=Severity.INFO,
                category=FindingCategory.INVITE, target=target, description=str(exc),
            )]

        srtp_negotiated = bool(srtp_result.answer_sdp and srtp_result.answer_sdp.is_srtp)
        srtp_routed = srtp_result.appears_routed
        plain_routed = plain_result.appears_routed

        if not plain_routed:
            return [Finding(
                module=self.name,
                title="Inconclusive — destination did not route with either offer",
                severity=Severity.INFO,
                category=FindingCategory.INVITE,
                target=target,
                description=(
                    f"Neither the SRTP-only nor the plain-RTP-only offer toward "
                    f"'{self.to_user}' was routed — likely means this specific destination "
                    f"doesn't exist/route on this PBX, not that SRTP is unsupported. Re-run "
                    f"with --to-user set to a known-valid, reachable extension for a "
                    f"conclusive result."
                ),
            )]

        if srtp_routed and srtp_negotiated:
            return [Finding(
                module=self.name,
                title="SRTP is supported",
                severity=Severity.INFO,
                category=FindingCategory.INVITE,
                target=target,
                description="The SRTP-only offer was routed and answered with a matching "
                             "RTP/SAVP + crypto attribute — SRTP is genuinely negotiated, "
                             "not just plain RTP with SDP that happens to look similar.",
                evidence=f"crypto suites: {srtp_result.answer_sdp.crypto_suites_offered}",
            )]

        # Plain RTP routes, but the SRTP-only offer specifically didn't
        # (rejected outright, or "routed" without ever actually
        # negotiating SRTP in the answer) -- the differential signal
        # this whole design exists to produce.
        return [Finding(
            module=self.name,
            title="SRTP not supported (plain RTP works, SRTP-only offer does not)",
            severity=Severity.MEDIUM,
            category=FindingCategory.INVITE,
            target=target,
            description=(
                f"A plain-RTP-only offer toward '{self.to_user}' routed successfully "
                f"(SIP {plain_result.final_status_code or 'provisional response'}), but an "
                f"otherwise-identical SRTP-only offer to the SAME destination did not "
                f"negotiate SRTP (SIP {srtp_result.final_status_code or 'no final response'}). "
                f"Since the plain-RTP offer to the same destination succeeded, this reflects "
                f"a real media-capability gap, not an unreachable destination."
            ),
            remediation="If confidentiality of call audio matters for this deployment, enable "
                         "SRTP support on the PBX/SBC's media handling configuration.",
        )]
