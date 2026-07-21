"""
Caller-ID / From-header spoofing check — invite tier (same 3-layer
confirmation as toll_fraud_exposure/srtp_check: written acknowledgment,
active-tier confirmed first, then invite-tier confirmed).

The core design challenge, and why this ISN'T simply "send an INVITE
with a fake From and see if it routes": a SIP dialplan's routing
decision is normally keyed on the REQUEST-URI (the destination), not
the From header — a correctly-functioning, perfectly safe PBX will
almost always route a call identically regardless of what the caller
claims to be. Treating "routes the same either way" as a vulnerability
finding would be a false positive against the overwhelming majority of
real deployments, not a real signal.

Instead, like srtp_check, this is a DIFFERENTIAL test: it sends a
"baseline" INVITE (a plain, external-looking identity) and a "spoofed"
INVITE to the SAME destination claiming to be a specific OTHER identity
(by default, the destination extension itself — "the callee calling
itself", a pattern with no legitimate explanation and a hallmark of
CLI-spoofing/vishing testing; --spoof-from lets an engagement target a
genuinely known-trusted internal identity instead, e.g. a reception or
executive extension) — both via the From header AND via
P-Asserted-Identity (RFC 3325's trusted-identity mechanism, which an
untrusted, unauthenticated party should never be able to successfully
self-assert). If the target's SIGNALLING-level treatment (final status
code, whether it routes, whether it demands authentication) differs
between the two, that's real evidence of identity-aware handling. If it
DOESN'T differ, that's genuine — if modest — evidence that nothing at
the SIP layer distinguishes a spoofed identity from a legitimate one,
reported as MEDIUM rather than an overclaimed CRITICAL/HIGH, since this
alone doesn't prove a downstream system (e.g. what's ultimately
displayed to a callee) treats the identities differently either.
"""

from __future__ import annotations

import time
from typing import Any

from voipaudit.core.invite_probe import InviteProbeError, safe_invite_probe
from voipaudit.core.models import Finding, FindingCategory, Severity
from voipaudit.plugins.base import BasePlugin
from voipaudit.plugins.pbx_fingerprint import _split_host_port

# Same reasoning as srtp_check's own pacing: a firm, mandatory pause
# between the two real INVITEs this module sends, independent of the
# shared global rate budget every other plugin uses.
_SECONDS_BETWEEN_PROBES = 2.0

_DEFAULT_TEST_USER = "voipaudit-spoof-test"
_BASELINE_FROM_USER = "voipaudit-probe"


class CallerIDSpoofingModule(BasePlugin):
    name = "caller_id_spoofing"
    category = "invite"

    def __init__(
        self, engagement, timeout: float = 4.0, to_user: str = _DEFAULT_TEST_USER,
        transport: str = "udp", tls_verify: bool = True, spoof_from: str | None = None,
    ):
        super().__init__(engagement)
        self.timeout = timeout
        self.to_user = to_user
        self.transport = transport
        self.tls_verify = tls_verify
        # Defaults to "the destination calling itself" when not given —
        # a self-contained baseline that needs no prior knowledge of
        # the target's numbering plan, and has no legitimate
        # explanation for a real call.
        self.spoof_from = spoof_from or to_user

    def scan(self, target: str, **kwargs: Any) -> list[Finding]:
        host, port = _split_host_port(target)
        self.engagement.authorize_action(self.name, host, "sip_invite_spoofing_probe", category=self.category)

        try:
            baseline = safe_invite_probe(
                host, port, to_user=self.to_user, from_user=_BASELINE_FROM_USER,
                total_timeout=self.timeout, transport=self.transport, tls_verify=self.tls_verify,
            )
        except InviteProbeError as exc:
            return [Finding(
                module=self.name, title="Could not probe baseline identity", severity=Severity.INFO,
                category=FindingCategory.INVITE, target=target, description=str(exc),
            )]

        time.sleep(_SECONDS_BETWEEN_PROBES)

        try:
            spoofed = safe_invite_probe(
                host, port, to_user=self.to_user, from_user=self.spoof_from,
                total_timeout=self.timeout, transport=self.transport, tls_verify=self.tls_verify,
                p_asserted_identity=self.spoof_from,
            )
        except InviteProbeError as exc:
            return [Finding(
                module=self.name, title="Could not probe spoofed identity", severity=Severity.INFO,
                category=FindingCategory.INVITE, target=target, description=str(exc),
            )]

        return [self._finding_for_results(target, baseline, spoofed)]

    def _finding_for_results(self, target: str, baseline, spoofed) -> Finding:
        if not baseline.appears_routed and not spoofed.appears_routed:
            return Finding(
                module=self.name,
                title="Inconclusive — destination did not route with either identity",
                severity=Severity.INFO,
                category=FindingCategory.INVITE,
                target=target,
                description=(
                    f"Neither the baseline nor the spoofed-identity ('{self.spoof_from}') INVITE "
                    f"toward '{self.to_user}' was routed — likely means this specific destination "
                    f"doesn't exist/route on this PBX, not that identity spoofing is accepted or "
                    f"rejected. Re-run with --to-user set to a known-valid, reachable extension for "
                    f"a conclusive result."
                ),
            )

        same_outcome = (
            baseline.appears_routed == spoofed.appears_routed
            and baseline.final_status_code == spoofed.final_status_code
        )

        if same_outcome:
            return Finding(
                module=self.name,
                title="No Caller-ID/From-header differentiation observed",
                severity=Severity.MEDIUM,
                category=FindingCategory.INVITE,
                target=target,
                description=(
                    f"An INVITE toward '{self.to_user}' claiming to be '{self.spoof_from}' "
                    f"(via both From and P-Asserted-Identity) received IDENTICAL signalling-level "
                    f"treatment to a plain baseline identity (routed: {spoofed.appears_routed}, "
                    f"status: {spoofed.final_status_code}) — nothing at the SIP layer distinguished "
                    f"the spoofed identity from a legitimate one. This does not by itself prove a "
                    f"downstream system displays or trusts the spoofed identity, but shows no "
                    f"protocol-level authorization check rejected it either."
                ),
                evidence=(
                    f"baseline: routed={baseline.appears_routed} status={baseline.final_status_code}; "
                    f"spoofed: routed={spoofed.appears_routed} status={spoofed.final_status_code}"
                ),
                remediation="If Caller-ID/identity assertions should be restricted to authenticated or "
                             "trusted sources, enforce this at the SBC/PBX (e.g. strip/ignore a "
                             "self-supplied P-Asserted-Identity from untrusted peers per RFC 3325, "
                             "and validate From-header identities against the authenticated source).",
            )

        return Finding(
            module=self.name,
            title="Spoofed identity handled differently from baseline (identity checks appear present)",
            severity=Severity.INFO,
            category=FindingCategory.INVITE,
            target=target,
            description=(
                f"An INVITE toward '{self.to_user}' claiming to be '{self.spoof_from}' was treated "
                f"differently (routed={spoofed.appears_routed}, status={spoofed.final_status_code}) "
                f"than the plain baseline (routed={baseline.appears_routed}, "
                f"status={baseline.final_status_code}) — evidence the target distinguishes this "
                f"identity from an ordinary one, as expected for a properly restricted dialplan."
            ),
            evidence=(
                f"baseline: routed={baseline.appears_routed} status={baseline.final_status_code}; "
                f"spoofed: routed={spoofed.appears_routed} status={spoofed.final_status_code}"
            ),
        )
