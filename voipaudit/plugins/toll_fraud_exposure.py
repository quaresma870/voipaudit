"""
Live toll-fraud exposure check — invite tier (requires --confirm twice:
active tier, then invite tier — see core/engagement.py).

Distinct from analyze-cdr/analyze-pcap (which detect fraud that may
have ALREADY happened, from historical call records): this checks
whether the PBX's CURRENT dialplan configuration would even ALLOW toll
fraud to happen, independent of whether it already has. Sends a real,
safety-bounded INVITE toward each of a small set of known high-risk
destination patterns (reusing analyzers/toll_fraud.py's own
HIGH_RISK_PREFIXES — the same sourcing and same explicit
non-exhaustiveness caveat apply here) and observes whether the
dialplan appears to ROUTE the call at all (180 Ringing, 183 Session
Progress, or an outright 2xx answer) versus rejecting it outright
(403/404/etc.) — never waiting for or allowing the call to actually
connect and run, using safe_invite_probe's immediate-CANCEL technique
(see core/invite_probe.py's own docstring for the full safety design).
"""

from __future__ import annotations

import time
from typing import Any

from voipaudit.analyzers.toll_fraud import HIGH_RISK_PREFIXES
from voipaudit.core.invite_probe import InviteProbeError, safe_invite_probe
from voipaudit.core.models import Finding, FindingCategory, Severity
from voipaudit.plugins.base import BasePlugin
from voipaudit.plugins.pbx_fingerprint import _split_host_port

# A clearly-synthetic trailing suffix appended to each tested prefix --
# evokes the NANP N11-555-0100 through 0199 range explicitly reserved
# for fictional/test use (not a real assignable subscriber number in
# that numbering plan), and reads as obviously-synthetic in any other
# numbering plan too (a real subscriber number essentially never has
# this exact repeating pattern) without claiming a formal reservation
# convention that doesn't universally apply outside NANP.
_TEST_NUMBER_SUFFIX = "5550100"

# A firm, mandatory pause between successive INVITE probes within a
# single run of this module -- independent of (and in addition to) the
# global rate budget every other plugin already shares, since a rapid
# sequence of real INVITEs is a materially more sensitive pattern than
# the same rate of OPTIONS/REGISTER probes would be.
_MIN_SECONDS_BETWEEN_PROBES = 2.0

# A hard ceiling on how many destinations this module will ever probe
# in one run, independent of how many entries HIGH_RISK_PREFIXES
# happens to contain -- a deliberate, small, fixed sample (not "test
# everything the analyzer knows about"), keeping the total number of
# real INVITEs sent bounded and predictable regardless of how that
# list grows over time.
_MAX_DESTINATIONS_PER_RUN = 5


class TollFraudExposureModule(BasePlugin):
    name = "toll_fraud_exposure"
    category = "invite"

    def __init__(
        self, engagement, timeout: float = 4.0, transport: str = "udp",
        max_destinations: int = _MAX_DESTINATIONS_PER_RUN,
    ):
        super().__init__(engagement)
        self.timeout = timeout
        self.transport = transport
        self.max_destinations = min(max_destinations, _MAX_DESTINATIONS_PER_RUN)

    def scan(self, target: str, **kwargs: Any) -> list[Finding]:
        host, port = _split_host_port(target)
        self.engagement.authorize_action(self.name, host, "sip_invite_probe", category=self.category)

        findings: list[Finding] = []
        prefixes_to_test = list(HIGH_RISK_PREFIXES.items())[: self.max_destinations]

        for i, (prefix, description) in enumerate(prefixes_to_test):
            if i > 0:
                time.sleep(_MIN_SECONDS_BETWEEN_PROBES)

            test_number = prefix + _TEST_NUMBER_SUFFIX
            try:
                result = safe_invite_probe(
                    host, port, to_user=test_number, total_timeout=self.timeout,
                )
            except InviteProbeError as exc:
                findings.append(Finding(
                    module=self.name,
                    title=f"Could not probe +{prefix}",
                    severity=Severity.INFO,
                    category=FindingCategory.INVITE,
                    target=target,
                    description=str(exc),
                ))
                continue

            findings.append(self._finding_for_result(target, prefix, description, result))

        return findings

    def _finding_for_result(self, target: str, prefix: str, description: str, result) -> Finding:
        if result.appears_routed:
            return Finding(
                module=self.name,
                title=f"Dialplan appears to route calls toward +{prefix} ({description})",
                severity=Severity.CRITICAL,
                category=FindingCategory.INVITE,
                target=target,
                description=(
                    f"A real INVITE toward +{prefix} received a routing-indicating response "
                    f"(180/183, or an outright answer) before being cancelled — the dialplan "
                    f"did not reject this destination outright. This means the PBX's current "
                    f"configuration would allow a call toward a known high-risk destination to "
                    f"proceed, independent of whether it already has (see analyze-cdr/"
                    f"analyze-pcap for detecting fraud that may have already happened)."
                ),
                evidence=f"response codes seen: {[r.status_code for r in result.responses_seen]}",
                remediation="Restrict outbound dialplan routing for this destination pattern "
                             "(allow-list specific extensions/destinations rather than blocking "
                             "specific ones), or confirm this routing is genuinely intentional.",
            )

        if result.rejected_outright:
            return Finding(
                module=self.name,
                title=f"Dialplan correctly rejects +{prefix} ({description})",
                severity=Severity.INFO,
                category=FindingCategory.INVITE,
                target=target,
                description=f"INVITE toward +{prefix} was rejected outright "
                             f"(SIP {result.final_status_code}) with no routing-indicating "
                             f"response ever seen — as expected for a properly restricted dialplan.",
            )

        return Finding(
            module=self.name,
            title=f"No conclusive response for +{prefix}",
            severity=Severity.INFO,
            category=FindingCategory.INVITE,
            target=target,
            description=f"No response, or an inconclusive one, was received for +{prefix} within "
                         f"the probe timeout — cannot determine dialplan behavior for this "
                         f"destination from this run.",
        )
