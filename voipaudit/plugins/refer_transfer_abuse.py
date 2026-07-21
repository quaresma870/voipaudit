"""
REFER-based call-transfer abuse check — invite tier (same 3-layer
confirmation as toll_fraud_exposure/srtp_check/caller_id_spoofing:
written acknowledgment, active-tier confirmed first, then invite-tier
confirmed).

Distinct from toll_fraud_exposure's own direct-INVITE-toward-a-
high-risk-destination question: some dialplans restrict outbound
dialing more tightly than call transfers, so a PBX that correctly
refuses a direct INVITE toward an external destination might still
honor an in-dialog REFER (RFC 3515) asking it to transfer an
established call elsewhere — a real, distinct toll-fraud vector
("transfer abuse") this module tests for specifically.

This is the first invite-tier plugin whose underlying probe
(core/invite_probe.py's safe_transfer_probe) lets a call actually
CONNECT rather than cancelling at the first routing-indicating
response — see that function's own docstring for the full safety
reasoning, most importantly why the REFER's Refer-To destination is,
by default, a hardcoded, synthetic, fictional extension
(REFER_TRANSFER_TEST_EXTENSION), never a real or caller-suppliable
one: once a target honors a REFER, this tool has no dialog with —
and therefore no way to cancel — whatever call the target itself
places as a result.

confirm_reachable (--confirm-transfer-reachable) switches Refer-To to
point at a small SIP UAS this tool runs itself instead
(core/transfer_confirm.py), so a real callback INVITE from the target
can be directly observed rather than inferred from signalling alone —
the difference between "the target accepted our REFER" (HIGH, this
module's own default outcome) and "the target actually placed a new
call to an arbitrary destination we named" (CRITICAL, direct proof).
"""

from __future__ import annotations

from typing import Any

from voipaudit.core.invite_probe import (
    REFER_TRANSFER_TEST_EXTENSION,
    InviteProbeError,
    safe_transfer_probe,
)
from voipaudit.core.models import Finding, FindingCategory, Severity
from voipaudit.core.transfer_confirm import detect_local_ip_for_target
from voipaudit.plugins.base import BasePlugin
from voipaudit.plugins.pbx_fingerprint import _split_host_port

_DEFAULT_TEST_USER = "voipaudit-transfer-test"


class ReferTransferAbuseModule(BasePlugin):
    name = "refer_transfer_abuse"
    category = "invite"

    def __init__(
        self, engagement, timeout: float = 4.0, to_user: str = _DEFAULT_TEST_USER,
        transport: str = "udp", tls_verify: bool = True, refer_wait_timeout: float = 2.0,
        confirm_reachable: bool = False, callback_host: str | None = None, callback_port: int = 0,
    ):
        super().__init__(engagement)
        self.timeout = timeout
        self.to_user = to_user
        self.transport = transport
        self.tls_verify = tls_verify
        self.refer_wait_timeout = refer_wait_timeout
        self.confirm_reachable = confirm_reachable
        self.callback_host = callback_host
        self.callback_port = callback_port

    def scan(self, target: str, **kwargs: Any) -> list[Finding]:
        host, port = _split_host_port(target)
        self.engagement.authorize_action(self.name, host, "sip_invite_refer_probe", category=self.category)

        kwargs_for_probe: dict[str, Any] = {}
        if self.confirm_reachable:
            # --callback-host overrides the auto-detected address --
            # required for NAT/firewalled setups where the local
            # outbound-routing IP isn't what the target can actually
            # reach back on.
            callback_host = self.callback_host or detect_local_ip_for_target(host, port)
            kwargs_for_probe["callback_host"] = callback_host
            kwargs_for_probe["callback_port"] = self.callback_port

        try:
            result = safe_transfer_probe(
                host, port, to_user=self.to_user, total_timeout=self.timeout, transport=self.transport,
                tls_verify=self.tls_verify, refer_wait_timeout=self.refer_wait_timeout, **kwargs_for_probe,
            )
        except InviteProbeError as exc:
            return [Finding(
                module=self.name, title="Could not probe call-transfer handling", severity=Severity.INFO,
                category=FindingCategory.INVITE, target=target, description=str(exc),
            )]

        return [self._finding_for_result(target, result)]

    def _finding_for_result(self, target: str, result) -> Finding:
        if not result.dialog_established:
            return Finding(
                module=self.name,
                title="Inconclusive — could not establish a call to test transfer against",
                severity=Severity.INFO,
                category=FindingCategory.INVITE,
                target=target,
                description=(
                    f"'{self.to_user}' never answered (rejected outright, silent, or only "
                    f"ringing-then-silence) — a REFER can only be tested within an already-answered "
                    f"call. Re-run with --to-user set to a known-valid, reachable extension that "
                    f"actually answers for a conclusive result."
                ),
            )

        if result.callback_confirmed:
            return Finding(
                module=self.name,
                title="Confirmed: target places a new call to an arbitrary destination via REFER",
                severity=Severity.CRITICAL,
                category=FindingCategory.INVITE,
                target=target,
                description=(
                    f"After an unauthenticated INVITE to '{self.to_user}' was answered, a REFER "
                    f"asking the target to transfer the call to an address this tool controls was "
                    f"directly confirmed: the target itself placed a real, observed callback INVITE "
                    f"there. This is DIRECT proof (not inferred from signalling) that an "
                    f"unauthenticated caller can make this PBX place a new call toward any "
                    f"destination of their choosing, with no apparent authorization check on who "
                    f"may direct a transfer."
                ),
                evidence=f"callback_from={result.callback_from!r}, "
                         f"callback_user_agent={result.callback_user_agent!r}",
                remediation="Restrict which calls/parties may issue a REFER the dialplan will honor "
                             "(e.g. require the referrer to be an authenticated internal extension), "
                             "or disable blind/unattended transfer initiation from untrusted sources. "
                             "Treat this as equivalent in severity to an accepted unauthenticated "
                             "INVITE toward an arbitrary destination.",
            )

        if result.refer_appears_honored:
            return Finding(
                module=self.name,
                title="Target appears to honor an unauthenticated call transfer (REFER)",
                severity=Severity.HIGH,
                category=FindingCategory.INVITE,
                target=target,
                description=(
                    f"After an unauthenticated INVITE to '{self.to_user}' was answered, a REFER "
                    f"requesting transfer to a synthetic test extension "
                    f"('{REFER_TRANSFER_TEST_EXTENSION}') received a final "
                    f"{result.refer_final_status_code or 'response'}"
                    + (f" and a NOTIFY reporting '{result.notify_sipfrag}'" if result.notify_sipfrag else "")
                    + " — the target's signalling indicates it accepted (and, per the NOTIFY, at "
                      "least attempted) the transfer with no apparent authorization check on who "
                      "may direct it. This tool only ever targets a synthetic, almost-certainly-"
                      "nonexistent extension, so this finding reflects protocol-level acceptance of "
                      "the REFER itself, not a confirmed real-destination transfer. Re-run with "
                      "--confirm-transfer-reachable for direct proof."
                ),
                evidence=f"refer_final_status_code={result.refer_final_status_code}, "
                         f"notify_sipfrag={result.notify_sipfrag!r}",
                remediation="Restrict which calls/parties may issue a REFER the dialplan will honor "
                             "(e.g. require the referrer to be an authenticated internal extension), "
                             "or disable blind/unattended transfer initiation from untrusted sources.",
            )

        return Finding(
            module=self.name,
            title="Call transfer (REFER) not honored",
            severity=Severity.INFO,
            category=FindingCategory.INVITE,
            target=target,
            description=(
                f"After an unauthenticated INVITE to '{self.to_user}' was answered, a REFER "
                f"requesting transfer to a synthetic test extension received "
                f"{'a ' + str(result.refer_final_status_code) + ' response' if result.refer_final_status_code else 'no response'} "
                f"with no indication of being honored — as expected for a properly restricted dialplan."
            ),
        )
