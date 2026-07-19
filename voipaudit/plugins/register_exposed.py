"""
Unauthenticated REGISTER exposure check.

Sends a real SIP REGISTER with no Authorization header and expires=0
(requesting immediate de-registration, so nothing persists even in the
worst case). A correctly configured PBX responds 401/407 with a
WWW-Authenticate/Proxy-Authenticate challenge (RFC 3261 §22.1). A PBX
that instead responds 200 OK is accepting an unauthenticated
registration — a real, exploitable misconfiguration (an attacker could
register an arbitrary extension and receive calls intended for it, or
use the PBX as a relay for toll fraud).

Deliberately classified as active-tier (category="active", requires
--confirm), not recon — unlike OPTIONS (explicitly side-effect-free
per the SIP spec), a REGISTER is real protocol traffic that a real
PBX's security monitoring (fail2ban-for-SIP, an SBC's own rate
limiting) can't distinguish from a genuine, malicious probing attempt.
Erring conservative here matches this whole portfolio's established
philosophy for anything beyond passive/side-effect-free observation.
"""

from __future__ import annotations

from typing import Any

from voipaudit.core.models import Finding, FindingCategory, Severity
from voipaudit.core.sip import SipTimeout, build_register_request, send_sip_request
from voipaudit.plugins.base import BasePlugin
from voipaudit.plugins.pbx_fingerprint import _split_host_port


class RegisterExposedModule(BasePlugin):
    name = "register_exposed"
    category = "active"

    def __init__(self, engagement, timeout: float = 3.0, transport: str = "udp", send_fn=None):
        super().__init__(engagement)
        self.timeout = timeout
        self.transport = transport
        self._send = send_fn or send_sip_request

    def scan(self, target: str, **kwargs: Any) -> list[Finding]:
        host, port = _split_host_port(target)
        self.engagement.authorize_action(self.name, host, "sip_register_probe", category=self.category)

        request = build_register_request(host, port, "0.0.0.0", 0, expires=0, transport=self.transport)
        try:
            response = self._send(request, host, port, timeout=self.timeout, transport=self.transport)
        except SipTimeout:
            return [Finding(
                module=self.name,
                title="No SIP response to REGISTER",
                severity=Severity.INFO,
                category=FindingCategory.ACTIVE,
                target=target,
                description=f"No SIP response from {host}:{port} over {self.transport.upper()} "
                             f"within {self.timeout}s.",
            )]

        if response.status_code == 200:
            return [Finding(
                module=self.name,
                title="Unauthenticated SIP REGISTER accepted",
                severity=Severity.CRITICAL,
                category=FindingCategory.ACTIVE,
                target=target,
                description=(
                    f"{host}:{port} accepted a REGISTER request with no Authorization "
                    f"header at all (SIP {response.status_code} {response.reason_phrase}). "
                    f"A correctly configured PBX should challenge this with 401/407."
                ),
                evidence=response.raw[:500],
                remediation=(
                    "Require digest authentication for all REGISTER requests. Verify no "
                    "extension/trunk is configured to allow unauthenticated registration, "
                    "and check for unexpected registrations already present on this PBX."
                ),
            )]

        if response.status_code in (401, 407):
            challenge = response.header("www-authenticate") or response.header("proxy-authenticate") or ""
            return [Finding(
                module=self.name,
                title="REGISTER correctly requires authentication",
                severity=Severity.INFO,
                category=FindingCategory.ACTIVE,
                target=target,
                description=f"{host}:{port} responded {response.status_code} "
                             f"{response.reason_phrase} with an authentication challenge, "
                             f"as expected.",
                evidence=challenge,
            )]

        return [Finding(
            module=self.name,
            title="Unexpected REGISTER response",
            severity=Severity.LOW,
            category=FindingCategory.ACTIVE,
            target=target,
            description=f"{host}:{port} responded {response.status_code} "
                         f"{response.reason_phrase} to an unauthenticated REGISTER — "
                         f"neither a clean accept nor a standard auth challenge. Worth "
                         f"manual review.",
            evidence=response.raw[:500],
        )]
