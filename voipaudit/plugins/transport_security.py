"""
Transport security — checks whether SIP signalling is available (and
enforced) over TLS, and reports certificate health when it is.

Three things this checks, each with a real, distinct security
implication:

1. Is TLS (SIPS) offered at all? If not, signalling is unencrypted on
   the wire unless something else (a VPN, an IPsec tunnel) protects it
   — a real, if often deliberately-accepted, exposure for internal
   deployments.
2. If TLS is offered, is the certificate expired or expiring soon? An
   expired cert doesn't stop SIP traffic from flowing (most SIP
   clients/trunks either don't verify at all, or degrade to a warning
   rather than refusing calls) — meaning "the cert expired" quietly
   becomes "nobody is actually verifying anything," a worse state
   than not having TLS configured at all in some respects.
3. If TLS is offered, is plaintext SIP (UDP/TCP on the standard port)
   ALSO still accepted on the same host? If so, TLS isn't actually
   *enforced* — an attacker (or a misconfigured client) can simply use
   the unencrypted path instead, and the presence of TLS alone doesn't
   protect anything against that.

Deliberately recon-tier (category="recon", no --confirm needed): every
check here is a side-effect-free OPTIONS ping, the same low-risk probe
pbx_fingerprint already uses, just repeated across transports rather
than active protocol manipulation.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from voipaudit.core.models import Finding, FindingCategory, Severity
from voipaudit.core.sip import SipTimeout, build_options_request, send_sip_request
from voipaudit.plugins.base import BasePlugin
from voipaudit.plugins.pbx_fingerprint import _split_host_port

_CERT_EXPIRY_WARNING_DAYS = 30


class TransportSecurityModule(BasePlugin):
    name = "transport_security"
    category = "recon"

    def __init__(
        self, engagement, timeout: float = 3.0,
        tls_port: int = 5061, plaintext_port: int = 5060,
        tls_verify: bool = False, send_fn=None,
    ):
        super().__init__(engagement)
        self.timeout = timeout
        # Deliberately always default to the standard SIP ports (RFC
        # 3261 §18.1: 5060 plaintext, 5061 TLS/SIPS) rather than trying
        # to infer them from whatever port happens to be in a scanned
        # target string. Confirmed the earlier "infer from the given
        # port" approach was a real bug, not just inelegant: when a
        # target's port was neither exactly 5060 nor 5061 (true for
        # every ephemeral test port, and common in real deployments
        # with non-default port assignments), both tls_port and
        # plaintext_port fell back to the SAME given port — meaning a
        # plaintext OPTIONS request got sent to a TLS-only listener,
        # producing a real connection-reset error, reproduced via the
        # actual installed CLI before fixing it. A single "target"
        # string can't unambiguously specify two different ports
        # anyway, so tls_port/plaintext_port are independent knobs
        # here, not derived from the scanned target at all.
        self.tls_port = tls_port
        self.plaintext_port = plaintext_port
        # tls_verify defaults to False here specifically (unlike
        # send_sip_request's own default of True): this plugin's whole
        # point is to inspect whatever certificate a target presents,
        # including a self-signed or expired one — refusing to even
        # connect to such a target by default would make the plugin
        # unable to report on exactly the misconfigurations it exists
        # to find.
        self.tls_verify = tls_verify
        self._send = send_fn or send_sip_request

    def scan(self, target: str, **kwargs: Any) -> list[Finding]:
        # The port in the target string is deliberately ignored here —
        # see the __init__ docstring-comment above for why tls_port/
        # plaintext_port are independent, explicit knobs instead.
        host, _given_port = _split_host_port(target)
        tls_port = self.tls_port
        plaintext_port = self.plaintext_port

        self.engagement.authorize_action(self.name, host, "sip_transport_security_probe", category=self.category)

        findings: list[Finding] = []
        tls_response = None
        try:
            request = build_options_request(host, tls_port, "0.0.0.0", 0, transport="tls")
            tls_response = self._send(
                request, host, tls_port, timeout=self.timeout, transport="tls", tls_verify=self.tls_verify,
            )
        except SipTimeout:
            findings.append(Finding(
                module=self.name,
                title="TLS (SIPS) not offered",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description=f"No SIP response from {host}:{tls_port} over TLS within "
                             f"{self.timeout}s — signalling is unencrypted on the wire unless "
                             f"something else (VPN, IPsec) protects it.",
            ))

        if tls_response is not None:
            findings.extend(self._certificate_findings(target, host, tls_port, tls_response))

        if tls_response is not None:
            findings.extend(self._plaintext_still_accepted_findings(target, host, plaintext_port))

        return findings

    def _certificate_findings(self, target: str, host: str, tls_port: int, tls_response) -> list[Finding]:
        info = tls_response.tls_info or {}
        out = [Finding(
            module=self.name,
            title=f"TLS offered: {info.get('protocol_version', 'unknown version')}",
            severity=Severity.INFO,
            category=FindingCategory.RECON,
            target=target,
            description=f"{host}:{tls_port} accepted a TLS connection "
                         f"({info.get('protocol_version')}, cipher {info.get('cipher', (None,))[0]}).",
        )]

        not_after = info.get("not_after")
        if not not_after:
            # Either no certificate details were retrievable (verification
            # was off AND the target's cert chain couldn't be decoded
            # without it), or the connection didn't actually present one
            # in a way Python's ssl module could parse — worth a flag on
            # its own, distinct from "cert is fine."
            if not info.get("certificate_present"):
                out.append(Finding(
                    module=self.name,
                    title="TLS offered but no certificate details retrievable",
                    severity=Severity.LOW,
                    category=FindingCategory.RECON,
                    target=target,
                    description=f"{host}:{tls_port} completed a TLS handshake but this probe "
                                 f"couldn't retrieve certificate details to check expiry.",
                ))
            return out

        try:
            expiry = datetime.fromisoformat(not_after)
        except ValueError:
            out.append(Finding(
                module=self.name,
                title="Certificate expiry date in an unrecognized format",
                severity=Severity.LOW,
                category=FindingCategory.RECON,
                target=target,
                description=f"Got not_after={not_after!r}, which didn't parse as an ISO 8601 date.",
            ))
            return out

        days_left = (expiry - datetime.now(UTC)).days
        if days_left < 0:
            out.append(Finding(
                module=self.name,
                title="TLS certificate has expired",
                severity=Severity.CRITICAL,
                category=FindingCategory.RECON,
                target=target,
                description=f"{host}:{tls_port}'s certificate expired {-days_left} day(s) ago "
                             f"({not_after}). An expired certificate doesn't stop SIP traffic from "
                             f"flowing for most clients/trunks — it quietly means nobody is "
                             f"actually verifying the connection anymore.",
                evidence=f"not_after={not_after}",
                remediation="Renew the certificate. Audit whether any client/trunk connecting to "
                             "this endpoint has been silently accepting it unverified.",
            ))
        elif days_left <= _CERT_EXPIRY_WARNING_DAYS:
            out.append(Finding(
                module=self.name,
                title="TLS certificate expiring soon",
                severity=Severity.MEDIUM,
                category=FindingCategory.RECON,
                target=target,
                description=f"{host}:{tls_port}'s certificate expires in {days_left} day(s) "
                             f"({not_after}).",
                evidence=f"not_after={not_after}",
            ))
        else:
            out.append(Finding(
                module=self.name,
                title="TLS certificate validity OK",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description=f"{host}:{tls_port}'s certificate is valid for {days_left} more day(s).",
            ))
        return out

    def _plaintext_still_accepted_findings(self, target: str, host: str, plaintext_port: int) -> list[Finding]:
        for transport in ("udp", "tcp"):
            try:
                request = build_options_request(host, plaintext_port, "0.0.0.0", 0, transport=transport)
                self._send(request, host, plaintext_port, timeout=self.timeout, transport=transport)
            except SipTimeout:
                continue
            return [Finding(
                module=self.name,
                title=f"Plaintext SIP still accepted alongside TLS ({transport.upper()})",
                severity=Severity.MEDIUM,
                category=FindingCategory.RECON,
                target=target,
                description=f"{host}:{plaintext_port} accepted an unencrypted {transport.upper()} "
                             f"OPTIONS request even though TLS is also offered — TLS isn't actually "
                             f"*enforced*, so an attacker (or a misconfigured client) can simply use "
                             f"the unencrypted path instead.",
                remediation="If encrypted-only signalling is the intent, disable the plaintext "
                             "UDP/TCP listener (or restrict it to a trusted internal network only) "
                             "rather than leaving both available on the public interface.",
            )]
        return [Finding(
            module=self.name,
            title="Plaintext SIP not accepted (TLS appears enforced)",
            severity=Severity.INFO,
            category=FindingCategory.RECON,
            target=target,
            description=f"{host}:{plaintext_port} did not respond over plaintext UDP or TCP.",
        )]
