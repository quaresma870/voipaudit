"""
PBX fingerprinting — sends a single SIP OPTIONS request (RFC 3261 §11,
no dialog created, no side effects) and matches the response's
Server/User-Agent header against known PBX/SIP-stack signatures.

This is deliberately the recon-tier, lowest-risk plugin in this
toolkit — OPTIONS is specifically designed by the SIP spec as a
capability query with no session side effects, unlike REGISTER
(creates/refreshes a binding) or INVITE (attempts to establish a real
call). category="recon", no --confirm required.
"""

from __future__ import annotations

from typing import Any

from voipaudit.core.models import Finding, FindingCategory, Severity
from voipaudit.core.sip import SipTimeout, build_options_request, send_sip_request
from voipaudit.plugins.base import BasePlugin

# Known SIP Server/User-Agent header signatures. Deliberately matched
# via substring (case-insensitive) rather than exact string, since real
# deployments commonly append site-specific suffixes or version
# details to the base product string (e.g. "FreePBX-16.0" vs a bare
# "FreePBX").
_KNOWN_SIGNATURES: list[tuple[str, str]] = [
    ("asterisk", "Asterisk PBX"),
    ("freepbx", "FreePBX (Asterisk-based)"),
    ("3cx", "3CX Phone System"),
    ("freeswitch", "FreeSWITCH"),
    ("kamailio", "Kamailio SIP Server"),
    ("opensips", "OpenSIPS"),
    ("cisco-sipgateway", "Cisco SIP Gateway/CallManager"),
    ("grandstream", "Grandstream device/PBX"),
    ("yealink", "Yealink device"),
    ("sangoma", "Sangoma PBX/gateway"),
    ("avaya", "Avaya SIP platform"),
]


class PBXFingerprintModule(BasePlugin):
    name = "pbx_fingerprint"
    category = "recon"

    def __init__(
        self, engagement, timeout: float = 3.0, transport: str = "udp",
        tls_verify: bool = True, send_fn=None,
    ):
        super().__init__(engagement)
        self.timeout = timeout
        self.transport = transport
        self.tls_verify = tls_verify
        # send_fn is injectable purely for fast, deterministic unit
        # tests that don't want a real UDP/TCP round trip for every
        # single test case — every test that verifies the plugin's
        # real network behavior end-to-end still goes through the real
        # send_sip_request against tests/fixtures/mock_pbx, matching
        # this portfolio's established injectable-function-for-speed,
        # real-target-for-integration pattern.
        self._send = send_fn or send_sip_request

    def scan(self, target: str, **kwargs: Any) -> list[Finding]:
        host, port = _split_host_port(target)
        self.engagement.authorize_action(self.name, host, "sip_options_ping", category=self.category)

        request = build_options_request(host, port, "0.0.0.0", 0, transport=self.transport)
        try:
            response = self._send(
                request, host, port, timeout=self.timeout, transport=self.transport,
                tls_verify=self.tls_verify,
            )
        except SipTimeout:
            return [Finding(
                module=self.name,
                title="No SIP response",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description=f"No SIP response from {host}:{port} over {self.transport.upper()} "
                            f"within {self.timeout}s — closed, filtered, or not a SIP endpoint "
                            f"on this transport.",
            )]

        server_header = response.header("server") or response.header("user-agent")
        if not server_header:
            return [Finding(
                module=self.name,
                title="SIP endpoint responds but does not identify itself",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description=f"Got a SIP {response.status_code} {response.reason_phrase} response "
                             f"with no Server or User-Agent header.",
            )]

        matched_product = None
        lower = server_header.lower()
        for needle, product in _KNOWN_SIGNATURES:
            if needle in lower:
                matched_product = product
                break

        if matched_product:
            return [Finding(
                module=self.name,
                title=f"PBX/SIP stack identified: {matched_product}",
                severity=Severity.INFO,
                category=FindingCategory.RECON,
                target=target,
                description=f"OPTIONS response revealed: {server_header!r}",
                evidence=server_header,
                remediation="Consider suppressing or genericizing the Server/User-Agent header "
                             "if this exposure isn't intentional — a precise version string makes "
                             "targeted CVE lookups trivial for an attacker.",
            )]

        return [Finding(
            module=self.name,
            title="SIP endpoint identified (unrecognized product)",
            severity=Severity.INFO,
            category=FindingCategory.RECON,
            target=target,
            description=f"OPTIONS response revealed an unrecognized Server/User-Agent string: "
                         f"{server_header!r}",
            evidence=server_header,
        )]


def _split_host_port(target: str) -> tuple[str, int]:
    """Splits a 'host:port' or bare 'host' target string, defaulting
    to the standard SIP UDP port 5060 (RFC 3261 §18.1) when no port is
    given."""
    t = target.strip()
    for scheme in ("sips:", "sip:"):
        if t.lower().startswith(scheme):
            t = t[len(scheme):]
            break
    if t.startswith("["):  # IPv6 literal, e.g. [::1]:5060
        end = t.find("]")
        if end != -1:
            host = t[1:end]
            rest = t[end + 1:]
            port = int(rest[1:]) if rest.startswith(":") else 5060
            return host, port
    if ":" in t:
        host, _, port_str = t.rpartition(":")
        if port_str.isdigit():
            return host, int(port_str)
    return t, 5060
