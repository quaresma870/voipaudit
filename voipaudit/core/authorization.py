"""
Authorization & scope — the single most important file in this toolkit.

Nothing in voipaudit runs against any target without a validated
authorization.yml. VoIP/PBX infrastructure is production telecom
equipment — an unauthorized REGISTER flood or spoofed INVITE against a
real PBX can cause real toll fraud exposure or service disruption, the
same category of real-world risk redteam-toolkit's own authorization
model exists to gate. This module is adapted directly from that
proven, already-audited pattern (see the sibling redteam-toolkit repo),
not reinvented — only the target-matching logic is SIP-specific.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml


class AuthorizationError(ValueError):
    """Raised when authorization.yml is missing, malformed, or invalid."""


@dataclass
class Scope:
    targets: list[str]
    excluded_targets: list[str] = field(default_factory=list)
    allowed_categories: list[str] = field(default_factory=list)


@dataclass
class Window:
    start: datetime
    end: datetime


@dataclass
class RateLimits:
    """Optional override of the global rate budget defaults. SIP scanning
    is easy to accidentally turn into a real REGISTER/OPTIONS flood
    against a production PBX — the default budget is deliberately
    conservative (see core/rate_limit.py)."""
    max_total_requests: int
    max_per_second: float


@dataclass
class Authorization:
    engagement_id: str
    authorized_by: str
    authorized_contact_email: str
    client: str
    scope: Scope
    window: Window
    confirmation_phrase: str
    rate_limits: RateLimits | None = None
    source_path: Path | None = None

    def is_within_window(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        return self.window.start <= now <= self.window.end

    def is_in_scope(self, target: str) -> bool:
        """CIDR/IP and wildcard-domain matching, applied to the host
        part of a SIP target (an IP, hostname, or a 'host:port'/'sip:
        user@host:port' string — the host is extracted before matching).
        Exclusions always win, even if a target also matches an
        inclusion pattern."""
        host = _extract_host(target)
        for excl in self.scope.excluded_targets:
            if _matches(host, _extract_host(excl)):
                return False
        return any(_matches(host, _extract_host(inc)) for inc in self.scope.targets)

    def allows_category(self, category: str) -> bool:
        return category in self.scope.allowed_categories


def _extract_host(target: str) -> str:
    """Strips a 'sip:'/'sips:' scheme, a 'user@' part, and a trailing
    ':port', leaving just the bare host/IP for scope matching —
    confirmed this is the right granularity to scope on (not
    port-specific) since the same PBX is commonly reachable on more
    than one port/transport (5060/udp, 5061/tls) and scoping per-port
    would require listing every combination in authorization.yml for
    no real safety benefit."""
    t = target.strip()
    for scheme in ("sips:", "sip:"):
        if t.lower().startswith(scheme):
            t = t[len(scheme):]
            break
    if "@" in t:
        t = t.split("@", 1)[1]
    # IPv6 literal in brackets, e.g. [::1]:5060 — keep the brackets off
    # for ip_address() parsing but don't treat the trailing :NNNN as
    # part of an IPv6 address itself.
    if t.startswith("["):
        end = t.find("]")
        if end != -1:
            return t[1:end]
    if t.count(":") == 1:
        host, _, maybe_port = t.rpartition(":")
        if maybe_port.isdigit():
            return host
    return t


def _matches(target_host: str, pattern_host: str) -> bool:
    """Match a bare host/IP against a scope pattern: CIDR/IP network
    first, then wildcard domain ('*.example.com'), then exact string
    match."""
    try:
        network = ipaddress.ip_network(pattern_host, strict=False)
        try:
            return ipaddress.ip_address(target_host) in network
        except ValueError:
            pass
    except ValueError:
        pass

    if pattern_host.startswith("*."):
        suffix = pattern_host[1:]
        bare = pattern_host[2:]
        return target_host == bare or target_host.endswith(suffix)

    return target_host == pattern_host


_REQUIRED_FIELDS = (
    "engagement_id", "authorized_by", "authorized_contact_email",
    "client", "scope", "window", "confirmation_phrase",
)


def load_authorization(path: str | Path) -> Authorization:
    """Parse and fully validate an authorization.yml. Raises
    AuthorizationError with a specific, actionable message on any
    problem — never silently accepts a partially-valid file."""
    path = Path(path)
    if not path.exists():
        raise AuthorizationError(f"Authorization file not found: {path}")

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise AuthorizationError(f"Authorization file is not valid YAML: {exc}") from exc

    if not isinstance(data, dict):
        raise AuthorizationError("Authorization file must be a YAML mapping at the top level.")

    missing = [f for f in _REQUIRED_FIELDS if not data.get(f)]
    if missing:
        raise AuthorizationError(
            f"Authorization file is missing or has an empty required field: {', '.join(missing)}"
        )

    scope_data = data["scope"]
    if not isinstance(scope_data, dict) or not scope_data.get("targets"):
        raise AuthorizationError(
            "'scope.targets' must be a non-empty list — define at least one authorized target."
        )

    window_data = data["window"]
    if not isinstance(window_data, dict) or not window_data.get("start") or not window_data.get("end"):
        raise AuthorizationError("'window' must include both a non-empty 'start' and 'end' timestamp.")

    try:
        start = _parse_datetime(window_data["start"])
        end = _parse_datetime(window_data["end"])
    except (ValueError, TypeError) as exc:
        raise AuthorizationError(f"'window' timestamps must be ISO 8601: {exc}") from exc

    if end <= start:
        raise AuthorizationError("'window.end' must be after 'window.start'.")

    scope = Scope(
        targets=list(scope_data["targets"]),
        excluded_targets=list(scope_data.get("excluded_targets") or []),
        allowed_categories=list(scope_data.get("allowed_categories") or []),
    )

    rate_limits = None
    rate_data = data.get("rate_limits")
    if rate_data:
        if not isinstance(rate_data, dict):
            raise AuthorizationError("'rate_limits' must be a mapping with 'max_total_requests'/'max_per_second'.")
        try:
            rate_limits = RateLimits(
                max_total_requests=int(rate_data["max_total_requests"]),
                max_per_second=float(rate_data["max_per_second"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorizationError(
                f"'rate_limits' must include numeric 'max_total_requests' and 'max_per_second': {exc}"
            ) from exc

    return Authorization(
        engagement_id=str(data["engagement_id"]),
        authorized_by=str(data["authorized_by"]),
        authorized_contact_email=str(data["authorized_contact_email"]),
        client=str(data["client"]),
        scope=scope,
        window=Window(start=start, end=end),
        confirmation_phrase=str(data["confirmation_phrase"]),
        rate_limits=rate_limits,
        source_path=path,
    )


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    s = str(value)
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
