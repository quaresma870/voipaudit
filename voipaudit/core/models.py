"""
Core data models — mirrors the clean dataclass pattern used throughout this
portfolio's other tools (secureaudit, redteam-toolkit), adapted for
SIP/VoIP-scoped auditing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(StrEnum):
    RECON = "recon"      # fingerprinting, OPTIONS ping, passive/low-risk protocol probing
    ACTIVE = "active"     # REGISTER/INVITE spoofing tests, flood-adjacent probing — requires --confirm


@dataclass
class Finding:
    module: str
    title: str
    severity: Severity
    category: FindingCategory
    target: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "target": self.target,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "extra": self.extra,
        }


@dataclass
class ModuleResult:
    module: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    duration_ms: float = 0.0

    @property
    def passed(self) -> bool:
        return self.error is None and not any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings
        )
