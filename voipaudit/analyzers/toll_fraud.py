"""
Toll fraud pattern detection over parsed CDR records.

This is deliberately a file-analysis feature, not a live network probe
— it takes a CDR export as input and looks for patterns indicative of
fraud that may have already occurred, which is a fundamentally
different question from "is this PBX currently exposed to fraud"
(that's the live `register_exposed`/future live-exposure-check
territory — see ROADMAP.md for why these were split into two separate
features). No Authorization/Engagement gate is used here: there's no
live target being touched, just a file already in the user's
possession.

Three detection rules, each with a real, documented basis:

1. Calls to known high-risk international destinations (IRSF/Wangiri
   targets) — see HIGH_RISK_PREFIXES below for sourcing. Importantly:
   this list is NOT, and cannot be, exhaustive. Industry fraud reports
   are explicit that IPRN (International Premium Rate Number) traffic
   is now spread across 200+ countries and shifts month to month as
   fraudsters adapt — a static blocklist alone is a known-incomplete
   defense, not a guarantee. Treat HIGH_RISK_PREFIXES as a starting
   point to extend with your own carrier's current fraud intelligence,
   not a finished product.
2. Off-hours call volume — bursts of outbound calls (especially
   international ones) outside a configurable "normal business hours"
   window, a classic indicator of automated/compromised-extension
   dialing rather than genuine human calling patterns.
3. Rapid repeated short calls from a single extension — many calls in
   a short time window from the same src, especially short-duration
   ones, indicative of an automated dialer or a compromised extension
   being used to probe many destinations quickly.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from voipaudit.core.cdr import CDRRecord
from voipaudit.core.models import Finding, FindingCategory, Severity

# Sourced from two structurally-durable categories (not tied to any
# single month's fraud campaign) plus a few illustrative,
# currently-documented examples:
#
# - International satellite / premium-network prefixes: these are
#   ALWAYS worth scrutiny for a typical business PBX that has no
#   legitimate reason to call a satellite phone or a premium
#   international network number. (ITU-T E.164 country/global service
#   codes: 870-874 Inmarsat, 881 Global Mobile Satellite System, 882
#   International Networks, 883 International Networks (shared code),
#   888 Telecommunications for Disaster Relief -- 883/888 in
#   particular are also widely abused for IPRN hosting.)
# - NANP numbers formatted to *look* domestic (shared +1 country code)
#   but that are actually expensive international destinations -- the
#   classic Wangiri/one-ring-callback target set, structurally durable
#   since the deception relies on the shared country code, not a
#   specific campaign. (Anguilla 264, Antigua & Barbuda 268, British
#   Virgin Islands 284, Cayman Islands 345, Grenada 473, Turks &
#   Caicos 649, Montserrat 664, Dominica 767, Dominican Republic
#   809/829/849, Trinidad & Tobago 868, Jamaica 876.)
# - A few currently-documented high-IRSF-ratio destinations from a
#   real, dated fraud report (AB Handshake Q4 2025: Cook Islands 682,
#   Guinea-Bissau 245, Somalia 252) -- included as illustrative
#   examples of the kind of intelligence this list needs to be kept
#   current with, not as a permanent or exhaustive set.
#
# Keys are E.164 country/prefix codes WITHOUT a leading '+' or '00' —
# matching is done against a normalized destination number (see
# _normalize_e164 below).
HIGH_RISK_PREFIXES: dict[str, str] = {
    "870": "Inmarsat satellite",
    "871": "Inmarsat satellite",
    "872": "Inmarsat satellite",
    "873": "Inmarsat satellite",
    "874": "Inmarsat satellite",
    "881": "Global Mobile Satellite System",
    "882": "International Networks (premium)",
    "883": "International Networks (premium, IPRN-hosting-prone)",
    "888": "Telecommunications for Disaster Relief (also IPRN-hosting-prone)",
    "1264": "Anguilla (NANP Wangiri target)",
    "1268": "Antigua & Barbuda (NANP Wangiri target)",
    "1284": "British Virgin Islands (NANP Wangiri target)",
    "1345": "Cayman Islands (NANP Wangiri target)",
    "1473": "Grenada (NANP Wangiri target)",
    "1649": "Turks & Caicos (NANP Wangiri target)",
    "1664": "Montserrat (NANP Wangiri target)",
    "1767": "Dominica (NANP Wangiri target)",
    "1809": "Dominican Republic (NANP Wangiri target)",
    "1829": "Dominican Republic (NANP Wangiri target)",
    "1849": "Dominican Republic (NANP Wangiri target)",
    "1868": "Trinidad & Tobago (NANP Wangiri target)",
    "1876": "Jamaica (NANP Wangiri target)",
    "682": "Cook Islands (high IRSF ratio, AB Handshake Q4 2025 report)",
    "245": "Guinea-Bissau (high IRSF ratio, AB Handshake Q4 2025 report)",
    "252": "Somalia (most common IRSF destination, TransNexus IPRN market study)",
}

# Sorted longest-prefix-first so a 4-digit NANP area code (e.g. "1264")
# is checked before the bare "1" would ever incorrectly match first —
# there's no bare "1" entry above, but this ordering is the correct,
# general way to do E.164 prefix matching regardless.
_SORTED_PREFIXES = sorted(HIGH_RISK_PREFIXES, key=len, reverse=True)

_DEFAULT_BUSINESS_START_HOUR = 7
_DEFAULT_BUSINESS_END_HOUR = 21  # 24h clock; calls outside [7, 21) are "off-hours"
_OFF_HOURS_MIN_CALLS = 5  # below this, a single late call isn't inherently suspicious
_BURST_WINDOW_SECONDS = 300  # 5 minutes
_BURST_MIN_CALLS = 5
_BURST_MAX_AVG_DURATION_SECONDS = 15  # short calls are the fraud-probing signature


def _normalize_e164(dst: str) -> str:
    """Strips common dial-prefix noise (leading '+', '00', a leading
    trunk-access '9' some PBX dialplans prepend) so HIGH_RISK_PREFIXES
    matching works against the same shape of number a real dialplan
    would actually dial out with. Not a complete E.164 normalizer —
    real dialplans vary enough that a fully general one is out of
    scope here; this handles the common cases."""
    d = dst.strip().lstrip("+")
    if d.startswith("00"):
        d = d[2:]
    return d


def _matched_high_risk_prefix(dst: str) -> str | None:
    normalized = _normalize_e164(dst)
    for prefix in _SORTED_PREFIXES:
        if normalized.startswith(prefix):
            return prefix
    return None


@dataclass
class TollFraudAnalysis:
    findings: list[Finding] = field(default_factory=list)
    records_analyzed: int = 0


def analyze_toll_fraud(
    records: list[CDRRecord],
    source_label: str = "cdr",
    business_start_hour: int = _DEFAULT_BUSINESS_START_HOUR,
    business_end_hour: int = _DEFAULT_BUSINESS_END_HOUR,
) -> TollFraudAnalysis:
    """Runs all three detection rules over a parsed CDR set. Returns
    every finding across all three rules — callers decide how to
    render/filter (e.g. by severity) rather than this function making
    that choice."""
    findings: list[Finding] = []
    findings.extend(_high_risk_destination_findings(records, source_label))
    findings.extend(_off_hours_findings(records, source_label, business_start_hour, business_end_hour))
    findings.extend(_burst_findings(records, source_label))
    return TollFraudAnalysis(findings=findings, records_analyzed=len(records))


def _high_risk_destination_findings(records: list[CDRRecord], source_label: str) -> list[Finding]:
    matches: dict[str, list[CDRRecord]] = defaultdict(list)
    for rec in records:
        if not rec.answered:
            continue  # unanswered calls didn't generate billable fraud revenue
        prefix = _matched_high_risk_prefix(rec.dst)
        if prefix:
            matches[prefix].append(rec)

    findings = []
    for prefix, recs in matches.items():
        total_billsec = sum(r.billsec for r in recs)
        findings.append(Finding(
            module="toll_fraud_cdr",
            title=f"Calls to known high-risk destination (+{prefix}, {HIGH_RISK_PREFIXES[prefix]})",
            severity=Severity.CRITICAL,
            category=FindingCategory.RECON,
            target=source_label,
            description=(
                f"{len(recs)} answered call(s) to +{prefix} ({HIGH_RISK_PREFIXES[prefix]}), "
                f"totaling {total_billsec}s of billable time, from extension(s): "
                f"{', '.join(sorted({r.src for r in recs}))}."
            ),
            evidence=f"e.g. {recs[0].start.isoformat()} {recs[0].src} -> {recs[0].dst} ({recs[0].billsec}s)",
            remediation=(
                "Verify these calls were legitimate. If not, the source extension(s) may be "
                "compromised — check for weak/default credentials, and consider restricting "
                "outbound international dialing on this PBX by default (allow-list specific "
                "extensions/destinations rather than blocking specific ones)."
            ),
        ))
    return findings


def _off_hours_findings(
    records: list[CDRRecord], source_label: str, start_hour: int, end_hour: int,
) -> list[Finding]:
    off_hours = [
        r for r in records
        if r.answered and not (start_hour <= r.start.hour < end_hour)
    ]
    if len(off_hours) < _OFF_HOURS_MIN_CALLS:
        return []

    by_src: dict[str, list[CDRRecord]] = defaultdict(list)
    for r in off_hours:
        by_src[r.src].append(r)

    findings = []
    for src, recs in by_src.items():
        if len(recs) < _OFF_HOURS_MIN_CALLS:
            continue
        international = [r for r in recs if _matched_high_risk_prefix(r.dst) or len(r.dst) > 7]
        findings.append(Finding(
            module="toll_fraud_cdr",
            title=f"Off-hours call volume from extension {src}",
            severity=Severity.MEDIUM if not international else Severity.HIGH,
            category=FindingCategory.RECON,
            target=source_label,
            description=(
                f"{len(recs)} answered call(s) from {src} outside the "
                f"{start_hour:02d}:00-{end_hour:02d}:00 business-hours window "
                f"({len(international)} to numbers that look international) — "
                f"a classic signature of automated or compromised-extension dialing "
                f"rather than genuine human calling patterns."
            ),
        ))
    return findings


def _burst_findings(records: list[CDRRecord], source_label: str) -> list[Finding]:
    by_src: dict[str, list[CDRRecord]] = defaultdict(list)
    for r in records:
        by_src[r.src].append(r)

    findings = []
    for src, recs in by_src.items():
        recs = sorted(recs, key=lambda r: r.start)
        window: list[CDRRecord] = []
        for rec in recs:
            window.append(rec)
            window = [r for r in window if (rec.start - r.start).total_seconds() <= _BURST_WINDOW_SECONDS]
            if len(window) < _BURST_MIN_CALLS:
                continue
            avg_duration = sum(r.billsec for r in window) / len(window)
            if avg_duration <= _BURST_MAX_AVG_DURATION_SECONDS:
                findings.append(Finding(
                    module="toll_fraud_cdr",
                    title=f"Rapid burst of short calls from extension {src}",
                    severity=Severity.HIGH,
                    category=FindingCategory.RECON,
                    target=source_label,
                    description=(
                        f"{len(window)} calls from {src} within {_BURST_WINDOW_SECONDS}s "
                        f"(ending {rec.start.isoformat()}), averaging {avg_duration:.1f}s each — "
                        f"an automated-dialer/compromised-extension signature, not typical human "
                        f"calling behavior."
                    ),
                    evidence=", ".join(f"{r.dst} ({r.billsec}s)" for r in window[:5]),
                ))
                # Clear the window (not just break) so a later, genuinely
                # separate burst from the same extension can still be
                # detected, while avoiding re-flagging the same overlapping
                # calls repeatedly as the window slides forward one call
                # at a time.
                window = []
    return findings
