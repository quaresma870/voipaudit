"""voipaudit CLI."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

console = Console()

_TEMPLATE = """\
# voipaudit authorization file.
#
# This file does not authorize anything until every field below is
# filled in truthfully and explicit, written sign-off has been
# obtained from the owner of every target listed in scope.targets.
# voipaudit will refuse to run a single probe without a validated
# file like this one.

engagement_id: ""            # a short, unique identifier for this engagement
authorized_by: ""            # full name of the person who approved this
authorized_contact_email: ""
client: ""                   # organisation being tested

scope:
  targets:
    - ""                     # e.g. "203.0.113.10", "pbx.example.com", "203.0.113.0/24"
  excluded_targets: []
  allowed_categories:
    - recon                  # OPTIONS-based fingerprinting only — no session/registration traffic
    # - active                # also allows register_exposed (a real REGISTER probe) — requires --confirm too

window:
  start: ""                  # ISO 8601, e.g. "2026-01-01T00:00:00+00:00"
  end: ""

confirmation_phrase: ""      # required verbatim before any --active-tier module runs

# rate_limits:                # optional override of the conservative SIP defaults
#   max_total_requests: 1000
#   max_per_second: 10.0
"""


@click.group()
@click.version_option(package_name="voipaudit")
def cli():
    """📞 voipaudit — authorized SIP/VoIP security auditing."""


@cli.command()
@click.option("--output", "-o", default="authorization.yml", show_default=True)
@click.option("--force", is_flag=True, help="Overwrite an existing file.")
def init(output, force):
    """Create an authorization.yml template.

    Every field still requires manual completion — this never auto-fills
    scope, dates, or the confirmation phrase.
    """
    path = Path(output)
    if path.exists() and not force:
        console.print(f"[red]{path} already exists.[/red] Use --force to overwrite.")
        sys.exit(1)

    path.write_text(_TEMPLATE, encoding="utf-8")
    console.print(f"[green]✔[/green] Template written: [bold]{path}[/bold]")
    console.print(
        "\n[yellow]This file does not authorize anything yet.[/yellow] "
        "Fill in every field, get explicit sign-off from the target owner, then run:\n"
        f"  [cyan]voipaudit validate-scope --authorization {path}[/cyan]\n"
    )


@cli.command(name="validate-scope")
@click.option("--authorization", "-a", default="authorization.yml", show_default=True)
def validate_scope(authorization):
    """Validate an authorization.yml — schema, time window, and scope."""
    from voipaudit.core.authorization import AuthorizationError, load_authorization

    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    console.print(f"[green]✔[/green] Valid authorization file: [bold]{authorization}[/bold]")
    console.print(f"  Engagement: {auth.engagement_id} ({auth.client})")
    console.print(f"  Authorized by: {auth.authorized_by}")
    console.print(f"  Targets: {', '.join(auth.scope.targets)}")
    console.print(f"  Categories: {', '.join(auth.scope.allowed_categories) or '(none)'}")
    console.print(f"  Window: {auth.window.start.isoformat()} → {auth.window.end.isoformat()}")
    if not auth.is_within_window():
        console.print("  [yellow]⚠ Current time is outside this authorization's window.[/yellow]")


@cli.command(name="list-plugins")
def list_plugins():
    """List all available plugins and their tier (recon/active)."""
    from voipaudit.plugins import available_plugins

    table_rows = available_plugins()
    console.print("\n[bold]Available plugins[/bold]\n")
    for name, category in table_rows.items():
        tag = "[cyan]recon[/cyan]" if category == "recon" else "[yellow]active[/yellow]"
        console.print(f"  {name:<20} {tag}")
    console.print()


@cli.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--authorization", "-a", default="authorization.yml", show_default=True)
@click.option("--audit-log", default=None, help="Path to the audit log (default: <engagement_id>.audit.jsonl)")
@click.option("--modules", "-m", default=None,
              help="Comma-separated plugin names to run (default: all recon-tier plugins).")
@click.option("--confirm", default=None,
              help="Type the exact engagement_id to enable active-tier plugins this run.")
@click.option("--timeout", default=3.0, show_default=True, type=float, help="Per-probe SIP timeout in seconds.")
@click.option("--transport", type=click.Choice(["udp", "tcp", "tls"]), default="udp", show_default=True,
              help="SIP transport to use for every probe this run (ignored by transport_security, "
                   "which always checks TLS and plaintext together regardless of this setting).")
@click.option("--insecure", is_flag=True,
              help="Skip TLS certificate verification — needed to reach a self-signed or otherwise "
                   "unverifiable target at all. Never silently downgrades the target's own security; "
                   "only affects whether this client verifies the target's certificate.")
@click.option("--tls-port", default=5061, show_default=True, type=int,
              help="Port to probe for TLS/SIPS — used only by transport_security.")
@click.option("--plaintext-port", default=5060, show_default=True, type=int,
              help="Port to probe for plaintext UDP/TCP — used only by transport_security.")
@click.option("--json", "json_output", default=None, type=click.Path(),
              help="Also write findings as JSON to this path — a more robust way to check "
                   "results programmatically than parsing the terminal table's word-wrapped text.")
def scan(targets, authorization, audit_log, modules, confirm, timeout, transport, insecure, tls_port, plaintext_port, json_output):
    """Scan one or more SIP targets (host, host:port, or sip:/sips: URI)."""
    from voipaudit.core.authorization import AuthorizationError, load_authorization
    from voipaudit.core.engagement import (
        ActiveTierNotConfirmed,
        Engagement,
        InviteTierNotConfirmed,
        ScopeViolation,
    )
    from voipaudit.plugins import available_plugins
    from voipaudit.plugins.pbx_fingerprint import PBXFingerprintModule
    from voipaudit.plugins.register_exposed import RegisterExposedModule
    from voipaudit.plugins.toll_fraud_exposure import TollFraudExposureModule
    from voipaudit.plugins.transport_security import TransportSecurityModule
    from voipaudit.reports.terminal import print_results

    _PLUGIN_CLASSES = {
        "pbx_fingerprint": PBXFingerprintModule,
        "register_exposed": RegisterExposedModule,
        "transport_security": TransportSecurityModule,
        "toll_fraud_exposure": TollFraudExposureModule,
    }

    try:
        auth = load_authorization(authorization)
    except AuthorizationError as exc:
        console.print(f"[red]✘ Invalid authorization file:[/red] {exc}")
        sys.exit(1)

    log_path = audit_log or f"{auth.engagement_id}.audit.jsonl"
    eng = Engagement(auth, log_path)

    registry = available_plugins()
    if modules:
        selected = [m.strip() for m in modules.split(",")]
        unknown = [m for m in selected if m not in registry]
        if unknown:
            console.print(f"[red]✘ Unknown module(s):[/red] {', '.join(unknown)}")
            console.print(f"  Available: {', '.join(registry)}")
            sys.exit(1)
    else:
        selected = [m for m, cat in registry.items() if cat == "recon"]

    if any(registry[m] in ("active", "invite") for m in selected):
        if not confirm:
            console.print(
                "[red]✘ At least one selected module is active-tier (or higher) and --confirm "
                "was not given.[/red]"
            )
            console.print(f"  Re-run with: [cyan]--confirm {auth.engagement_id}[/cyan]")
            sys.exit(1)
        try:
            eng.confirm_active_tier(confirm)
            console.print(f"[green]✔[/green] Active-tier confirmed for engagement '{auth.engagement_id}'.\n")
        except ActiveTierNotConfirmed as exc:
            console.print(f"[red]✘ {exc}[/red]")
            sys.exit(1)

    if any(registry[m] == "invite" for m in selected):
        console.print(
            "\n[bold yellow]⚠ invite-tier module(s) selected — this sends real SIP INVITE "
            "requests.[/bold yellow]"
        )
        console.print(
            "  A real INVITE can ring a phone or, if answered, start accruing real "
            "telephony cost.\n  This probe auto-cancels at the earliest possible moment "
            "(see core/invite_probe.py), but is never risk-free.\n"
        )
        if not confirm:
            console.print(
                "[red]✘ At least one selected module is invite-tier and --confirm was not given.[/red]"
            )
            console.print(f"  Re-run with: [cyan]--confirm {auth.engagement_id}[/cyan]")
            sys.exit(1)
        try:
            eng.confirm_invite_tier(confirm)
            console.print(f"[green]✔[/green] Invite-tier confirmed for engagement '{auth.engagement_id}'.\n")
        except InviteTierNotConfirmed as exc:
            console.print(f"[red]✘ {exc}[/red]")
            sys.exit(1)

    exit_code = 0
    all_findings = []
    for target in targets:
        results = []
        for mod_name in selected:
            plugin_cls = _PLUGIN_CLASSES[mod_name]
            # transport_security and toll_fraud_exposure each have a
            # genuinely different constructor shape from the
            # transport/tls_verify pattern the other plugins share —
            # transport_security always probes TLS + plaintext
            # together regardless of --transport, and
            # toll_fraud_exposure sends INVITE over a fixed transport
            # with its own max_destinations knob, not a tls_verify
            # concept at all.
            if mod_name == "transport_security":
                plugin = plugin_cls(
                    eng, timeout=timeout, tls_verify=not insecure,
                    tls_port=tls_port, plaintext_port=plaintext_port,
                )
            elif mod_name == "toll_fraud_exposure":
                plugin = plugin_cls(eng, timeout=timeout, transport=transport)
            else:
                plugin = plugin_cls(eng, timeout=timeout, transport=transport, tls_verify=not insecure)
            try:
                result = plugin.run(target)
            except ScopeViolation as exc:
                console.print(f"[red]✘ {exc}[/red]")
                exit_code = 1
                continue
            results.append(result)
            all_findings.extend(result.findings)
            if any(f.severity.value in ("CRITICAL", "HIGH") for f in result.findings):
                exit_code = 1
        print_results(target, results)

    if json_output:
        import json as json_module
        with open(json_output, "w") as f:
            json_module.dump([f.to_dict() for f in all_findings], f, indent=2)
        console.print(f"[green]✔[/green] Wrote {len(all_findings)} finding(s) to {json_output}")

    sys.exit(exit_code)


@cli.command(name="analyze-cdr")
@click.argument("cdr_file", type=click.Path(exists=True))
@click.option("--business-start-hour", default=7, show_default=True, type=int,
              help="Hour (0-23) business hours start — calls before this are 'off-hours'.")
@click.option("--business-end-hour", default=21, show_default=True, type=int,
              help="Hour (0-23) business hours end — calls at/after this are 'off-hours'.")
@click.option("--json", "json_output", default=None, type=click.Path(),
              help="Also write findings as JSON to this path.")
def analyze_cdr(cdr_file, business_start_hour, business_end_hour, json_output):
    """Analyze an Asterisk CDR CSV export for toll-fraud patterns.

    File-analysis only — no live target is touched, so no
    authorization.yml or Engagement gate is needed here (unlike
    `scan`). See ROADMAP.md for why CDR analysis and live SIP scanning
    are deliberately kept as separate features.
    """
    from voipaudit.analyzers.toll_fraud import analyze_toll_fraud
    from voipaudit.core.cdr import CDRParseError, parse_asterisk_cdr_csv
    from voipaudit.core.models import ModuleResult
    from voipaudit.reports.terminal import print_results

    try:
        records = parse_asterisk_cdr_csv(cdr_file)
    except CDRParseError as exc:
        console.print(f"[red]✘ Could not parse {cdr_file}:[/red] {exc}")
        sys.exit(1)

    if not records:
        console.print(f"[yellow]⚠[/yellow] {cdr_file} parsed successfully but contained no records.")
        sys.exit(0)

    console.print(f"[green]✔[/green] Parsed {len(records)} record(s) from {cdr_file}\n")

    result = analyze_toll_fraud(
        records, source_label=cdr_file,
        business_start_hour=business_start_hour, business_end_hour=business_end_hour,
    )
    print_results(cdr_file, [ModuleResult(module="toll_fraud_cdr", findings=result.findings)])

    if json_output:
        import json as json_module
        with open(json_output, "w") as f:
            json_module.dump([f.to_dict() for f in result.findings], f, indent=2)
        console.print(f"[green]✔[/green] Wrote {len(result.findings)} finding(s) to {json_output}")

    if any(f.severity.value in ("CRITICAL", "HIGH") for f in result.findings):
        sys.exit(1)


@cli.command(name="analyze-pcap")
@click.argument("pcap_file", type=click.Path(exists=True))
@click.option("--business-start-hour", default=7, show_default=True, type=int,
              help="Hour (0-23) business hours start — calls before this are 'off-hours'.")
@click.option("--business-end-hour", default=21, show_default=True, type=int,
              help="Hour (0-23) business hours end — calls at/after this are 'off-hours'.")
@click.option("--json", "json_output", default=None, type=click.Path(),
              help="Also write findings as JSON to this path.")
def analyze_pcap(pcap_file, business_start_hour, business_end_hour, json_output):
    """Analyze a packet capture (pcap/pcapng) for toll-fraud patterns.

    Reconstructs SIP call sessions directly from captured traffic and
    runs the exact same toll-fraud analysis as `analyze-cdr` — this
    works against effectively any SBC/PBX vendor's traffic (SIP itself
    is the standard, not any particular CDR export format), not just
    Asterisk. Requires the optional 'pcap' extra: pip install
    voipaudit[pcap].

    File-analysis only — no live target is touched, so no
    authorization.yml or Engagement gate is needed here, matching
    `analyze-cdr`'s own reasoning.
    """
    from voipaudit.analyzers.toll_fraud import analyze_toll_fraud
    from voipaudit.core.models import ModuleResult
    from voipaudit.core.pcap_parser import PcapParseError, parse_pcap_to_call_records
    from voipaudit.reports.terminal import print_results

    try:
        records = parse_pcap_to_call_records(pcap_file)
    except PcapParseError as exc:
        console.print(f"[red]✘ Could not parse {pcap_file}:[/red] {exc}")
        sys.exit(1)

    if not records:
        console.print(
            f"[yellow]⚠[/yellow] {pcap_file} parsed successfully but no complete SIP call "
            f"(INVITE + a final response) was found in it."
        )
        sys.exit(0)

    console.print(f"[green]✔[/green] Reconstructed {len(records)} call record(s) from {pcap_file}\n")

    result = analyze_toll_fraud(
        records, source_label=pcap_file,
        business_start_hour=business_start_hour, business_end_hour=business_end_hour,
    )
    print_results(pcap_file, [ModuleResult(module="toll_fraud_pcap", findings=result.findings)])

    if json_output:
        import json as json_module
        with open(json_output, "w") as f:
            json_module.dump([f.to_dict() for f in result.findings], f, indent=2)
        console.print(f"[green]✔[/green] Wrote {len(result.findings)} finding(s) to {json_output}")

    if any(f.severity.value in ("CRITICAL", "HIGH") for f in result.findings):
        sys.exit(1)


def main():
    cli()


if __name__ == "__main__":
    main()
