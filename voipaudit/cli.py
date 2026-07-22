"""voipaudit CLI."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
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
    """List all available plugins and their tier (recon/active/invite)."""
    from voipaudit.plugins import available_plugins

    table_rows = available_plugins()
    tag_styles = {
        "recon": "[cyan]recon[/cyan]",
        "active": "[yellow]active[/yellow]",
        "invite": "[bold red]invite[/bold red]",
    }
    console.print("\n[bold]Available plugins[/bold]\n")
    for name, category in table_rows.items():
        tag = tag_styles.get(category, category)
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
@click.option("--to-user", default=None,
              help="Destination user/extension to test — used by srtp_check, caller_id_spoofing, "
                   "and refer_transfer_abuse. Defaults to a generic placeholder; results are "
                   "strongest against a known-valid, reachable extension.")
@click.option("--spoof-from", default=None,
              help="Identity to claim (From header and P-Asserted-Identity) in caller_id_spoofing's "
                   "spoofed-identity probe. Defaults to --to-user itself (\"the destination calling "
                   "itself\") — set this to a specific known-trusted internal identity to test "
                   "instead (e.g. a reception or executive extension).")
@click.option("--confirm-transfer-reachable", is_flag=True,
              help="refer_transfer_abuse only: point Refer-To at a small SIP listener this tool runs "
                   "itself instead of a synthetic extension on the target, to directly observe (not "
                   "just infer from signalling) whether the target places a real callback call. "
                   "Escalates the finding to CRITICAL when confirmed.")
@click.option("--callback-host", default=None,
              help="refer_transfer_abuse --confirm-transfer-reachable only: address the confirmation "
                   "listener binds to and advertises in Refer-To. Defaults to auto-detecting the "
                   "local outbound-routing IP toward the target; override for NAT/firewalled setups "
                   "where that address isn't what the target can actually reach back on.")
@click.option("--callback-port", default=0, show_default=True, type=int,
              help="refer_transfer_abuse --confirm-transfer-reachable only: port for the confirmation "
                   "listener. Defaults to an OS-assigned ephemeral port.")
@click.option("--db", "db_path", default=None, type=click.Path(),
              help="Also persist each target's run and findings to this SQLite database (created if "
                   "it doesn't exist) — browsable later with `voipaudit dashboard --db PATH`. Opt-in; "
                   "without this, nothing is written beyond the existing tamper-evident audit log.")
def scan(
    targets, authorization, audit_log, modules, confirm, timeout, transport, insecure, tls_port,
    plaintext_port, json_output, to_user, spoof_from, confirm_transfer_reachable, callback_host,
    callback_port, db_path,
):
    """Scan one or more SIP targets (host, host:port, or sip:/sips: URI)."""
    from voipaudit.core.authorization import AuthorizationError, load_authorization
    from voipaudit.core.engagement import (
        ActiveTierNotConfirmed,
        Engagement,
        InviteTierNotConfirmed,
        ScopeViolation,
    )
    from voipaudit.plugins import available_plugins
    from voipaudit.plugins.caller_id_spoofing import CallerIDSpoofingModule
    from voipaudit.plugins.pbx_fingerprint import PBXFingerprintModule
    from voipaudit.plugins.refer_transfer_abuse import ReferTransferAbuseModule
    from voipaudit.plugins.register_exposed import RegisterExposedModule
    from voipaudit.plugins.srtp_check import SRTPCheckModule
    from voipaudit.plugins.toll_fraud_exposure import TollFraudExposureModule
    from voipaudit.plugins.transport_security import TransportSecurityModule
    from voipaudit.reports.terminal import print_results

    _PLUGIN_CLASSES = {
        "pbx_fingerprint": PBXFingerprintModule,
        "register_exposed": RegisterExposedModule,
        "transport_security": TransportSecurityModule,
        "toll_fraud_exposure": TollFraudExposureModule,
        "srtp_check": SRTPCheckModule,
        "caller_id_spoofing": CallerIDSpoofingModule,
        "refer_transfer_abuse": ReferTransferAbuseModule,
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

    db_conn = None
    if db_path:
        from voipaudit.core.db import init_db
        db_conn = init_db(db_path)

    exit_code = 0
    all_findings = []
    for target in targets:
        results = []
        run_started_at = datetime.now(UTC)
        for mod_name in selected:
            plugin_cls = _PLUGIN_CLASSES[mod_name]
            # transport_security has a genuinely different shape from
            # the rest (it always probes TLS + plaintext together
            # regardless of --transport). The other invite-tier
            # plugins all use core/invite_probe.py, which supports
            # udp/tcp/tls uniformly, so --transport is passed straight
            # through to each of them the same way.
            if mod_name == "transport_security":
                plugin = plugin_cls(
                    eng, timeout=timeout, tls_verify=not insecure,
                    tls_port=tls_port, plaintext_port=plaintext_port,
                )
            elif mod_name in (
                "toll_fraud_exposure", "srtp_check", "caller_id_spoofing", "refer_transfer_abuse",
            ):
                kwargs = {"timeout": timeout, "transport": transport, "tls_verify": not insecure}
                if mod_name != "toll_fraud_exposure" and to_user:
                    kwargs["to_user"] = to_user
                if mod_name == "caller_id_spoofing" and spoof_from:
                    kwargs["spoof_from"] = spoof_from
                if mod_name == "refer_transfer_abuse" and confirm_transfer_reachable:
                    kwargs["confirm_reachable"] = True
                    if callback_host:
                        kwargs["callback_host"] = callback_host
                    kwargs["callback_port"] = callback_port
                plugin = plugin_cls(eng, **kwargs)
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

        if db_conn is not None:
            from voipaudit.core.db import record_run
            target_findings = [f for r in results for f in r.findings]
            record_run(
                db_conn, engagement_id=auth.engagement_id, client=auth.client, target=target,
                modules=selected, transport=transport, started_at=run_started_at,
                finished_at=datetime.now(UTC), findings=target_findings,
            )

    if db_conn is not None:
        db_conn.close()
        console.print(f"[green]✔[/green] Persisted scan history to {db_path}")

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
@click.option("--tls-keylog", default=None, type=click.Path(exists=True),
              help="SSLKEYLOGFILE (NSS Key Log format, the same file Wireshark's own "
                   "'Decrypt TLS traffic' uses) to additionally decrypt TLS/SIPS-carried SIP "
                   "traffic in this capture. TLS 1.2 only — see core/pcap_parser.py for why "
                   "TLS 1.3 isn't attempted. Without this, TLS-carried SIP traffic in the "
                   "capture is silently skipped, same as any other undecryptable traffic.")
@click.option("--json", "json_output", default=None, type=click.Path(),
              help="Also write findings as JSON to this path.")
def analyze_pcap(pcap_file, business_start_hour, business_end_hour, tls_keylog, json_output):
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
        records = parse_pcap_to_call_records(pcap_file, tls_keylog=tls_keylog)
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


@cli.command()
@click.option("--db", "db_path", required=True, type=click.Path(exists=True),
              help="Path to a scan history database populated by `scan --db`.")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Bind address. Defaults to localhost only — this dashboard has no "
                   "authentication of its own; only bind it more broadly on a trusted network.")
@click.option("--port", default=8000, show_default=True, type=int)
def dashboard(db_path, host, port):
    """Read-only web dashboard for browsing `scan --db` history.

    GET-only: nothing served here ever inserts, updates, or deletes
    anything. Requires the optional 'dashboard' extra: pip install
    voipaudit[dashboard].
    """
    try:
        import uvicorn
    except ImportError:
        console.print(
            "[red]✘ The 'dashboard' extra is required.[/red] Install with: "
            "pip install voipaudit[dashboard]"
        )
        sys.exit(1)

    from voipaudit.dashboard.app import create_app

    app = create_app(db_path)
    console.print(f"[green]✔[/green] Serving read-only dashboard at http://{host}:{port} (Ctrl+C to stop)")
    if host not in ("127.0.0.1", "localhost"):
        console.print(
            "[yellow]⚠ Binding beyond localhost — this dashboard has no authentication of its "
            "own. Only do this on a trusted network.[/yellow]"
        )
    uvicorn.run(app, host=host, port=port, log_level="warning")


def main():
    cli()


if __name__ == "__main__":
    main()
