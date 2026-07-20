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
def scan(targets, authorization, audit_log, modules, confirm, timeout, transport, insecure, tls_port, plaintext_port):
    """Scan one or more SIP targets (host, host:port, or sip:/sips: URI)."""
    from voipaudit.core.authorization import AuthorizationError, load_authorization
    from voipaudit.core.engagement import ActiveTierNotConfirmed, Engagement, ScopeViolation
    from voipaudit.plugins import available_plugins
    from voipaudit.plugins.pbx_fingerprint import PBXFingerprintModule
    from voipaudit.plugins.register_exposed import RegisterExposedModule
    from voipaudit.plugins.transport_security import TransportSecurityModule
    from voipaudit.reports.terminal import print_results

    _PLUGIN_CLASSES = {
        "pbx_fingerprint": PBXFingerprintModule,
        "register_exposed": RegisterExposedModule,
        "transport_security": TransportSecurityModule,
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

    if any(registry[m] == "active" for m in selected):
        if not confirm:
            console.print(
                "[red]✘ At least one selected module is active-tier and --confirm was not given.[/red]"
            )
            console.print(f"  Re-run with: [cyan]--confirm {auth.engagement_id}[/cyan]")
            sys.exit(1)
        try:
            eng.confirm_active_tier(confirm)
            console.print(f"[green]✔[/green] Active-tier confirmed for engagement '{auth.engagement_id}'.\n")
        except ActiveTierNotConfirmed as exc:
            console.print(f"[red]✘ {exc}[/red]")
            sys.exit(1)

    exit_code = 0
    for target in targets:
        results = []
        for mod_name in selected:
            plugin_cls = _PLUGIN_CLASSES[mod_name]
            # transport_security has a genuinely different shape (it
            # always probes TLS + plaintext together, regardless of
            # --transport) rather than forcing a one-size-fits-all
            # constructor across plugins whose actual behavior differs.
            if mod_name == "transport_security":
                plugin = plugin_cls(
                    eng, timeout=timeout, tls_verify=not insecure,
                    tls_port=tls_port, plaintext_port=plaintext_port,
                )
            else:
                plugin = plugin_cls(eng, timeout=timeout, transport=transport, tls_verify=not insecure)
            try:
                result = plugin.run(target)
            except ScopeViolation as exc:
                console.print(f"[red]✘ {exc}[/red]")
                exit_code = 1
                continue
            results.append(result)
            if any(f.severity.value in ("CRITICAL", "HIGH") for f in result.findings):
                exit_code = 1
        print_results(target, results)

    sys.exit(exit_code)


def main():
    cli()


if __name__ == "__main__":
    main()
