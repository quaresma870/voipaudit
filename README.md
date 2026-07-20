# 📞 voipaudit

Authorized SIP/VoIP security auditing — PBX fingerprinting, unauthenticated
REGISTER exposure detection, and more to come.

---

## ⚠️ Authorization required — read this first

**This tool will not run a single probe without a validated `authorization.yml`.**
That file records who approved the engagement, exactly which targets are in
scope, and for how long. Every probe — even a passive OPTIONS ping — is
checked against it before a single SIP message is sent, and every check
(allowed or refused) is recorded in a tamper-evident, hash-chained audit log.

Sending unsolicited SIP traffic (even a single REGISTER attempt) against
infrastructure you don't have explicit, written permission to test is not
something this tool exists to help with. VoIP infrastructure is
production telecom equipment — misuse has real consequences (toll fraud
exposure, service disruption, legal liability).

---

## Status

Early, actively developed. v0.1 covers three plugins, over UDP, TCP, and TLS:

- **`pbx_fingerprint`** (recon tier) — sends a SIP OPTIONS ping (RFC 3261
  §11, no dialog created, no side effects) and identifies the PBX/SIP
  stack from the response's Server/User-Agent header.
- **`register_exposed`** (active tier, requires `--confirm`) — sends a
  real REGISTER with no Authorization header and `Expires: 0`, checking
  whether the target incorrectly accepts an unauthenticated registration.
- **`transport_security`** (recon tier) — checks whether TLS (SIPS) is
  offered, reports certificate expiry, and flags plaintext SIP still
  being accepted alongside TLS (meaning encryption isn't actually
  *enforced*, just available).

All three transports (`--transport udp` / `tcp` / `tls`, UDP by default;
`--insecure` to skip certificate verification for a self-signed target)
are tested against a real mock SIP server over real sockets — not
simulated or assumed, including a real, deliberately-expired certificate
for `transport_security`'s CRITICAL detection path.

See [ROADMAP.md](ROADMAP.md) for what's planned next.

---

## Installation

```bash
git clone https://github.com/quaresma870/voipaudit.git
cd voipaudit
pip install .
```

## Quickstart

```bash
# 1. Create a template — every field still requires manual completion
voipaudit init

# 2. Fill in authorization.yml by hand: engagement_id, authorized_by,
#    scope.targets, window.start/end, confirmation_phrase. Get explicit
#    written sign-off from the target owner before going further.

# 3. Validate it
voipaudit validate-scope

# 4. Recon — PBX fingerprinting (no --confirm needed)
voipaudit scan pbx.example.com

# 5. Active-tier — REGISTER exposure check (requires --confirm)
voipaudit scan pbx.example.com --modules register_exposed --confirm <engagement_id>
```

Targets accept `host`, `host:port`, or a `sip:`/`sips:` URI. Port defaults
to the standard SIP UDP port 5060 (RFC 3261 §18.1) when omitted. Add
`--transport tcp` to probe over TCP instead of the default UDP.

## Plugins

| Plugin | Tier | What it checks |
|--------|------|-----------------|
| `pbx_fingerprint` | recon | Identifies the PBX/SIP stack via a SIP OPTIONS ping |
| `register_exposed` | active | Detects unauthenticated REGISTER acceptance |
| `transport_security` | recon | TLS availability, certificate expiry, plaintext-alongside-TLS |

```bash
voipaudit list-plugins

# transport_security probes two independent ports (TLS and plaintext),
# defaulting to the standard 5061/5060 — override for non-default setups:
voipaudit scan pbx.example.com --modules transport_security \
  --tls-port 5061 --plaintext-port 5060 --insecure
```

## The audit log

Every probe — allowed or refused — is recorded in
`<engagement_id>.audit.jsonl`, hash-chained so that editing, deleting, or
reordering any historical entry is detectable. Same tamper-evidence design
already used (and audited) in the sibling
[redteam-toolkit](https://github.com/quaresma870/redteam-toolkit) and
[secureaudit](https://github.com/quaresma870/secureaudit) projects — see
either repo's README for the full explanation of what this catches and
its one documented, inherent limitation (truncation of the most recent
entries).

## Project structure

```
voipaudit/
├── voipaudit/
│   ├── cli.py                    # init, validate-scope, scan, list-plugins
│   ├── core/
│   │   ├── authorization.py      # Authorization/Scope/Window — the scope gate's data model
│   │   ├── engagement.py         # Engagement — ties Authorization + audit log together
│   │   ├── audit_log.py          # hash-chained, append-only audit log
│   │   ├── rate_limit.py         # conservative SIP-specific rate budget defaults
│   │   ├── sip.py                # raw SIP (RFC 3261) message construction/parsing/transport
│   │   └── models.py             # Finding, Severity, ModuleResult
│   ├── plugins/
│   │   ├── base.py               # BasePlugin — every plugin's scan() must call authorize_action()
│   │   ├── pbx_fingerprint.py
│   │   ├── register_exposed.py
│   │   └── transport_security.py
│   └── reports/
│       └── terminal.py           # Rich-based terminal output
├── tests/
│   ├── fixtures/mock_pbx/server.py   # a real UDP SIP server, for tests only
│   └── test_voipaudit.py
└── .github/workflows/ci.yml
```

## CI

On every push/PR: lint → build the real wheel → install it in a clean venv
→ run the real installed `voipaudit` CLI against a real mock SIP server
(not `CliRunner` against the dev source tree) — the same "build it, run it
for real" method already applied throughout the sibling secureaudit and
redteam-toolkit repos, adopted here from the very first commit rather than
discovered later through an audit.

---

## License

MIT — see [LICENSE](LICENSE).
