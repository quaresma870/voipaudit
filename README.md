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

Early, actively developed. v0.1 covers four live-scan plugins (UDP,
TCP, and TLS) plus file-analysis commands:

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
- **`toll_fraud_exposure`** (**invite tier**, requires a written
  acknowledgment in `authorization.yml` *and* `--confirm` twice — see
  [Invite-tier: real INVITE probing](#invite-tier-real-invite-probing)
  below) — sends real, safety-bounded SIP INVITEs toward known
  high-risk destinations to check whether the dialplan would even route
  a call there, auto-cancelling at the earliest possible moment.
- **`srtp_check`** (**invite tier**, same requirements as above) —
  checks whether the target actually negotiates SRTP (encrypted media)
  when offered, using a differential test (an SRTP-only offer vs a
  plain-RTP-only offer to the same destination) that distinguishes
  "SRTP not supported" from "destination not reachable at all."
- **`analyze-cdr`** — parses an Asterisk CDR CSV export and flags
  patterns indicative of toll fraud already having occurred: calls to
  known high-risk international destinations, off-hours call bursts, and
  rapid repeated short calls from one extension. File-analysis only, no
  live target touched — no authorization.yml needed for this command.
- **`analyze-pcap`** — reconstructs SIP call sessions directly from a
  packet capture and runs the exact same toll-fraud analysis as
  `analyze-cdr` — works against effectively any SBC/PBX vendor's traffic
  (SIP itself is the standard, not any particular CDR export format),
  not just Asterisk. Requires the optional `pcap` extra
  (`pip install voipaudit[pcap]`).

All three live-scan transports (`--transport udp` / `tcp` / `tls`, UDP by
default; `--insecure` to skip certificate verification for a self-signed
target) are tested against a real mock SIP server over real sockets —
not simulated or assumed, including a real, deliberately-expired
certificate for `transport_security`'s CRITICAL detection path.

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
| `toll_fraud_exposure` | **invite** | Whether the dialplan routes calls toward high-risk destinations |
| `srtp_check` | **invite** | Whether SRTP (encrypted media) is actually negotiated |

```bash
voipaudit list-plugins

# transport_security probes two independent ports (TLS and plaintext),
# defaulting to the standard 5061/5060 — override for non-default setups:
voipaudit scan pbx.example.com --modules transport_security \
  --tls-port 5061 --plaintext-port 5060 --insecure
```

## Invite-tier: real INVITE probing

`toll_fraud_exposure` and `srtp_check` send real SIP INVITE requests —
categorically different from every other probe in this toolkit. A real
INVITE can ring a phone, or in the worst case be answered and start
accruing real per-minute cost. This is why invite-tier sits **above**
active-tier with its own, stricter authorization requirements, rather
than being folded into `active`:

1. **A written acknowledgment in `authorization.yml`.** `invite` in
   `scope.allowed_categories` requires a new field,
   `invite_tier_acknowledgment`, containing this exact text copied
   verbatim (not paraphrased — `voipaudit init` doesn't pre-fill it for
   you):
   ```
   I understand that invite-tier tests send real SIP INVITE requests
   that may ring phones or incur real telephony cost, and I am
   authorized to do this against every target in scope.
   ```
2. **`active` must also be in `allowed_categories`.** Invite-tier is an
   escalation beyond active-tier, not an independent switch —
   `active` must be confirmed first, every session.
3. **`--confirm <engagement_id>` still required**, same as active-tier.

```bash
voipaudit scan pbx.example.com --modules toll_fraud_exposure --confirm <engagement_id>

# srtp_check tests a specific destination/extension — results are
# strongest against a known-valid, reachable one:
voipaudit scan pbx.example.com --modules srtp_check --to-user 1001 --confirm <engagement_id>
```

**The safety technique:** as soon as ANY response indicates the call is
actually being routed (180 Ringing, 183 Session Progress, or an
outright 2xx answer), the probe immediately sends CANCEL (or, for the
rare instant-answer case, ACK followed immediately by BYE) — see
`core/invite_probe.py`'s own docstring for the full design. The goal is
only ever "does the dialplan route this destination at all," never
"does the call complete." A hard timeout (default 4s) applies
throughout every single probe, regardless of which plugin sends it.

`toll_fraud_exposure` sweeps a small, fixed sample of destinations
(default 5, hard-capped), with a mandatory 2-second pause between each
— drawn from the same `HIGH_RISK_PREFIXES` list `analyze-cdr`/
`analyze-pcap` already use (see their own documentation above for
sourcing and the same non-exhaustiveness caveat). `srtp_check` instead
sends exactly two probes to one destination (an SRTP-only offer, then
— after the same 2-second pause — a plain-RTP-only offer) to run its
differential comparison.

## CDR / toll-fraud analysis

```bash
voipaudit analyze-cdr /var/log/asterisk/cdr-csv/Master.csv
voipaudit analyze-cdr Master.csv --json findings.json
voipaudit analyze-cdr Master.csv --business-start-hour 8 --business-end-hour 18
```

File-analysis only — no live target is touched, so no `authorization.yml`
is needed for this command. Detects three patterns, each covered by real
test data in `tests/fixtures/cdr/sample_master.csv`:

- Calls to known high-risk international destinations (see
  `voipaudit/analyzers/toll_fraud.py`'s `HIGH_RISK_PREFIXES` for sourcing
  — this list is **not, and cannot be, exhaustive**; industry fraud
  reports are explicit that premium-rate number traffic is spread across
  200+ countries and shifts monthly, so treat this as a starting point
  to extend with your own carrier's current fraud intelligence).
- Off-hours call bursts from a single extension.
- Rapid repeated short calls from a single extension (an
  automated-dialer/compromised-extension signature).

### From a packet capture instead

```bash
pip install voipaudit[pcap]
voipaudit analyze-pcap capture.pcap
voipaudit analyze-pcap capture.pcap --json findings.json
```

Reconstructs SIP call sessions (INVITE → final response → BYE, correlated
by Call-ID) directly from captured traffic and feeds them into the exact
same `analyze_toll_fraud()` used by `analyze-cdr` — no changes needed to
the analysis logic itself, since the output is the same `CDRRecord`
shape either way. This works against any SBC/PBX vendor's traffic, not
just Asterisk, since SIP itself (not any particular CDR export format)
is what every one of them actually speaks on the wire. Only UDP SIP
transport is parsed in this first version — see
[ROADMAP.md](ROADMAP.md).

This is a genuinely different feature from `scan`'s live probing — see
[ROADMAP.md](ROADMAP.md) for why toll-fraud detection was deliberately
split into this file-analysis feature and a separate, not-yet-built live
exposure check.

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
│   ├── cli.py                    # init, validate-scope, scan, list-plugins, analyze-cdr, analyze-pcap
│   ├── core/
│   │   ├── authorization.py      # Authorization/Scope/Window — the scope gate's data model + REQUIRED_INVITE_ACKNOWLEDGMENT
│   │   ├── engagement.py         # Engagement — ties Authorization + audit log together, 3-tier confirmation
│   │   ├── audit_log.py          # hash-chained, append-only audit log
│   │   ├── rate_limit.py         # conservative SIP-specific rate budget defaults
│   │   ├── sip.py                # raw SIP (RFC 3261) message construction/parsing/transport
│   │   ├── sip_message.py        # general SIP message parsing (requests + responses) for captured traffic
│   │   ├── invite_probe.py       # real INVITE probing with immediate cancel/ack-bye — the safety-critical core
│   │   ├── sdp.py                # minimal SDP (RFC 4566/4568) construction/parsing for SRTP checking
│   │   ├── cdr.py                # Asterisk CDR CSV parsing
│   │   ├── pcap_parser.py        # pcap → SIP call session reconstruction → CDRRecord
│   │   └── models.py             # Finding, Severity, ModuleResult
│   ├── plugins/
│   │   ├── base.py               # BasePlugin — every plugin's scan() must call authorize_action()
│   │   ├── pbx_fingerprint.py
│   │   ├── register_exposed.py
│   │   ├── transport_security.py
│   │   ├── toll_fraud_exposure.py    # invite tier — live dialplan-routing exposure check
│   │   └── srtp_check.py             # invite tier — differential SRTP-vs-plain-RTP media check
│   ├── analyzers/
│   │   └── toll_fraud.py         # CDR-based toll-fraud pattern detection (no Engagement gate — file-only)
│   └── reports/
│       └── terminal.py           # Rich-based terminal output
├── tests/
│   ├── fixtures/mock_pbx/server.py            # a real UDP+TCP+TLS SIP server, for tests only
│   ├── fixtures/mock_pbx/invite_responder.py  # a real, configurable/offer-aware INVITE responder, for tests only
│   ├── fixtures/cdr/sample_master.csv
│   ├── test_voipaudit.py
│   ├── test_toll_fraud.py
│   ├── test_pcap_analysis.py     # pcap files generated programmatically via scapy within the tests
│   ├── test_invite_probe.py      # the invite-tier safety infrastructure — tested most thoroughly of all
│   └── test_srtp_check.py        # SDP construction/parsing + the differential SRTP check
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
