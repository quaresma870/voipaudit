# Changelog

All notable changes to this project are documented here. See the
[README](README.md) for current features and usage.

### v0.1.0
- feat: **initial release** — `voipaudit`, an authorized SIP/VoIP security auditing CLI.
  Authorization/scope model, active-tier confirmation gate, and hash-chained tamper-evident
  audit logging adapted directly from the sibling redteam-toolkit and secureaudit repos'
  already-audited patterns, not reinvented.
- feat: **raw SIP (RFC 3261) protocol layer** — message construction, response parsing, and
  transport, supporting both UDP and TCP from the first release. The Via header's transport
  token correctly reflects the transport actually used (RFC 3261 §18.2.2), and TCP responses
  are framed correctly via `Content-Length` (a byte stream has no built-in message boundaries,
  unlike UDP datagrams).
- feat: **`pbx_fingerprint`** (recon tier) — SIP OPTIONS-based PBX/SIP-stack identification.
- feat: **`register_exposed`** (active tier, requires `--confirm`) — detects PBX/SBC targets
  that incorrectly accept an unauthenticated SIP REGISTER.
- test: both plugins and the full SIP protocol layer (including TCP stream framing) tested
  against a real mock SIP server over real UDP and TCP sockets — not simulated or assumed.
- feat: **CI integration test job** — builds the real wheel, installs it in a clean venv, and
  runs every documented command against a real mock SIP server, for both transports, from the
  very first commit (adopted from the start, not discovered later through an audit).
