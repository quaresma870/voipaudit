# Roadmap

This tracks what's shipped and what's planned for `voipaudit`. Order
reflects current priority, not a fixed release schedule — priorities may
shift based on what turns out to matter most in practice.

## Shipped

### v0.1.0
- Authorization/scope model, active-tier confirmation gate, hash-chained
  tamper-evident audit log (adapted from the sibling redteam-toolkit and
  secureaudit repos' already-audited patterns).
- Raw SIP (RFC 3261) protocol layer — UDP, TCP, and TLS transports, all
  three tested against a real mock SIP server over real sockets.
- `pbx_fingerprint` (recon) — SIP OPTIONS-based PBX/SIP-stack identification.
- `register_exposed` (active, requires `--confirm`) — detects PBX/SBC
  targets that incorrectly accept an unauthenticated SIP REGISTER.
- `transport_security` (recon) — TLS availability, certificate expiry
  (a real, deliberately-expired certificate is used to test the CRITICAL
  detection path — not a mocked date), and whether plaintext SIP is still
  accepted alongside TLS.
- CI: builds the real wheel, installs it in a clean venv, and runs every
  documented command against a real mock SIP server for all three
  transports.

## Next

### Toll fraud — two distinct features, deliberately split
"Toll fraud detection" turned out to mean two genuinely different things,
worth building as separate, differently-shaped features rather than one:

- **CDR/log analysis** (input: a call-detail-record export, e.g.
  Asterisk's own CDR CSV format) — parses real call records and flags
  patterns indicative of fraud already having occurred: bursts of calls
  to high-cost international destinations, unusual-hour call volume,
  rapid repeated short calls from one extension. This is a file-analysis
  feature, not a live network probe — no Authorization/Engagement gate
  needed the way live scanning modules require, since there's no live
  target being touched.
- **Live exposure check** (a `toll_fraud_exposure`-style recon module) —
  checks whether the PBX's *current configuration* would even allow toll
  fraud to happen, independent of whether it already has. Likely needs
  real INVITE-based call-setup testing to check dialplan permissiveness
  toward expensive destinations, which is a materially higher-risk,
  active-tier probe than anything shipped so far (a real INVITE can
  actually ring a phone or incur cost) — needs careful, conservative
  design before this ships, not a quick add.

### SRTP media encryption checks
`transport_security` covers *signalling* encryption (TLS/SIPS). Media
(RTP) encryption is a separate concern — checking whether a PBX offers or
requires SRTP (vs plaintext RTP) needs inspecting the SDP body of a real
call-setup exchange, which (like the live toll-fraud exposure check
above) means actually attempting a call, not just an OPTIONS ping. Likely
built alongside or shortly after the live toll-fraud exposure module,
since both need the same underlying "safely attempt a real INVITE"
groundwork.

### More PBX fingerprint signatures
`pbx_fingerprint`'s signature list is a reasonable starting set, not
exhaustive. Extend as real-world Server/User-Agent strings turn up that
aren't recognized yet.

### Persistence + dashboard
A `--db` flag to persist scan results (matching the sibling
secureaudit/redteam-toolkit/loganalyzer repos' own SQLite-backed history
pattern) and a read-only web dashboard to browse past engagements.

### Longer term: INVITE-spoofing tests
Testing whether Caller-ID / From-header spoofing is accepted — a real,
active-tier, higher-risk probe needing the same careful design
consideration as the live toll-fraud and SRTP checks above.
