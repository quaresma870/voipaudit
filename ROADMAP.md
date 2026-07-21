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

### v0.2.0
- `analyze-cdr` — parses a real Asterisk CDR CSV export (field order and
  format confirmed against Asterisk's own documentation and cdr_csv.c
  source, not invented) and detects three patterns indicative of toll
  fraud already having occurred:
  - Calls to known high-risk international destinations. Sourced from
    two structurally-durable categories (satellite/premium-network
    prefixes; NANP numbers formatted to look domestic but that are
    actually expensive international destinations — the classic
    Wangiri target set) plus a few illustrative, currently-documented
    examples from a real, dated fraud report. Explicitly documented as
    non-exhaustive — industry fraud reporting is clear that premium-rate
    traffic spans 200+ countries and shifts monthly.
  - Off-hours call bursts from a single extension.
  - Rapid repeated short calls from a single extension.
  File-analysis only — no Authorization/Engagement gate, since no live
  target is touched. Verified against real, hand-crafted CDR test data
  covering both the fraud patterns and ordinary business calls (to
  confirm no false positives on legitimate traffic).

### v0.3.0
- `analyze-pcap` — reconstructs SIP call sessions directly from a packet
  capture (INVITE → final response → BYE, correlated by Call-ID, using
  the same duration/billsec semantics as Asterisk's own CDR) and runs the
  exact same `analyze_toll_fraud()` used by `analyze-cdr`, with zero
  changes to that function — confirming pcap parsing is a genuine
  drop-in alternative data source, not a parallel/divergent analysis
  path. Works against effectively any SBC/PBX vendor's traffic, not just
  Asterisk, since SIP itself (not any particular CDR export format) is
  what every one of them speaks on the wire. New optional `pcap` extra
  (scapy) keeps the base install lean for users who only want live
  scanning. Only UDP SIP transport is parsed in this first version — TCP
  pcap support is a tracked gap below.
- `core/sip_message.py` — a new general-purpose SIP message parser
  (handles both requests and responses) for arbitrary captured traffic,
  deliberately kept separate from `core/sip.py`'s own SipMessage type
  (which specifically represents a response to a request this tool
  itself sent during live scanning, not arbitrary bidirectional traffic).

### v0.4.0
- `toll_fraud_exposure` — the live toll-fraud **exposure** check (as
  opposed to analyze-cdr/analyze-pcap, which detect fraud that may have
  already happened): checks whether the PBX's *current configuration*
  would even route a call toward a known high-risk destination,
  independent of whether it already has. Origin: proposed by the user
  as a natural companion to analyze-pcap while choosing priorities — a
  live-scan complement to the file-analysis-only CDR/pcap checks.
- A new, dedicated **invite tier**, deliberately sitting above
  active-tier rather than folded into it: `invite` in
  `authorization.yml`'s `allowed_categories` requires a new
  `invite_tier_acknowledgment` field containing an exact, non-
  paraphrasable acknowledgment text, `active` must ALSO be confirmed
  first every session (invite is an escalation, not an independent
  switch), and `--confirm` is still required. See
  `core/authorization.py`'s `REQUIRED_INVITE_ACKNOWLEDGMENT` and
  `core/engagement.py`'s `confirm_invite_tier`.
- `core/invite_probe.py` — real SIP INVITE probing with an immediate
  CANCEL (or ACK+BYE, for the rare instant-answer case) reflex as soon
  as any routing-indicating response arrives (180 Ringing, 183 Session
  Progress, or a 2xx), so the probe only ever needs to observe "is this
  destination routed at all," never "does the call complete." Verified
  against 5 real response scenarios (outright rejection, ringing-then-
  silence, immediate answer, trying-then-silence, total silence) against
  a real, dedicated mock INVITE responder over real UDP sockets before
  building the plugin on top of it.

### v0.5.0
- `srtp_check` (invite tier) — checks whether the target actually
  negotiates SRTP (RTP/SAVP, RFC 3711) when offered, distinct from
  `transport_security`'s existing *signalling*-encryption check
  (TLS/SIPS). Reused `core/invite_probe.py`'s safety reflex and the
  invite-tier authorization model entirely as-is, exactly as
  anticipated when that groundwork shipped in v0.4.0 — only needed
  extending `build_invite`/`safe_invite_probe` to optionally carry an
  SDP body and parse one back from the response.
- `core/sdp.py` — minimal SDP (RFC 4566) construction and parsing, just
  enough to build a real audio media offer and inspect an answer's
  negotiated transport (`RTP/AVP` vs `RTP/SAVP`) and crypto attribute
  (RFC 4568 SDES `a=crypto:`), not a general-purpose SDP library.
- **Differential test design**: a rejected SRTP-only offer alone can't
  distinguish "this target doesn't support SRTP" from "this destination
  doesn't exist/route at all." `srtp_check` sends both an SRTP-only
  offer AND a plain-RTP-only offer to the SAME destination and compares
  outcomes — if plain RTP routes but SRTP specifically doesn't, that's
  real evidence about media capability, not reachability. Verified
  against a real, offer-aware mock INVITE responder (extended to
  inspect the actual incoming SDP transport, not just which destination
  was dialed) for the differential case specifically, not just the
  "SRTP supported"/"nothing routes" cases that a fixed-response mock
  could already cover.
- Found and fixed two real bugs while wiring this in: `toll_fraud_exposure`
  had accepted a `transport` parameter that was silently never used
  (invite_probe.py is UDP-only) — removed it rather than leave
  misleading dead code; and `list-plugins` labeled every non-recon
  plugin as "active," hiding the invite-tier distinction entirely —
  fixed to show all three tiers correctly.

## Next

### TCP pcap support
`analyze-pcap` only extracts UDP payloads in this first version — the
overwhelming majority of real-world SIP trunk traffic is UDP, but a TCP
capture (or a mixed one) currently has its TCP-carried SIP messages
silently missed. TCP SIP reassembly (handling messages split or
coalesced across TCP segments, unlike UDP's one-datagram-one-message
guarantee) is a real, separate parsing problem worth its own careful
implementation, not a quick follow-on to the UDP path. The same UDP-only
limitation now also applies to `core/invite_probe.py` (and therefore
both invite-tier plugins) — TCP/TLS INVITE support is a related, but
separate, follow-on.

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
