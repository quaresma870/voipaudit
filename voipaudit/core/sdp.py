"""
Minimal SDP (Session Description Protocol, RFC 4566) construction and
parsing — deliberately just enough to build a real audio media offer
and inspect an answer's negotiated transport, not a general-purpose
SDP library. Used specifically to check whether a target negotiates
SRTP (RTP/SAVP, RFC 3711) vs plain RTP (RTP/AVP) when offered, and
whether the offered crypto (RFC 4568 SDES `a=crypto:` attribute) is
actually present.

RTP/AVP (plain RTP) vs RTP/SAVP (Secure Audio Video Profile, i.e.
SRTP) is the media-line transport token in the `m=` line — the actual
security-relevant signal for this check, alongside the presence of a
matching `a=crypto:` line describing the real key/cipher parameters.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

# RFC 4568 §6.1 defines several standard crypto-suite names; this is
# the one most universally supported (AES-128 in counter mode with a
# full-length 80-bit HMAC-SHA1 authentication tag) and the one most
# real SRTP-capable PBX/SBC implementations offer by default when
# asked for anything at all.
_DEFAULT_CRYPTO_SUITE = "AES_CM_128_HMAC_SHA1_80"


def _gen_srtp_key_material() -> str:
    """A syntactically valid base64 SRTP master key+salt for the
    'inline:' key method (RFC 4568 §6.2) — 30 bytes (16-byte master
    key + 14-byte salt, the standard AES_CM_128_HMAC_SHA1_80 sizing),
    base64-encoded. This is a throwaway key generated fresh for a
    single probe that's cancelled within a second or two — never
    reused, never intended to actually protect real media, since no
    real media is ever exchanged over this probe at all."""
    import base64
    return base64.b64encode(secrets.token_bytes(30)).decode()


def build_audio_offer_sdp(
    local_host: str, rtp_port: int, transport: str = "RTP/SAVP",
    crypto_suite: str = _DEFAULT_CRYPTO_SUITE,
) -> str:
    """Builds a minimal, real, valid SDP offer for a single audio
    media stream. transport='RTP/SAVP' offers SRTP only (with a real
    crypto attribute) — the target must either answer with matching
    SRTP parameters or reject the offer, since there's no plain-RTP
    fallback in this offer at all, making the response unambiguous
    evidence of SRTP support. transport='RTP/AVP' offers plain RTP
    only, the control case for checking whether plaintext is ALSO
    still accepted (mirroring transport_security's own
    plaintext-alongside-TLS check, applied to media instead of
    signalling)."""
    lines = [
        "v=0",
        f"o=voipaudit {secrets.randbits(31)} {secrets.randbits(31)} IN IP4 {local_host}",
        "s=-",
        f"c=IN IP4 {local_host}",
        "t=0 0",
        f"m=audio {rtp_port} {transport} 0",
        "a=rtpmap:0 PCMU/8000",
    ]
    if transport == "RTP/SAVP":
        key = _gen_srtp_key_material()
        lines.append(f"a=crypto:1 {crypto_suite} inline:{key}")
    return "\r\n".join(lines) + "\r\n"


@dataclass
class SDPMediaInfo:
    media_type: str | None = None       # e.g. "audio"
    transport: str | None = None        # "RTP/AVP" or "RTP/SAVP" (or another token verbatim)
    crypto_suites_offered: list[str] = field(default_factory=list)

    @property
    def is_srtp(self) -> bool:
        return self.transport is not None and "SAVP" in self.transport

    @property
    def has_crypto_attribute(self) -> bool:
        return bool(self.crypto_suites_offered)


def parse_sdp(body: str) -> SDPMediaInfo:
    """Extracts just the first media (`m=`) line's type/transport and
    every `a=crypto:` line's suite name — deliberately not a full SDP
    parser (no session-level attribute parsing, no multi-media-stream
    handling), since this is the only information any check in this
    toolkit currently needs."""
    info = SDPMediaInfo()
    for line in body.replace("\r\n", "\n").split("\n"):
        line = line.strip()
        if line.startswith("m=") and info.media_type is None:
            parts = line[2:].split()
            if len(parts) >= 3:
                info.media_type = parts[0]
                info.transport = parts[2]
        elif line.startswith("a=crypto:"):
            parts = line[len("a=crypto:"):].split()
            if len(parts) >= 2:
                info.crypto_suites_offered.append(parts[1])
    return info
