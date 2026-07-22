"""
Tests for core/transfer_confirm.py's TransferCallbackListener — a
single-shot SIP UAS used only by refer_transfer_abuse's optional
--confirm-transfer-reachable mode, tested over real UDP/TCP/TLS
sockets (a real handshake and real ephemeral self-signed certificate
for the TLS case, not a mock of the transport layer itself).
"""

from __future__ import annotations

import socket
import ssl

from voipaudit.core.transfer_confirm import (
    TransferCallbackListener,
    detect_local_ip_for_target,
    generate_callback_token,
)


def _build_invite(token: str, host: str, port: int, transport: str) -> bytes:
    return (
        f"INVITE sip:{token}@{host}:{port} SIP/2.0\r\n"
        f"Via: SIP/2.0/{transport.upper()} {host}:9999;branch=z9hG4bKtest\r\n"
        f"From: <sip:pbx@{host}>;tag=abc\r\n"
        f"To: <sip:{token}@{host}>\r\n"
        f"Call-ID: transfercallback@test\r\n"
        "CSeq: 1 INVITE\r\n"
        f"Contact: <sip:pbx@{host}:9999>\r\n"
        "User-Agent: TestPBX/1.0\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode()


class TestTransferCallbackListener:
    def test_udp_receives_and_declines(self):
        token = generate_callback_token()
        with TransferCallbackListener("127.0.0.1", 0, "udp", token, timeout=3.0) as listener:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(_build_invite(token, "127.0.0.1", listener.port, "udp"), ("127.0.0.1", listener.port))
                sock.settimeout(2.0)
                resp, _ = sock.recvfrom(65535)
            finally:
                sock.close()
        assert resp.startswith(b"SIP/2.0 603 Decline")
        assert listener.result.received is True
        assert listener.result.user_agent == "TestPBX/1.0"
        assert "pbx@127.0.0.1" in listener.result.from_header

    def test_tcp_receives_and_declines(self):
        token = generate_callback_token()
        with TransferCallbackListener("127.0.0.1", 0, "tcp", token, timeout=3.0) as listener:
            sock = socket.create_connection(("127.0.0.1", listener.port), timeout=2.0)
            try:
                sock.sendall(_build_invite(token, "127.0.0.1", listener.port, "tcp"))
                resp = sock.recv(65535)
            finally:
                sock.close()
        assert resp.startswith(b"SIP/2.0 603 Decline")
        assert listener.result.received is True

    def test_tls_receives_and_declines(self):
        """Confirms the ephemeral self-signed certificate is generated
        and actually usable for a real TLS handshake -- not just that
        the generation code runs without raising."""
        token = generate_callback_token()
        with TransferCallbackListener("127.0.0.1", 0, "tls", token, timeout=3.0) as listener:
            raw = socket.create_connection(("127.0.0.1", listener.port), timeout=2.0)
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_sock = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
            try:
                tls_sock.sendall(_build_invite(token, "127.0.0.1", listener.port, "tls"))
                resp = tls_sock.recv(65535)
            finally:
                tls_sock.close()
        assert resp.startswith(b"SIP/2.0 603 Decline")
        assert listener.result.received is True

    def test_non_matching_token_ignored_within_timeout(self):
        """A request with the WRONG token must not be treated as the
        expected callback -- confirms real correlation, not "anything
        that arrives counts"."""
        token = generate_callback_token()
        with TransferCallbackListener("127.0.0.1", 0, "udp", token, timeout=1.0) as listener:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.sendto(
                    _build_invite("some-other-token", "127.0.0.1", listener.port, "udp"),
                    ("127.0.0.1", listener.port),
                )
            finally:
                sock.close()
        assert listener.result.received is False

    def test_timeout_with_nothing_received(self):
        token = generate_callback_token()
        with TransferCallbackListener("127.0.0.1", 0, "udp", token, timeout=0.5) as listener:
            pass
        assert listener.result.received is False


class TestDetectLocalIpForTarget:
    def test_returns_a_valid_ipv4_address_for_loopback(self):
        ip = detect_local_ip_for_target("127.0.0.1", 5060)
        assert ip  # non-empty
        parts = ip.split(".")
        assert len(parts) == 4
        assert all(p.isdigit() for p in parts)
