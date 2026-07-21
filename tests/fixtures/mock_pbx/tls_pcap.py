"""
Builds a real TLS 1.2 session (a real client and a real server, both
using Python's own ssl module and the same checked-in test certificate
as tests/fixtures/mock_pbx/server.py/invite_responder.py) into a real
pcap + SSLKEYLOGFILE pair, for testing core/pcap_parser.py's TLS
decryption path -- FOR TESTS ONLY.

Matches this project's own established "test against a real protocol
implementation, not a mock/assumption" precedent (see
tests/fixtures/mock_pbx/server.py's own docstring, and
tests/test_pcap_tcp.py's real scapy-crafted TCP captures): the TLS
ciphertext turned into pcap packets here is genuinely produced by a
real TLS handshake and real AEAD encryption, not hand-approximated.

A local, single-use TCP proxy sits between the real client and real
server so every byte actually placed on the wire in each direction can
be captured, in true chronological order across both directions
(needed for correct record-level reassembly -- see
core/pcap_parser.py's own _decrypt_tls_flow), and turned into a real
scapy Ether/IP/TCP packet.
"""

from __future__ import annotations

import socket
import ssl
import threading
from pathlib import Path

_CERTS_DIR = Path(__file__).parent / "certs"


def capture_tls12_pcap(
    tmp_path: Path,
    exchanges: list[tuple[bytes, bytes]],
    split_client_record_index: int | None = None,
) -> tuple[Path, Path]:
    """exchanges is a list of (client_sends, server_responds) byte
    pairs, sent in order over ONE real TLS 1.2 connection (e.g.
    [(INVITE, RESP_180), (BYE, RESP_200)]).

    split_client_record_index, if given, splits the Nth client->server
    application-data TLS record (0-indexed, counting only
    post-handshake records -- i.e. index 0 is the first real
    application message sent) across two separate packets, to exercise
    core/pcap_parser.py's own TLS-record reassembly logic (mirroring
    test_pcap_tcp.py's existing "message split across segments" test
    for plain TCP).

    Returns (pcap_path, keylog_path), both real files under tmp_path.
    Give a distinct tmp_path per call (e.g. tmp_path / "session_a") when
    a test needs more than one independent session, since the pcap and
    keylog filenames are fixed within a given tmp_path.
    """
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("127.0.0.1", 0))
    srv_sock.listen(1)
    real_port = srv_sock.getsockname()[1]

    ctx_s = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx_s.load_cert_chain(certfile=str(_CERTS_DIR / "cert.pem"), keyfile=str(_CERTS_DIR / "key.pem"))
    ctx_s.maximum_version = ssl.TLSVersion.TLSv1_2

    server_done = threading.Event()
    server_error: list[Exception] = []

    def server_thread() -> None:
        try:
            conn, _addr = srv_sock.accept()
            tls_conn = ctx_s.wrap_socket(conn, server_side=True)
            tls_conn.settimeout(5.0)
            for client_sends, server_responds in exchanges:
                received = tls_conn.recv(65535)
                if received != client_sends:
                    raise AssertionError(f"expected {client_sends!r}, got {received!r}")
                tls_conn.sendall(server_responds)
            tls_conn.close()
        except Exception as exc:  # noqa: BLE001 -- surfaced via server_error to the test thread
            server_error.append(exc)
        finally:
            server_done.set()

    th = threading.Thread(target=server_thread, daemon=True)
    th.start()

    # A logging TCP proxy between the real client and real server --
    # this is what lets us capture every byte actually placed on the
    # wire, in a single global chronological order across both
    # directions, without needing OS-level packet capture permissions.
    proxy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_sock.bind(("127.0.0.1", 0))
    proxy_sock.listen(1)
    proxy_port = proxy_sock.getsockname()[1]

    events: list[tuple[int, str, bytes]] = []
    events_lock = threading.Lock()
    counter = [0]

    def log_event(direction: str, data: bytes) -> None:
        with events_lock:
            counter[0] += 1
            events.append((counter[0], direction, data))

    def proxy_thread() -> None:
        client_conn, _addr = proxy_sock.accept()
        upstream = socket.create_connection(("127.0.0.1", real_port))

        def pump(src: socket.socket, dst: socket.socket, direction: str) -> None:
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    log_event(direction, data)
                    dst.sendall(data)
            except OSError:
                pass

        t1 = threading.Thread(target=pump, args=(client_conn, upstream, "c2s"), daemon=True)
        t2 = threading.Thread(target=pump, args=(upstream, client_conn, "s2c"), daemon=True)
        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

    pth = threading.Thread(target=proxy_thread, daemon=True)
    pth.start()

    keylog_path = tmp_path / "keylog.txt"
    ctx_c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx_c.check_hostname = False
    ctx_c.verify_mode = ssl.CERT_NONE
    ctx_c.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx_c.keylog_filename = str(keylog_path)

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls_sock = ctx_c.wrap_socket(raw_sock, server_hostname="127.0.0.1")
    tls_sock.connect(("127.0.0.1", proxy_port))
    for client_sends, server_responds in exchanges:
        tls_sock.sendall(client_sends)
        received = tls_sock.recv(65535)
        if received != server_responds:
            raise AssertionError(f"expected {server_responds!r}, got {received!r}")
    tls_sock.close()

    server_done.wait(timeout=5)
    th.join(timeout=5)
    pth.join(timeout=5)
    if server_error:
        raise server_error[0]

    events.sort(key=lambda e: e[0])

    from scapy.all import IP, TCP, Ether, wrpcap

    pkts = []
    cseq, sseq = 1000, 5000
    cport = 44444
    client_app_data_index = 0
    for _seq, direction, data in events:
        if direction == "c2s":
            # A handshake record's first byte is a real TLS content
            # type (0x16 handshake, 0x14 change_cipher_spec) -- real
            # post-handshake application data always starts 0x17.
            is_app_data = data[:1] == b"\x17"
            if is_app_data and split_client_record_index == client_app_data_index:
                mid = len(data) // 2
                part1, part2 = data[:mid], data[mid:]
                pkts.append(Ether() / IP(src="127.0.0.1", dst="127.0.0.1") /
                            TCP(sport=cport, dport=proxy_port, seq=cseq, ack=sseq, flags="PA") / part1)
                cseq += len(part1)
                pkts.append(Ether() / IP(src="127.0.0.1", dst="127.0.0.1") /
                            TCP(sport=cport, dport=proxy_port, seq=cseq, ack=sseq, flags="PA") / part2)
                cseq += len(part2)
            else:
                pkts.append(Ether() / IP(src="127.0.0.1", dst="127.0.0.1") /
                            TCP(sport=cport, dport=proxy_port, seq=cseq, ack=sseq, flags="PA") / data)
                cseq += len(data)
            if is_app_data:
                client_app_data_index += 1
        else:
            pkts.append(Ether() / IP(src="127.0.0.1", dst="127.0.0.1") /
                        TCP(sport=proxy_port, dport=cport, seq=sseq, ack=cseq, flags="PA") / data)
            sseq += len(data)

    pcap_path = tmp_path / "capture.pcap"
    wrpcap(str(pcap_path), pkts)
    return pcap_path, keylog_path
