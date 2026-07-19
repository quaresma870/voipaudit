from __future__ import annotations

import datetime
from pathlib import Path

import pytest

from tests.fixtures.mock_pbx.server import start_mock_pbx
from voipaudit.core.authorization import (
    AuthorizationError,
    load_authorization,
)
from voipaudit.core.engagement import (
    ActiveTierNotConfirmed,
    Engagement,
    ScopeViolation,
)
from voipaudit.core.sip import (
    SipTimeout,
    build_options_request,
    build_register_request,
    parse_sip_response,
    send_sip_request,
)


def _write_auth_yaml(path: Path, **overrides) -> None:
    now = datetime.datetime.now(datetime.UTC)
    defaults = {
        "engagement_id": "test-2026-q1",
        "authorized_by": "Jane Doe",
        "authorized_contact_email": "jane@example.com",
        "client": "Example Corp",
        "scope": {
            "targets": ["127.0.0.1"],
            "excluded_targets": [],
            "allowed_categories": ["recon", "active"],
        },
        "window": {
            "start": (now - datetime.timedelta(hours=1)).isoformat(),
            "end": (now + datetime.timedelta(days=1)).isoformat(),
        },
        "confirmation_phrase": "I confirm authorization for test-2026-q1",
    }
    defaults.update(overrides)
    import yaml
    path.write_text(yaml.safe_dump(defaults))


class TestSipProtocol:
    """Unit tests for raw SIP message construction and parsing —
    isolated from any network I/O."""

    def test_build_options_request_is_well_formed(self):
        req = build_options_request("target.example", 5060, "127.0.0.1", 5061)
        text = req.decode()
        assert text.startswith("OPTIONS sip:target.example:5060 SIP/2.0\r\n")
        assert "Via: SIP/2.0/UDP 127.0.0.1:5061;branch=z9hG4bK" in text
        assert "Max-Forwards: 70" in text
        assert text.endswith("\r\n\r\n")

    def test_build_register_request_has_expires_zero_by_default(self):
        req = build_register_request("target.example", 5060, "127.0.0.1", 5061)
        text = req.decode()
        assert text.startswith("REGISTER sip:target.example:5060 SIP/2.0\r\n")
        assert "Expires: 0" in text
        # No Authorization header at all — this is the whole point of the probe
        assert "Authorization:" not in text

    def test_branch_has_rfc3261_magic_cookie(self):
        req = build_options_request("t", 5060, "127.0.0.1", 0)
        assert "branch=z9hG4bK" in req.decode()

    def test_parse_sip_response_status_line(self):
        raw = b"SIP/2.0 200 OK\r\nServer: Asterisk PBX 18.9.0\r\nContent-Length: 0\r\n\r\n"
        msg = parse_sip_response(raw)
        assert msg.status_code == 200
        assert msg.reason_phrase == "OK"
        assert msg.header("server") == "Asterisk PBX 18.9.0"

    def test_parse_sip_response_header_lookup_is_case_insensitive(self):
        raw = b"SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"x\"\r\n\r\n"
        msg = parse_sip_response(raw)
        assert msg.header("WWW-Authenticate") == 'Digest realm="x"'
        assert msg.header("www-authenticate") == 'Digest realm="x"'

    def test_parse_sip_response_rejects_non_sip_data(self):
        with pytest.raises(ValueError):
            parse_sip_response(b"HTTP/1.1 200 OK\r\n\r\n")

    def test_send_sip_request_real_udp_round_trip(self):
        """A real UDP socket round trip against the real mock PBX —
        not a mock of the transport layer itself."""
        server = start_mock_pbx(server_header="TestPBX/1.0")
        try:
            req = build_options_request("127.0.0.1", server.port, "127.0.0.1", 0)
            resp = send_sip_request(req, "127.0.0.1", server.port, timeout=2.0)
            assert resp.status_code == 200
            assert resp.header("server") == "TestPBX/1.0"
        finally:
            server.stop()

    def test_send_sip_request_times_out_against_a_silent_port(self):
        """A real timeout against a genuinely non-responsive UDP port —
        confirms SipTimeout fires for real, not just in theory."""
        import socket
        # Bind a UDP socket that never sends a response, to get a real,
        # guaranteed-silent port (more reliable than assuming a random
        # high port is closed).
        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(("127.0.0.1", 0))
        port = silent.getsockname()[1]
        try:
            req = build_options_request("127.0.0.1", port, "127.0.0.1", 0)
            with pytest.raises(SipTimeout):
                send_sip_request(req, "127.0.0.1", port, timeout=0.5)
        finally:
            silent.close()

    def test_via_header_transport_token_matches_requested_transport(self):
        """RFC 3261 §18.2.2: the Via header's transport token must
        reflect the transport actually used — a real, meaningful
        protocol detail some SBC/PBX implementations validate, not
        arbitrary decoration."""
        udp_req = build_options_request("t", 5060, "127.0.0.1", 0, transport="udp")
        tcp_req = build_options_request("t", 5060, "127.0.0.1", 0, transport="tcp")
        assert "SIP/2.0/UDP" in udp_req.decode()
        assert "SIP/2.0/TCP" in tcp_req.decode()

    def test_invalid_transport_rejected(self):
        with pytest.raises(ValueError, match="Unsupported transport"):
            build_options_request("t", 5060, "127.0.0.1", 0, transport="sctp")

    def test_send_sip_request_real_tcp_round_trip(self):
        """A real TCP connection, real stream framing, against the
        real mock PBX's TCP listener — not a mock of the transport
        layer itself."""
        server = start_mock_pbx(server_header="TestPBX/1.0")
        try:
            req = build_options_request("127.0.0.1", server.tcp_port, "127.0.0.1", 0, transport="tcp")
            resp = send_sip_request(req, "127.0.0.1", server.tcp_port, timeout=3.0, transport="tcp")
            assert resp.status_code == 200
            assert resp.header("server") == "TestPBX/1.0"
        finally:
            server.stop()

    def test_tcp_connection_refused_raises_sip_timeout(self):
        """A real TCP RST from a genuinely closed port — confirmed
        distinct from a UDP timeout in the message text, but folded
        into the same SipTimeout exception type so callers only need
        one except clause for 'no SIP response obtained'."""
        import socket

        closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()  # closed immediately — guarantees nothing is listening

        req = build_options_request("127.0.0.1", port, "127.0.0.1", 0, transport="tcp")
        with pytest.raises(SipTimeout, match="[Cc]onnect"):
            send_sip_request(req, "127.0.0.1", port, timeout=2.0, transport="tcp")

    def test_tcp_response_with_body_framed_correctly(self):
        """Confirms _read_sip_message correctly reads exactly
        Content-Length body bytes, not just up to the header
        terminator — sent directly over a raw socket (bypassing the
        mock PBX, which never sends a body) since this is specifically
        testing the client's stream-framing logic against a
        deliberately crafted response."""
        import socket
        import threading

        body = b'{"ok": true}'
        response = (
            b"SIP/2.0 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve_one():
            conn, _ = listener.accept()
            conn.recv(4096)  # discard the request
            conn.sendall(response)
            conn.close()

        thread = threading.Thread(target=serve_one, daemon=True)
        thread.start()

        req = build_options_request("127.0.0.1", port, "127.0.0.1", 0, transport="tcp")
        try:
            resp = send_sip_request(req, "127.0.0.1", port, timeout=3.0, transport="tcp")
            assert resp.status_code == 200
            assert resp.raw.endswith(body.decode())
        finally:
            listener.close()
            thread.join(timeout=2.0)


class TestDualTransportPlugins:
    """Confirms both plugins work correctly over TCP too, not just the
    UDP path already covered by TestPBXFingerprintPlugin/
    TestRegisterExposedPlugin — a real TCP round trip against the real
    mock PBX's TCP listener for each."""

    def _engagement(self, tmp_path) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        eng = Engagement.load(path, tmp_path / "test.audit.jsonl")
        eng.confirm_active_tier("test-2026-q1")
        return eng

    def test_pbx_fingerprint_over_tcp(self, tmp_path):
        from voipaudit.plugins.pbx_fingerprint import PBXFingerprintModule

        server = start_mock_pbx(server_header="Kamailio SIP Server 5.7")
        try:
            eng = self._engagement(tmp_path)
            result = PBXFingerprintModule(eng, timeout=3.0, transport="tcp").run(
                f"127.0.0.1:{server.tcp_port}"
            )
            assert result.error is None
            assert "Kamailio" in result.findings[0].title
        finally:
            server.stop()

    def test_register_exposed_over_tcp_detects_vulnerable_pbx(self, tmp_path):
        from voipaudit.plugins.register_exposed import RegisterExposedModule

        server = start_mock_pbx(accept_unauthenticated_register=True)
        try:
            eng = self._engagement(tmp_path)
            result = RegisterExposedModule(eng, timeout=3.0, transport="tcp").run(
                f"127.0.0.1:{server.tcp_port}"
            )
            assert result.error is None
            assert result.findings[0].severity.value == "CRITICAL"
        finally:
            server.stop()


class TestAuthorization:
    def test_valid_file_loads(self, tmp_path):
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        auth = load_authorization(path)
        assert auth.engagement_id == "test-2026-q1"
        assert auth.is_within_window()

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(AuthorizationError, match="not found"):
            load_authorization(tmp_path / "nope.yml")

    def test_missing_required_field_raises(self, tmp_path):
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path, client="")
        with pytest.raises(AuthorizationError, match="client"):
            load_authorization(path)

    def test_window_end_before_start_raises(self, tmp_path):
        now = datetime.datetime.now(datetime.UTC)
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path, window={
            "start": now.isoformat(),
            "end": (now - datetime.timedelta(days=1)).isoformat(),
        })
        with pytest.raises(AuthorizationError, match="window.end"):
            load_authorization(path)

    @pytest.mark.parametrize("target,in_scope", [
        ("127.0.0.1", True),
        ("127.0.0.1:5060", True),          # host:port form
        ("sip:127.0.0.1:5060", True),      # sip: URI form
        ("sip:ext100@127.0.0.1", True),    # sip: URI with user part
        ("10.0.0.5", False),
    ])
    def test_scope_matching_handles_sip_uri_forms(self, tmp_path, target, in_scope):
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        auth = load_authorization(path)
        assert auth.is_in_scope(target) is in_scope

    def test_cidr_scope_matching(self, tmp_path):
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path, scope={
            "targets": ["203.0.113.0/24"], "excluded_targets": [], "allowed_categories": ["recon"],
        })
        auth = load_authorization(path)
        assert auth.is_in_scope("203.0.113.55:5060") is True
        assert auth.is_in_scope("203.0.114.55:5060") is False

    def test_exclusion_wins_over_inclusion(self, tmp_path):
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path, scope={
            "targets": ["203.0.113.0/24"], "excluded_targets": ["203.0.113.99"],
            "allowed_categories": ["recon"],
        })
        auth = load_authorization(path)
        assert auth.is_in_scope("203.0.113.99:5060") is False
        assert auth.is_in_scope("203.0.113.5:5060") is True


class TestEngagementGate:
    def _engagement(self, tmp_path, **overrides) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path, **overrides)
        return Engagement.load(path, tmp_path / "test.audit.jsonl")

    def test_in_scope_recon_action_allowed(self, tmp_path):
        eng = self._engagement(tmp_path)
        eng.authorize_action("pbx_fingerprint", "127.0.0.1", "sip_options_ping", category="recon")
        # no exception = allowed

    def test_out_of_scope_target_refused(self, tmp_path):
        eng = self._engagement(tmp_path)
        with pytest.raises(ScopeViolation, match="scope"):
            eng.authorize_action("pbx_fingerprint", "10.0.0.99", "sip_options_ping", category="recon")

    def test_active_category_refused_without_confirm(self, tmp_path):
        eng = self._engagement(tmp_path)
        with pytest.raises(ScopeViolation, match="not confirmed"):
            eng.authorize_action("register_exposed", "127.0.0.1", "sip_register_probe", category="active")

    def test_active_category_allowed_after_confirm(self, tmp_path):
        eng = self._engagement(tmp_path)
        eng.confirm_active_tier("test-2026-q1")
        eng.authorize_action("register_exposed", "127.0.0.1", "sip_register_probe", category="active")

    def test_confirm_wrong_engagement_id_refused(self, tmp_path):
        eng = self._engagement(tmp_path)
        with pytest.raises(ActiveTierNotConfirmed, match="does not match"):
            eng.confirm_active_tier("wrong-id")

    def test_confirm_when_active_not_in_allowed_categories_refused(self, tmp_path):
        eng = self._engagement(tmp_path, scope={
            "targets": ["127.0.0.1"], "excluded_targets": [], "allowed_categories": ["recon"],
        })
        with pytest.raises(ActiveTierNotConfirmed, match="allowed_categories"):
            eng.confirm_active_tier("test-2026-q1")

    def test_every_action_is_audit_logged(self, tmp_path):
        eng = self._engagement(tmp_path)
        eng.authorize_action("pbx_fingerprint", "127.0.0.1", "sip_options_ping", category="recon")
        try:
            eng.authorize_action("x", "10.0.0.99", "y", category="recon")
        except ScopeViolation:
            pass
        entries = eng.audit_log.read_all()
        assert len(entries) == 2
        assert entries[0]["allowed"] is True
        assert entries[1]["allowed"] is False

    def test_audit_log_integrity_holds(self, tmp_path):
        from voipaudit.core.audit_log import verify_log_integrity

        eng = self._engagement(tmp_path)
        eng.authorize_action("pbx_fingerprint", "127.0.0.1", "sip_options_ping", category="recon")
        valid, broken_line, entry_count = verify_log_integrity(tmp_path / "test.audit.jsonl")
        assert valid is True
        assert entry_count == 1


class TestPBXFingerprintPlugin:
    """Tested against the real mock PBX over a real UDP socket."""

    def _engagement(self, tmp_path) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        return Engagement.load(path, tmp_path / "test.audit.jsonl")

    def test_identifies_known_pbx_signature(self, tmp_path):
        from voipaudit.plugins.pbx_fingerprint import PBXFingerprintModule

        server = start_mock_pbx(server_header="Asterisk PBX 18.9.0")
        try:
            eng = self._engagement(tmp_path)
            result = PBXFingerprintModule(eng, timeout=2.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert len(result.findings) == 1
            assert "Asterisk" in result.findings[0].title
            assert result.findings[0].severity.value == "INFO"
        finally:
            server.stop()

    def test_unrecognized_signature_reported_without_crashing(self, tmp_path):
        from voipaudit.plugins.pbx_fingerprint import PBXFingerprintModule

        server = start_mock_pbx(server_header="TotallyMadeUpPBX/9.9")
        try:
            eng = self._engagement(tmp_path)
            result = PBXFingerprintModule(eng, timeout=2.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert "unrecognized" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_no_response_reported_as_info_not_error(self, tmp_path):
        import socket

        from voipaudit.plugins.pbx_fingerprint import PBXFingerprintModule

        silent = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        silent.bind(("127.0.0.1", 0))
        port = silent.getsockname()[1]
        try:
            eng = self._engagement(tmp_path)
            result = PBXFingerprintModule(eng, timeout=0.5).run(f"127.0.0.1:{port}")
            assert result.error is None
            assert "No SIP response" in result.findings[0].title
        finally:
            silent.close()

    def test_out_of_scope_target_produces_module_error_not_crash(self, tmp_path):
        from voipaudit.plugins.pbx_fingerprint import PBXFingerprintModule

        eng = self._engagement(tmp_path)
        result = PBXFingerprintModule(eng, timeout=2.0).run("10.0.0.99:5060")
        assert result.error is not None
        assert "scope" in result.error.lower()


class TestRegisterExposedPlugin:
    """Tested against the real mock PBX in both its secure and
    vulnerable configurations, over a real UDP socket."""

    def _engagement(self, tmp_path) -> Engagement:
        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        eng = Engagement.load(path, tmp_path / "test.audit.jsonl")
        eng.confirm_active_tier("test-2026-q1")
        return eng

    def test_detects_unauthenticated_register_accepted(self, tmp_path):
        from voipaudit.plugins.register_exposed import RegisterExposedModule

        server = start_mock_pbx(accept_unauthenticated_register=True)
        try:
            eng = self._engagement(tmp_path)
            result = RegisterExposedModule(eng, timeout=2.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert len(result.findings) == 1
            assert result.findings[0].severity.value == "CRITICAL"
            assert "accepted" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_correctly_configured_pbx_reports_info_not_critical(self, tmp_path):
        """Regression-style test confirming no false positive: a
        securely configured PBX (challenges with 401) must NOT be
        reported as vulnerable."""
        from voipaudit.plugins.register_exposed import RegisterExposedModule

        server = start_mock_pbx(accept_unauthenticated_register=False)
        try:
            eng = self._engagement(tmp_path)
            result = RegisterExposedModule(eng, timeout=2.0).run(f"127.0.0.1:{server.port}")
            assert result.error is None
            assert result.findings[0].severity.value == "INFO"
            assert "correctly requires" in result.findings[0].title.lower()
        finally:
            server.stop()

    def test_active_tier_gate_actually_enforced_by_this_plugin(self, tmp_path):
        """Confirms the plugin itself calls authorize_action with
        category='active' — not just that Engagement's gate works in
        isolation (already covered by TestEngagementGate)."""
        from voipaudit.plugins.register_exposed import RegisterExposedModule

        path = tmp_path / "authorization.yml"
        _write_auth_yaml(path)
        eng = Engagement.load(path, tmp_path / "test.audit.jsonl")
        # deliberately NOT calling confirm_active_tier()
        result = RegisterExposedModule(eng, timeout=2.0).run("127.0.0.1:5060")
        assert result.error is not None
        assert "not confirmed" in result.error.lower()
