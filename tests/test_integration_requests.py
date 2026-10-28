"""requests integration against real sockets on 127.0.0.1 (see the httpx tests)."""

from __future__ import annotations

import pytest
import requests

from ssrf_guard import (
    BlockedAddressError,
    Policy,
    RedirectSchemeError,
    UnsupportedConfigurationError,
)
from ssrf_guard.integrations.requests import SSRFGuardAdapter, guarded_session

from .conftest import LOOPBACK_POLICY, TEST_HOST, FakeResolver, Server, TLSMaterial


def test_tls_keeps_sni_host_and_cert_verification(
    https_server: Server, tls: TLSMaterial, resolver: FakeResolver
) -> None:
    with guarded_session(LOOPBACK_POLICY, resolver) as session:
        response = session.get(https_server.url("/hello"), verify=tls.ca_file, timeout=5)
    assert response.status_code == 200
    assert https_server.sni == [TEST_HOST]
    assert https_server.hosts == [f"{TEST_HOST}:{https_server.port}"]
    assert resolver.calls == [TEST_HOST]


def test_certificate_for_other_name_is_rejected(https_server: Server, tls: TLSMaterial) -> None:
    resolver = FakeResolver({"other.test": ["127.0.0.1"]})
    with (
        guarded_session(LOOPBACK_POLICY, resolver) as session,
        pytest.raises(requests.exceptions.SSLError),
    ):
        session.get(https_server.url("/", host="other.test"), verify=tls.ca_file, timeout=5)


def test_plain_http(http_server: Server, resolver: FakeResolver) -> None:
    with guarded_session(LOOPBACK_POLICY, resolver) as session:
        response = session.get(http_server.url("/"), timeout=5)
    assert response.text == f"hello from {TEST_HOST}:{http_server.port}"


def test_default_policy_blocks_loopback(http_server: Server, resolver: FakeResolver) -> None:
    with guarded_session(resolver=resolver) as session, pytest.raises(BlockedAddressError):
        session.get(http_server.url("/"), timeout=5)
    assert http_server.paths == []


def test_ip_literal_blocked(http_server: Server) -> None:
    with guarded_session(resolver=FakeResolver({})) as session, pytest.raises(BlockedAddressError):
        session.get(f"http://127.0.0.1:{http_server.port}/", timeout=5)


def test_redirect_to_metadata_is_blocked(
    https_server: Server, tls: TLSMaterial, resolver: FakeResolver
) -> None:
    with guarded_session(LOOPBACK_POLICY, resolver) as session, pytest.raises(BlockedAddressError):
        session.get(
            https_server.url("/redirect?to=http://169.254.169.254/"), verify=tls.ca_file, timeout=5
        )


def test_redirect_to_name_that_resolves_internal_is_blocked_at_connect(
    https_server: Server, tls: TLSMaterial
) -> None:
    resolver = FakeResolver({TEST_HOST: ["127.0.0.1"], "evil.test": ["10.0.0.5"]})
    with guarded_session(LOOPBACK_POLICY, resolver) as session, pytest.raises(BlockedAddressError):
        session.get(
            https_server.url("/redirect?to=https://evil.test/"), verify=tls.ca_file, timeout=5
        )
    assert resolver.calls == [TEST_HOST, "evil.test"]


def test_redirect_downgrade_blocked_even_without_following(
    https_server: Server, tls: TLSMaterial, resolver: FakeResolver
) -> None:
    location = f"http://{TEST_HOST}:{https_server.port}/"
    with guarded_session(LOOPBACK_POLICY, resolver) as session:
        for follow in (True, False):
            with pytest.raises(RedirectSchemeError):
                session.get(
                    https_server.url(f"/redirect?to={location}"),
                    verify=tls.ca_file,
                    timeout=5,
                    allow_redirects=follow,
                )


def test_good_redirect_is_followed(
    https_server: Server, tls: TLSMaterial, resolver: FakeResolver
) -> None:
    with guarded_session(LOOPBACK_POLICY, resolver) as session:
        response = session.get(
            https_server.url("/redirect?to=/final"), verify=tls.ca_file, timeout=5
        )
    assert response.status_code == 200
    assert https_server.paths == ["/redirect?to=/final", "/final"]


def test_dns_rebinding_between_connections(http_server: Server) -> None:
    resolver = FakeResolver({TEST_HOST: [["127.0.0.1"], ["10.0.0.1"]]})
    with guarded_session(LOOPBACK_POLICY, resolver) as session:
        assert session.get(http_server.url("/"), timeout=5).status_code == 200
        # Drop the pooled keep-alive connection so the next request must reconnect
        # (a reused connection is, by design, not re-resolved).
        session.adapters["http://"].close()
        with pytest.raises(BlockedAddressError):
            session.get(http_server.url("/"), timeout=5)
    assert resolver.calls == [TEST_HOST, TEST_HOST]


def test_falls_back_to_next_vetted_address(http_server: Server) -> None:
    resolver = FakeResolver({TEST_HOST: ["127.0.0.2", "127.0.0.1"]})
    with guarded_session(LOOPBACK_POLICY, resolver) as session:
        assert session.get(http_server.url("/"), timeout=5).status_code == 200


def test_all_addresses_failing(http_server: Server) -> None:
    resolver = FakeResolver({TEST_HOST: ["127.0.0.2"]})
    with (
        guarded_session(LOOPBACK_POLICY, resolver) as session,
        pytest.raises(requests.exceptions.ConnectionError),
    ):
        session.get(http_server.url("/"), timeout=5)


def test_connect_timeout_is_mapped(
    http_server: Server, resolver: FakeResolver, monkeypatch: pytest.MonkeyPatch
) -> None:
    def slow(*_args: object, **_kwargs: object) -> None:
        raise TimeoutError("timed out")

    monkeypatch.setattr("urllib3.util.connection.create_connection", slow)
    with (
        guarded_session(LOOPBACK_POLICY, resolver) as session,
        pytest.raises(requests.exceptions.ConnectTimeout),
    ):
        session.get(http_server.url("/"), timeout=5)


def test_other_schemes_have_no_adapter() -> None:
    with guarded_session() as session, pytest.raises(requests.exceptions.InvalidSchema):
        session.get("file:///etc/passwd")


def test_proxies_are_refused(http_server: Server, resolver: FakeResolver) -> None:
    with guarded_session(LOOPBACK_POLICY, resolver) as session:
        with pytest.raises(UnsupportedConfigurationError):
            session.get(http_server.url("/"), proxies={"http": "http://proxy.example:3128"})
        # A proxy for another scheme does not apply and is harmless.
        session.get(http_server.url("/"), proxies={"https": "http://proxy.example:3128"}, timeout=5)
    with pytest.raises(UnsupportedConfigurationError):
        SSRFGuardAdapter().proxy_manager_for("http://proxy.example:3128")


def test_adapter_rejects_prepared_request_without_url() -> None:
    request = requests.PreparedRequest()
    with pytest.raises(UnsupportedConfigurationError):
        SSRFGuardAdapter().send(request)


def test_session_defaults() -> None:
    with guarded_session(Policy(max_redirects=2)) as session:
        assert session.max_redirects == 2
        assert session.trust_env is False
        assert set(session.adapters) == {"https://", "http://"}
