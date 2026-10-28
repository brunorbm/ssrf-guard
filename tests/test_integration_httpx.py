"""httpx integration against real sockets on 127.0.0.1.

The fake resolver maps ``service.test`` to 127.0.0.1 and the test-only
policy allows loopback, so these tests exercise real TCP and TLS: the
server records the SNI it received and the Host header, which proves the
connection was pinned to an IP *without* losing hostname semantics.
"""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

import httpcore
import httpx
import pytest

from ssrf_guard import (
    BlockedAddressError,
    Policy,
    RedirectSchemeError,
    UnsupportedConfigurationError,
)
from ssrf_guard.guard import Guard
from ssrf_guard.integrations.httpx import (
    AsyncSSRFGuardTransport,
    SSRFGuardTransport,
    _AsyncGuardedBackend,
    _GuardedBackend,
    guarded_async_client,
    guarded_client,
)

from .conftest import LOOPBACK_POLICY, TEST_HOST, FakeResolver, Server, TLSMaterial


def _ctx(tls: TLSMaterial) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=tls.ca_file)


def _client(resolver: FakeResolver, tls: TLSMaterial, **kwargs: object) -> httpx.Client:
    return guarded_client(
        LOOPBACK_POLICY, resolver, transport_kwargs={"verify": _ctx(tls)}, **kwargs
    )


def test_tls_keeps_sni_host_and_cert_verification(
    https_server: Server, tls: TLSMaterial, resolver: FakeResolver
) -> None:
    with _client(resolver, tls) as client:
        response = client.get(https_server.url("/hello"))
    assert response.status_code == 200
    assert https_server.sni == [TEST_HOST]
    assert https_server.hosts == [f"{TEST_HOST}:{https_server.port}"]
    assert resolver.calls == [TEST_HOST]  # httpcore never resolved on its own


def test_certificate_for_other_name_is_rejected(https_server: Server, tls: TLSMaterial) -> None:
    resolver = FakeResolver({"other.test": ["127.0.0.1"]})
    with _client(resolver, tls) as client, pytest.raises(httpx.ConnectError):
        client.get(https_server.url("/", host="other.test"))


def test_plain_http(http_server: Server, resolver: FakeResolver) -> None:
    with guarded_client(LOOPBACK_POLICY, resolver) as client:
        assert client.get(http_server.url("/")).text == f"hello from {TEST_HOST}:{http_server.port}"


def test_default_policy_blocks_loopback(http_server: Server, resolver: FakeResolver) -> None:
    with guarded_client(resolver=resolver) as client, pytest.raises(BlockedAddressError):
        client.get(http_server.url("/"))
    assert http_server.paths == []


def test_ip_literal_blocked_before_connecting(http_server: Server) -> None:
    with guarded_client(resolver=FakeResolver({})) as client, pytest.raises(BlockedAddressError):
        client.get(f"http://127.0.0.1:{http_server.port}/")
    assert http_server.paths == []


def test_redirect_to_metadata_is_blocked(
    https_server: Server, tls: TLSMaterial, resolver: FakeResolver
) -> None:
    with _client(resolver, tls) as client, pytest.raises(BlockedAddressError):
        client.get(https_server.url("/redirect?to=http://169.254.169.254/latest/meta-data/"))
    assert https_server.paths == ["/redirect?to=http://169.254.169.254/latest/meta-data/"]


def test_redirect_to_name_that_resolves_internal_is_blocked_at_connect(
    https_server: Server, tls: TLSMaterial
) -> None:
    resolver = FakeResolver({TEST_HOST: ["127.0.0.1"], "evil.test": ["10.0.0.5"]})
    with _client(resolver, tls) as client, pytest.raises(BlockedAddressError):
        client.get(https_server.url("/redirect?to=https://evil.test/"))
    assert resolver.calls == [TEST_HOST, "evil.test"]


def test_redirect_downgrade_blocked_even_without_following(
    https_server: Server, tls: TLSMaterial, resolver: FakeResolver
) -> None:
    location = f"http://{TEST_HOST}:{https_server.port}/"
    with _client(resolver, tls) as client:
        with pytest.raises(RedirectSchemeError):
            client.get(https_server.url(f"/redirect?to={location}"))
        with pytest.raises(RedirectSchemeError):
            client.get(https_server.url(f"/redirect?to={location}"), follow_redirects=False)


def test_good_redirect_is_followed(
    https_server: Server, tls: TLSMaterial, resolver: FakeResolver
) -> None:
    hops: list[int] = []
    with _client(
        resolver, tls, event_hooks={"response": [lambda r: hops.append(r.status_code)]}
    ) as client:
        response = client.get(https_server.url("/redirect?to=/final"))
    assert response.status_code == 200
    assert https_server.paths == ["/redirect?to=/final", "/final"]
    assert hops == [302, 200]


def test_dns_rebinding_between_connections(http_server: Server) -> None:
    """Each new connection resolves once and connects to exactly what it checked."""
    resolver = FakeResolver({TEST_HOST: [["127.0.0.1"], ["10.0.0.1"]]})
    with guarded_client(LOOPBACK_POLICY, resolver) as client:
        assert client.get(http_server.url("/"), headers={"Connection": "close"}).status_code == 200
        with pytest.raises(BlockedAddressError):
            client.get(http_server.url("/"))
    assert resolver.calls == [TEST_HOST, TEST_HOST]


def test_falls_back_to_next_vetted_address(http_server: Server) -> None:
    # Nothing listens on 127.0.0.2:<port>, so the first attempt is refused.
    resolver = FakeResolver({TEST_HOST: ["127.0.0.2", "127.0.0.1"]})
    with guarded_client(LOOPBACK_POLICY, resolver) as client:
        assert client.get(http_server.url("/")).status_code == 200


def test_all_addresses_failing_raises_connect_error(http_server: Server) -> None:
    resolver = FakeResolver({TEST_HOST: ["127.0.0.2", "127.0.0.3"]})
    with guarded_client(LOOPBACK_POLICY, resolver) as client, pytest.raises(httpx.ConnectError):
        client.get(http_server.url("/"))


def test_transport_alone_still_guards(http_server: Server, resolver: FakeResolver) -> None:
    """Even without the client helpers' hooks, the transport enforces the policy."""
    transport = SSRFGuardTransport(resolver=resolver)
    assert isinstance(transport.guard, Guard)
    with httpx.Client(transport=transport) as client, pytest.raises(BlockedAddressError):
        client.get(http_server.url("/"))


def test_scheme_check_runs_before_pool() -> None:
    transport = SSRFGuardTransport(resolver=FakeResolver({}))
    with httpx.Client(transport=transport) as client, pytest.raises(BlockedAddressError):
        client.get("http://[::1]/")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"proxy": "http://proxy.example:3128"},
        {"mounts": {"all://": httpx.HTTPTransport()}},
        {"transport": httpx.HTTPTransport()},
    ],
)
def test_bypassing_configuration_is_refused(kwargs: dict[str, object]) -> None:
    with pytest.raises(UnsupportedConfigurationError):
        guarded_client(**kwargs)  # type: ignore[arg-type]
    with pytest.raises(UnsupportedConfigurationError):
        guarded_async_client(**kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize("key", ["proxy", "uds"])
def test_transport_refuses_proxy_and_uds(key: str) -> None:
    kwargs: dict[str, Any] = {key: "http://proxy.example:3128" if key == "proxy" else "/x.sock"}
    with pytest.raises(UnsupportedConfigurationError):
        SSRFGuardTransport(**kwargs)
    with pytest.raises(UnsupportedConfigurationError):
        AsyncSSRFGuardTransport(**kwargs)


def test_client_defaults() -> None:
    with guarded_client(Policy(max_redirects=3)) as client:
        assert client.max_redirects == 3
        assert client.follow_redirects is True
        assert client.trust_env is False


def test_backend_unix_socket_and_sleep() -> None:
    guard = Guard()
    backend = _GuardedBackend(httpcore.SyncBackend(), guard)
    with pytest.raises(UnsupportedConfigurationError):
        backend.connect_unix_socket("/tmp/x.sock")
    backend.sleep(0)

    async def run() -> None:
        abackend = _AsyncGuardedBackend(httpcore.AnyIOBackend(), guard)
        with pytest.raises(UnsupportedConfigurationError):
            await abackend.connect_unix_socket("/tmp/x.sock")
        await abackend.sleep(0)

    asyncio.run(run())


def test_async_client(https_server: Server, tls: TLSMaterial, resolver: FakeResolver) -> None:
    async def run() -> None:
        async with guarded_async_client(
            LOOPBACK_POLICY, resolver, transport_kwargs={"verify": _ctx(tls)}
        ) as client:
            response = await client.get(https_server.url("/redirect?to=/final"))
            assert response.status_code == 200
            with pytest.raises(BlockedAddressError):
                await client.get(https_server.url("/redirect?to=http://[::1]/"))
            with pytest.raises(RedirectSchemeError):
                await client.get(
                    https_server.url(f"/redirect?to=http://{TEST_HOST}:{https_server.port}/")
                )

    asyncio.run(run())
    assert https_server.sni[0] == TEST_HOST
    assert https_server.paths[:2] == ["/redirect?to=/final", "/final"]


def test_async_blocks_and_falls_back(http_server: Server) -> None:
    resolver = FakeResolver({TEST_HOST: ["127.0.0.2", "127.0.0.1"], "bad.test": ["10.1.2.3"]})

    async def run() -> None:
        async with guarded_async_client(LOOPBACK_POLICY, resolver) as client:
            assert (await client.get(http_server.url("/"))).status_code == 200
            with pytest.raises(BlockedAddressError):
                await client.get(http_server.url("/", host="bad.test"))
        resolver2 = FakeResolver({TEST_HOST: ["127.0.0.2"]})
        async with guarded_async_client(LOOPBACK_POLICY, resolver2) as client:
            with pytest.raises(httpx.ConnectError):
                await client.get(http_server.url("/"))
        transport = AsyncSSRFGuardTransport(resolver=resolver)
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(BlockedAddressError):
                await client.get("http://[::1]/")

    asyncio.run(run())
