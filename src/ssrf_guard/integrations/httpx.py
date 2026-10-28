"""httpx integration: a transport that validates and pins at connect time.

The check happens in the *network backend*, the layer that opens TCP
sockets, rather than before the request is sent. That gives three
properties a "validate the URL, then call httpx" wrapper cannot:

* the address that passed the policy is the address the socket connects to
  (no second DNS lookup, so no DNS-rebinding window);
* every hop of a redirect chain and every new pooled connection is checked,
  because each one has to open a socket;
* TLS is untouched: httpcore still sends SNI and verifies the certificate
  against the *hostname* from the URL, not the pinned IP.

Usage::

    from ssrf_guard.integrations.httpx import guarded_client

    with guarded_client() as client:
        client.get(untrusted_url)

Limitations: proxies (``proxy=``, ``mounts=``) and Unix sockets are not
supported, because the guard would then vet the proxy rather than the
destination. The transport relies on httpcore's ``ConnectionPool`` exposing
its network backend as ``_network_backend`` (true for httpcore 1.x); if that
ever changes, constructing the transport raises instead of silently running
unguarded.
"""

from __future__ import annotations

import typing
from collections.abc import Iterable
from typing import Any

import anyio.to_thread
import httpcore
import httpx
from httpcore._backends.base import SOCKET_OPTION as SocketOption

from ..errors import UnsupportedConfigurationError
from ..guard import Guard
from ..policy import IPAddress, Policy
from ..resolver import Resolver

__all__ = [
    "AsyncSSRFGuardTransport",
    "SSRFGuardTransport",
    "guarded_async_client",
    "guarded_client",
]


def _refuse_unsupported(kwargs: dict[str, Any]) -> None:
    for key in ("proxy", "uds"):
        if kwargs.get(key) is not None:
            raise UnsupportedConfigurationError(
                f"{key}= is not supported by the SSRF guard transport: the guard would "
                "vet the intermediary instead of the real destination"
            )


class _GuardedBackend(httpcore.NetworkBackend):
    def __init__(self, inner: httpcore.NetworkBackend, guard: Guard) -> None:
        self._inner = inner
        self._guard = guard

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.NetworkStream:
        addresses = self._guard.resolve_host(host, port)
        options = list(socket_options) if socket_options is not None else None
        last_error: Exception | None = None
        for ip in addresses:
            try:
                return self._inner.connect_tcp(
                    str(ip),
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        assert last_error is not None  # noqa: S101 - resolve_host never returns ()
        raise last_error

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.NetworkStream:
        raise UnsupportedConfigurationError("Unix sockets are not supported")

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class _AsyncGuardedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, inner: httpcore.AsyncNetworkBackend, guard: Guard) -> None:
        self._inner = inner
        self._guard = guard

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        # The resolver is blocking (getaddrinfo); keep it off the event loop.
        addresses: tuple[IPAddress, ...] = await anyio.to_thread.run_sync(
            self._guard.resolve_host, host, port
        )
        options = list(socket_options) if socket_options is not None else None
        last_error: Exception | None = None
        for ip in addresses:
            try:
                return await self._inner.connect_tcp(
                    str(ip),
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        assert last_error is not None  # noqa: S101 - resolve_host never returns ()
        raise last_error

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise UnsupportedConfigurationError("Unix sockets are not supported")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


def _swap_backend(transport: httpx.BaseTransport | httpx.AsyncBaseTransport, guard: Guard) -> None:
    pool = getattr(transport, "_pool", None)
    inner = getattr(pool, "_network_backend", None)
    if pool is None or inner is None:  # pragma: no cover - depends on httpcore internals
        raise UnsupportedConfigurationError(
            "this httpx/httpcore version does not expose the connection pool's network "
            "backend; refusing to run unguarded"
        )
    wrapper: httpcore.NetworkBackend | httpcore.AsyncNetworkBackend
    if isinstance(inner, httpcore.AsyncNetworkBackend):
        wrapper = _AsyncGuardedBackend(inner, guard)
    else:
        wrapper = _GuardedBackend(inner, guard)
    pool._network_backend = wrapper


class SSRFGuardTransport(httpx.HTTPTransport):
    """An :class:`httpx.HTTPTransport` that only connects to vetted addresses.

    Accepts the same keyword arguments as :class:`httpx.HTTPTransport`
    except ``proxy`` and ``uds``.
    """

    def __init__(
        self, policy: Policy | None = None, resolver: Resolver | None = None, **kwargs: Any
    ) -> None:
        _refuse_unsupported(kwargs)
        super().__init__(**kwargs)
        self.guard = Guard(policy, resolver)
        _swap_backend(self, self.guard)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        # Cheap syntactic/policy check first: refuses schemes, credentials,
        # blocked literals etc. before any connection (or pooled reuse).
        self.guard.parse(str(request.url))
        return super().handle_request(request)


class AsyncSSRFGuardTransport(httpx.AsyncHTTPTransport):
    """Async counterpart of :class:`SSRFGuardTransport`."""

    def __init__(
        self, policy: Policy | None = None, resolver: Resolver | None = None, **kwargs: Any
    ) -> None:
        _refuse_unsupported(kwargs)
        super().__init__(**kwargs)
        self.guard = Guard(policy, resolver)
        _swap_backend(self, self.guard)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.guard.parse(str(request.url))
        return await super().handle_async_request(request)


def _redirect_hook(guard: Guard) -> typing.Callable[[httpx.Response], None]:
    def hook(response: httpx.Response) -> None:
        if response.has_redirect_location:
            guard.check_redirect(
                str(response.request.url), response.headers["Location"], redirects_so_far=None
            )

    return hook


def _client_kwargs(guard: Guard, kwargs: dict[str, Any]) -> dict[str, Any]:
    for key in ("proxy", "mounts", "transport"):
        if kwargs.get(key) is not None:
            raise UnsupportedConfigurationError(f"{key}= would bypass the guarded transport")
    hooks: dict[str, list[Any]] = {
        name: list(fns) for name, fns in (kwargs.pop("event_hooks", None) or {}).items()
    }
    hooks.setdefault("response", []).insert(0, _redirect_hook(guard))
    kwargs["event_hooks"] = hooks
    kwargs.setdefault("max_redirects", guard.policy.max_redirects)
    kwargs.setdefault("follow_redirects", True)
    # With an explicit transport httpx ignores *_PROXY variables anyway; say so.
    kwargs.setdefault("trust_env", False)
    return kwargs


def guarded_client(
    policy: Policy | None = None,
    resolver: Resolver | None = None,
    *,
    transport_kwargs: dict[str, Any] | None = None,
    **client_kwargs: Any,
) -> httpx.Client:
    """Build an :class:`httpx.Client` whose every connection is guarded.

    Redirects are followed by default, up to ``policy.max_redirects``; each
    hop is re-validated, and a redirect whose ``Location`` violates the
    policy (including a forbidden scheme change) raises
    :class:`~ssrf_guard.RedirectError` or another
    :class:`~ssrf_guard.SSRFGuardError` *even when* ``follow_redirects`` is
    false: the response is refused rather than handed back.
    """
    transport = SSRFGuardTransport(policy, resolver, **(transport_kwargs or {}))
    kwargs = _client_kwargs(transport.guard, client_kwargs)
    return httpx.Client(transport=transport, **kwargs)


def guarded_async_client(
    policy: Policy | None = None,
    resolver: Resolver | None = None,
    *,
    transport_kwargs: dict[str, Any] | None = None,
    **client_kwargs: Any,
) -> httpx.AsyncClient:
    """Async counterpart of :func:`guarded_client`.

    Response event hooks must be coroutines in httpx's async client, so the
    redirect check is wrapped accordingly.
    """
    transport = AsyncSSRFGuardTransport(policy, resolver, **(transport_kwargs or {}))
    kwargs = _client_kwargs(transport.guard, client_kwargs)
    sync_hooks = kwargs["event_hooks"]["response"]
    redirect_check = sync_hooks[0]

    async def async_redirect_check(response: httpx.Response) -> None:
        redirect_check(response)

    sync_hooks[0] = async_redirect_check
    return httpx.AsyncClient(transport=transport, **kwargs)
