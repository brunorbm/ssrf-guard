"""requests integration: an adapter that validates and pins at connect time.

Like the httpx integration, the policy is enforced where the socket is
opened (urllib3's ``HTTPConnection._new_conn``), so the vetted address is
the one connected to, every redirect hop and every new pooled connection is
checked, and TLS still sends SNI for, and verifies the certificate against,
the hostname in the URL.

Usage::

    from ssrf_guard.integrations.requests import guarded_session

    with guarded_session() as session:
        session.get(untrusted_url, timeout=10)

Proxies are refused: with a proxy the guard would vet the proxy's address,
not the destination's. :func:`guarded_session` therefore sets
``trust_env = False`` so ``HTTP(S)_PROXY`` variables and ``.netrc`` are
ignored; the adapter also refuses explicit ``proxies=``.
"""

from __future__ import annotations

import socket
import sys
from collections.abc import Mapping
from typing import Any, ClassVar

import requests
import requests.adapters
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.util import connection as urllib3_connection

from ..errors import UnsupportedConfigurationError
from ..guard import Guard
from ..policy import Policy
from ..resolver import Resolver

__all__ = ["SSRFGuardAdapter", "guarded_session"]


class _GuardedConnectionMixin(HTTPConnection):
    _ssrf_guard: ClassVar[Guard]

    def _new_conn(self) -> socket.socket:
        addresses = self._ssrf_guard.resolve_host(self._dns_host, self.port)
        last_error: Exception | None = None
        for ip in addresses:
            try:
                sock = urllib3_connection.create_connection(
                    (str(ip), self.port),
                    self.timeout,
                    source_address=self.source_address,
                    socket_options=self.socket_options,
                )
            except TimeoutError as exc:
                last_error = ConnectTimeoutError(
                    self, f"Connection to {self.host} ({ip}) timed out."
                )
                last_error.__cause__ = exc
            except OSError as exc:
                last_error = NewConnectionError(
                    self, f"Failed to establish a new connection to {ip}: {exc}"
                )
                last_error.__cause__ = exc
            else:
                sys.audit("http.client.connect", self, self.host, self.port)
                return sock
        assert last_error is not None  # noqa: S101 - resolve_host never returns ()
        raise last_error


def _pool_classes(guard: Guard) -> dict[str, type[HTTPConnectionPool]]:
    """Build pool classes bound to ``guard`` (urllib3 passes no per-pool context)."""
    conn_ns = {"_ssrf_guard": guard}
    http_conn = type("GuardedHTTPConnection", (_GuardedConnectionMixin, HTTPConnection), conn_ns)
    https_conn = type("GuardedHTTPSConnection", (_GuardedConnectionMixin, HTTPSConnection), conn_ns)
    http_pool = type(
        "GuardedHTTPConnectionPool", (HTTPConnectionPool,), {"ConnectionCls": http_conn}
    )
    https_pool = type(
        "GuardedHTTPSConnectionPool", (HTTPSConnectionPool,), {"ConnectionCls": https_conn}
    )
    return {"http": http_pool, "https": https_pool}


class SSRFGuardAdapter(requests.adapters.HTTPAdapter):
    """A :class:`requests.adapters.HTTPAdapter` that only connects to vetted addresses.

    Mount it for both ``http://`` and ``https://`` (``guarded_session`` does).
    """

    def __init__(
        self, policy: Policy | None = None, resolver: Resolver | None = None, **kwargs: Any
    ) -> None:
        self.guard = Guard(policy, resolver)
        super().__init__(**kwargs)

    def init_poolmanager(
        self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any
    ) -> None:
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)
        self.poolmanager.pool_classes_by_scheme = _pool_classes(self.guard)
        # PoolManager copies the mapping into key_fn/pool lookups lazily, so
        # replacing it right after construction covers every pool it creates.

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        raise UnsupportedConfigurationError("proxies are not supported by the SSRF guard adapter")

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: bool | str = True,
        cert: Any = None,
        proxies: Mapping[str, str] | None = None,
    ) -> requests.Response:
        if request.url is None:
            raise UnsupportedConfigurationError("request has no URL")
        if proxies and requests.utils.select_proxy(request.url, dict(proxies)):
            raise UnsupportedConfigurationError(
                "proxies are not supported by the SSRF guard adapter"
            )
        self.guard.parse(request.url)
        return super().send(
            request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies
        )


def guarded_session(
    policy: Policy | None = None, resolver: Resolver | None = None, **adapter_kwargs: Any
) -> requests.Session:
    """Build a :class:`requests.Session` whose every connection is guarded.

    * both ``http://`` and ``https://`` are mounted on :class:`SSRFGuardAdapter`
      (any other scheme has no adapter and fails);
    * ``trust_env`` is false, so proxy environment variables are ignored;
    * ``max_redirects`` comes from the policy;
    * a response hook refuses a redirect whose ``Location`` violates the policy
      (for example an ``https`` to ``http`` downgrade), even when the caller
      passed ``allow_redirects=False``.
    """
    adapter = SSRFGuardAdapter(policy, resolver, **adapter_kwargs)
    guard = adapter.guard
    session = requests.Session()
    session.adapters.clear()
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.trust_env = False
    session.max_redirects = guard.policy.max_redirects

    def redirect_hook(response: requests.Response, *args: Any, **kwargs: Any) -> None:
        if response.is_redirect and response.request.url is not None:
            guard.check_redirect(
                response.request.url, response.headers["Location"], redirects_so_far=None
            )

    session.hooks["response"].append(redirect_hook)
    return session
