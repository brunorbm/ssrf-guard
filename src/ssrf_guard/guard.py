"""Resolve-and-pin: validate a URL, resolve it, and hand back the exact IP to use."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv6Address, ip_address
from urllib.parse import urljoin

from ._host import Host
from .errors import (
    InvalidURLError,
    RedirectSchemeError,
    ResolutionError,
    TooManyRedirectsError,
    _echo,
)
from .policy import IPAddress, Policy
from .resolver import Resolver, SystemResolver
from .url import DEFAULT_PORTS, ParsedURL, check_host, check_port, parse_url

__all__ = ["Guard", "PinnedTarget", "validate_url"]


@dataclass(frozen=True)
class PinnedTarget:
    """A destination whose every resolved address passed the policy.

    Connect to ``ip`` (or, for fallback, any of ``addresses``) on ``port``;
    send ``host_header`` as the ``Host`` header and use ``host`` for TLS SNI
    and certificate verification. Do **not** hand ``url`` back to a client
    that resolves DNS itself: that reopens the DNS-rebinding window.
    """

    scheme: str
    host: str
    port: int
    ip: IPAddress
    addresses: tuple[IPAddress, ...]
    target: str
    host_header: str

    @property
    def url(self) -> str:
        """The normalized URL that was validated (contains the hostname, not the IP)."""
        return f"{self.scheme}://{self.host_header}{self.target}"

    @property
    def pinned_url(self) -> str:
        """The URL rewritten to the pinned IP (for clients that cannot set SNI)."""
        ip = f"[{self.ip}]" if isinstance(self.ip, IPv6Address) else str(self.ip)
        port = "" if DEFAULT_PORTS.get(self.scheme) == self.port else f":{self.port}"
        return f"{self.scheme}://{ip}{port}{self.target}"


class Guard:
    """Applies a :class:`Policy`, using a :class:`Resolver` for DNS.

    A Guard is immutable and thread-safe if its resolver is.
    """

    def __init__(self, policy: Policy | None = None, resolver: Resolver | None = None) -> None:
        self._policy = policy if policy is not None else Policy()
        self._resolver: Resolver = resolver if resolver is not None else SystemResolver()

    @property
    def policy(self) -> Policy:
        return self._policy

    @property
    def resolver(self) -> Resolver:
        return self._resolver

    def parse(self, url: str) -> ParsedURL:
        """Validate ``url`` without DNS. See :func:`ssrf_guard.parse_url`."""
        return parse_url(url, self._policy)

    def resolve(self, url: str) -> PinnedTarget:
        """Validate ``url``, resolve its host and pin a vetted address."""
        parsed = parse_url(url, self._policy)
        addresses = self._addresses_for(parsed.host, parsed.ip, parsed.port)
        return PinnedTarget(
            scheme=parsed.scheme,
            host=parsed.host,
            port=parsed.port,
            ip=addresses[0],
            addresses=addresses,
            target=parsed.target,
            host_header=parsed.host_header,
        )

    def resolve_host(self, host: str, port: int) -> tuple[IPAddress, ...]:
        """Validate a bare host and port (as an HTTP client passes them at
        connect time) and return every vetted address, in resolver order.
        """
        if not isinstance(port, int) or not 0 < port < 65536:
            raise InvalidURLError(f"port {port!r} is outside 1..65535")
        parsed: Host = check_host(host, self._policy)
        check_port(port, self._policy)
        return self._addresses_for(parsed.name, parsed.ip, port)

    def _addresses_for(self, host: str, ip: IPAddress | None, port: int) -> tuple[IPAddress, ...]:
        if ip is not None:
            # Literal; already checked by check_host. Never sent to DNS.
            return (ip,)
        answers = self._resolver.resolve(host, port)
        addresses: list[IPAddress] = []
        for answer in answers:
            try:
                addr = ip_address(answer)
            except ValueError as exc:
                raise ResolutionError(
                    f"resolver returned a non-address for {_echo(host)}"
                ) from exc
            # Every address must pass, not just the one we would use: the
            # client library or OS might pick a different one.
            self._policy.check_address(addr, hostname=host)
            if addr not in addresses:
                addresses.append(addr)
        if not addresses:
            raise ResolutionError(f"{_echo(host)} did not resolve to any address")
        return tuple(addresses)

    def check_redirect(self, current_url: str, location: str, redirects_so_far: int) -> ParsedURL:
        """Validate one redirect hop and return the parsed next URL.

        ``redirects_so_far`` counts redirects already followed before this one.
        The returned URL still has to be resolved (and is, automatically, by
        the guarded transports) before connecting.
        """
        if redirects_so_far + 1 > self._policy.max_redirects:
            raise TooManyRedirectsError(
                f"more than {self._policy.max_redirects} redirects"
            )
        current = parse_url(current_url, self._policy)
        nxt = parse_url(urljoin(current.url, location), self._policy)
        if nxt.scheme != current.scheme:
            mode = self._policy.redirect_scheme_changes
            upgrade = current.scheme == "http" and nxt.scheme == "https"
            if mode == "none" or (mode == "upgrade" and not upgrade):
                raise RedirectSchemeError(
                    f"redirect from {current.scheme}:// to {nxt.scheme}:// is not allowed"
                )
        return nxt


def validate_url(
    url: str, policy: Policy | None = None, resolver: Resolver | None = None
) -> PinnedTarget:
    """Shortcut for ``Guard(policy, resolver).resolve(url)``."""
    return Guard(policy, resolver).resolve(url)
