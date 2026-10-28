"""DNS resolvers.

A resolver turns a hostname into *all* of its addresses. The guard then
requires every one of them to be allowed, so a round-robin answer that mixes
a public and a private address cannot be used to slip through.
"""

from __future__ import annotations

import socket
from collections.abc import Sequence
from ipaddress import ip_address
from typing import Protocol, runtime_checkable

from .errors import ResolutionError, _echo
from .policy import IPAddress

__all__ = ["Resolver", "SystemResolver"]


_INET_FAMILIES: frozenset[int] = frozenset({socket.AF_INET, socket.AF_INET6})


@runtime_checkable
class Resolver(Protocol):
    """Anything that can resolve a hostname to IP addresses."""

    def resolve(self, host: str, port: int) -> Sequence[IPAddress]:
        """Return every address of ``host`` in preference order.

        Must raise :class:`~ssrf_guard.ResolutionError` (or return an empty
        sequence) when the name does not resolve.
        """
        ...


class SystemResolver:
    """Resolve with the operating system's ``getaddrinfo``.

    This honours ``/etc/hosts``, nsswitch and the system's address ordering
    (RFC 6724). Python's ``getaddrinfo`` has no timeout; wrap the call or use
    a custom :class:`Resolver` if slow DNS is a concern for you.
    """

    def __init__(self, family: socket.AddressFamily = socket.AF_UNSPEC) -> None:
        self._family = family

    def resolve(self, host: str, port: int) -> Sequence[IPAddress]:
        try:
            infos = socket.getaddrinfo(
                host, port, self._family, socket.SOCK_STREAM, socket.IPPROTO_TCP
            )
        except (OSError, UnicodeError) as exc:
            raise ResolutionError(f"cannot resolve {_echo(host)}: {exc}") from exc
        seen: dict[IPAddress, None] = {}
        for family, _type, _proto, _canon, sockaddr in infos:
            if family not in _INET_FAMILIES:  # e.g. AF_UNIX on exotic resolvers
                continue
            text = str(sockaddr[0]).split("%", 1)[0]
            seen.setdefault(ip_address(text), None)
        return list(seen)
