"""Strict URL parsing and normalization (no DNS).

The parser is intentionally narrower than both RFC 3986 and the WHATWG URL
Standard: anything that different parsers are known to read differently
(backslashes, whitespace and control characters, credentials, percent-encoded
hosts, missing ``//``, IPv6 zone identifiers, empty ports...) is refused
instead of being "fixed up". As a final check the result is compared with
:func:`urllib.parse.urlsplit` and refused on any disagreement.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from ._host import Host, parse_host
from .errors import (
    InvalidPortError,
    InvalidURLError,
    NonCanonicalAddressError,
    ParserDifferentialError,
    PortNotAllowedError,
    SchemeNotAllowedError,
    UserinfoNotAllowedError,
    _echo,
)
from .policy import IPAddress, Policy

__all__ = ["DEFAULT_PORTS", "ParsedURL", "check_host", "check_port", "parse_url"]

#: Default ports for schemes a policy may allow. A URL whose scheme is not
#: listed here must carry an explicit port.
DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443, "ws": 80, "wss": 443}

_SCHEME_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*")
# C0 controls, space, DEL, and the C1 controls. Clients disagree on whether
# to strip, encode or reject these, so we reject them.
_FORBIDDEN_RE = re.compile(r"[\x00-\x20\x7f-\x9f\\]")
_PORT_RE = re.compile(r"[0-9]{1,5}")


@dataclass(frozen=True)
class ParsedURL:
    """A syntactically valid URL that passed every policy check not needing DNS."""

    scheme: str
    host: str
    """ASCII lower-case host; IPv6 literals without brackets."""
    port: int
    """Effective port (explicit, or the scheme default)."""
    target: str
    """Request target: path plus query, always starting with ``/``. No fragment."""
    ip: IPAddress | None
    """The address, if the host is an IP literal."""

    @property
    def host_header(self) -> str:
        """Value for the HTTP ``Host`` header (port omitted when it is the default)."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        if DEFAULT_PORTS.get(self.scheme) == self.port:
            return host
        return f"{host}:{self.port}"

    @property
    def url(self) -> str:
        """Normalized URL. Parsing it again yields an equal :class:`ParsedURL`."""
        return f"{self.scheme}://{self.host_header}{self.target}"


def _split_authority(rest: str) -> tuple[str, str]:
    for i, ch in enumerate(rest):
        if ch in "/?#":
            return rest[:i], rest[i:]
    return rest, ""


def _parse_port(text: str, url: str) -> int:
    if not _PORT_RE.fullmatch(text):
        raise InvalidPortError(f"URL {_echo(url)} has an invalid port")
    port = int(text)
    if not 0 < port < 65536:
        raise InvalidPortError(f"URL {_echo(url)} has a port outside 1..65535")
    return port


def check_port(port: int, policy: Policy) -> None:
    """Raise :class:`PortNotAllowedError` if ``policy.allowed_ports`` excludes ``port``."""
    if policy.allowed_ports is not None and port not in policy.allowed_ports:
        raise PortNotAllowedError(f"port {port} is not allowed")


def check_host(raw_host: str, policy: Policy) -> Host:
    """Parse a host and apply every host-level policy check that needs no DNS."""
    host = parse_host(raw_host, allow_idna=policy.allow_idna)
    if host.ip is not None:
        # Blocked addresses are reported as such whatever their spelling.
        policy.check_address(host.ip)
        if not host.canonical and not policy.allow_noncanonical_ipv4:
            raise NonCanonicalAddressError(
                f"host {_echo(raw_host)} is a non-canonical spelling of {host.ip}"
            )
    else:
        policy.check_hostname(host.name)
    return host


def _differential_check(url: str, raw_host: str, port_text: str | None) -> None:
    """Refuse URLs where urllib.parse would see a different host or port."""
    try:
        theirs = urlsplit(url)
        their_host = theirs.hostname
        their_port = theirs.port
    except ValueError as exc:
        raise ParserDifferentialError(f"urllib.parse rejects URL {_echo(url)}") from exc
    ours = raw_host[1:-1] if raw_host.startswith("[") else raw_host
    if their_host is None or their_host != ours.lower():
        raise ParserDifferentialError(f"URL {_echo(url)} is parsed ambiguously (host)")
    if their_port != (int(port_text) if port_text else None):
        raise ParserDifferentialError(f"URL {_echo(url)} is parsed ambiguously (port)")


def parse_url(url: str, policy: Policy | None = None) -> ParsedURL:
    """Parse, normalize and policy-check ``url`` without touching the network.

    Raises a subclass of :class:`~ssrf_guard.SSRFGuardError` on any problem.
    Note that a DNS hostname passing this function says nothing about where it
    resolves to; use :meth:`ssrf_guard.Guard.resolve` for that.
    """
    policy = policy or Policy()
    if not isinstance(url, str):
        raise InvalidURLError(f"URL must be str, not {type(url).__name__}")
    if len(url) > policy.max_url_length:
        raise InvalidURLError(f"URL is longer than {policy.max_url_length} characters")
    if _FORBIDDEN_RE.search(url):
        raise InvalidURLError(
            f"URL {_echo(url)} contains whitespace, control characters or backslashes"
        )

    scheme_text, sep, rest = url.partition(":")
    if not sep or not _SCHEME_RE.fullmatch(scheme_text):
        raise InvalidURLError(f"URL {_echo(url)} has no valid scheme")
    scheme = scheme_text.lower()
    if scheme not in policy.allowed_schemes:
        raise SchemeNotAllowedError(f"scheme {scheme!r} is not allowed")
    if not rest.startswith("//"):
        raise InvalidURLError(f"URL {_echo(url)} must have the form scheme://host/...")

    authority, tail = _split_authority(rest[2:])
    if "@" in authority:
        raise UserinfoNotAllowedError(f"URL {_echo(url)} contains credentials (userinfo)")

    if authority.startswith("["):
        close = authority.find("]")
        if close == -1:
            raise InvalidURLError(f"URL {_echo(url)} has an unterminated IPv6 literal")
        raw_host, after = authority[: close + 1], authority[close + 1 :]
        if after and not after.startswith(":"):
            raise InvalidURLError(f"URL {_echo(url)} has garbage after the IPv6 literal")
        port_text = after[1:] if after else None
    else:
        raw_host, colon, port_text_or_empty = authority.partition(":")
        port_text = port_text_or_empty if colon else None

    if port_text is not None:
        port = _parse_port(port_text, url)
    elif scheme in DEFAULT_PORTS:
        port = DEFAULT_PORTS[scheme]
    else:
        raise InvalidPortError(f"scheme {scheme!r} has no default port; specify one")

    host = check_host(raw_host, policy)
    check_port(port, policy)
    _differential_check(url, raw_host, port_text)

    target, _, _fragment = tail.partition("#")
    if not target.startswith("/"):
        target = "/" + target
    return ParsedURL(scheme=scheme, host=host.name, port=port, target=target, ip=host.ip)
