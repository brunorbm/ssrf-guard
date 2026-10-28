"""Exception hierarchy.

Every exception raised by ``ssrf_guard`` because of *input* (a URL, a host, a
DNS answer or a redirect) derives from :class:`SSRFGuardError` and carries a
stable, machine-readable ``code`` class attribute. Codes are part of the public
API: they will not change within a major version, so callers may log them,
map them to HTTP status codes or assert on them in tests.

Configuration mistakes (for example a malformed CIDR in a :class:`Policy`)
raise ordinary :class:`ValueError` / :class:`TypeError`, because they are
programming errors rather than attacker-controlled input.

Hierarchy::

    SSRFGuardError                      ssrf_guard_error
    +-- InvalidURLError                 invalid_url
    |   +-- InvalidHostError            invalid_host
    |   +-- InvalidPortError            invalid_port
    |   +-- ParserDifferentialError     parser_differential
    +-- PolicyViolationError            policy_violation
    |   +-- SchemeNotAllowedError       scheme_not_allowed
    |   +-- UserinfoNotAllowedError     userinfo_not_allowed
    |   +-- PortNotAllowedError         port_not_allowed
    |   +-- NonCanonicalAddressError    noncanonical_address
    |   +-- BlockedHostnameError        blocked_hostname
    |   +-- BlockedAddressError         blocked_address
    |   +-- RedirectError               redirect_not_allowed
    |       +-- TooManyRedirectsError   too_many_redirects
    |       +-- RedirectSchemeError     redirect_scheme_change
    +-- ResolutionError                 resolution_failed
    +-- UnsupportedConfigurationError   unsupported_configuration
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

__all__ = [
    "BlockedAddressError",
    "BlockedHostnameError",
    "InvalidHostError",
    "InvalidPortError",
    "InvalidURLError",
    "NonCanonicalAddressError",
    "ParserDifferentialError",
    "PolicyViolationError",
    "PortNotAllowedError",
    "RedirectError",
    "RedirectSchemeError",
    "ResolutionError",
    "SSRFGuardError",
    "SchemeNotAllowedError",
    "TooManyRedirectsError",
    "UnsupportedConfigurationError",
    "UserinfoNotAllowedError",
]

_MAX_ECHO = 200


def _echo(value: str) -> str:
    """Render untrusted input safely for an exception message.

    ``repr`` escapes control characters (no log injection through CR/LF) and
    long values are truncated so a hostile URL cannot bloat logs.
    """
    if len(value) > _MAX_ECHO:
        value = value[:_MAX_ECHO] + "..."
    return repr(value)


class SSRFGuardError(Exception):
    """Base class for every input-driven error raised by ssrf_guard."""

    code: str = "ssrf_guard_error"


class InvalidURLError(SSRFGuardError):
    """The URL is malformed or uses syntax that this library refuses to interpret."""

    code = "invalid_url"


class InvalidHostError(InvalidURLError):
    """The host component is empty, malformed, or not a valid DNS name / IP literal."""

    code = "invalid_host"


class InvalidPortError(InvalidURLError):
    """The port component is not a decimal integer in 1..65535."""

    code = "invalid_port"


class ParserDifferentialError(InvalidURLError):
    """ssrf_guard and :func:`urllib.parse.urlsplit` disagree about the host or port.

    A disagreement means some downstream component could connect somewhere
    other than the place that was validated, so the URL is refused.
    """

    code = "parser_differential"


class PolicyViolationError(SSRFGuardError):
    """The URL is well formed but the :class:`~ssrf_guard.Policy` forbids it."""

    code = "policy_violation"


class SchemeNotAllowedError(PolicyViolationError):
    """The scheme is not in ``Policy.allowed_schemes``."""

    code = "scheme_not_allowed"


class UserinfoNotAllowedError(PolicyViolationError):
    """The URL embeds credentials (``user:pass@host``); these are always refused."""

    code = "userinfo_not_allowed"


class PortNotAllowedError(PolicyViolationError):
    """The port is not in ``Policy.allowed_ports``."""

    code = "port_not_allowed"


class NonCanonicalAddressError(PolicyViolationError):
    """An IPv4 literal was written in a non-canonical form (``0x7f.1``, ``2130706433``...).

    Only raised for addresses that would otherwise be allowed, and only when
    ``Policy.allow_noncanonical_ipv4`` is false. A non-canonical spelling of a
    *blocked* address always raises :class:`BlockedAddressError` instead.
    """

    code = "noncanonical_address"


class BlockedHostnameError(PolicyViolationError):
    """The hostname itself is blocked (``localhost``, ``*.internal``, single-label...)."""

    code = "blocked_hostname"

    def __init__(self, hostname: str, reason: str) -> None:
        super().__init__(f"hostname {_echo(hostname)} is blocked: {reason}")
        self.hostname = hostname
        self.reason = reason


class BlockedAddressError(PolicyViolationError):
    """The destination IP address (literal or resolved) is blocked by the policy."""

    code = "blocked_address"

    def __init__(
        self,
        address: IPv4Address | IPv6Address,
        reason: str,
        hostname: str | None = None,
    ) -> None:
        if hostname is None:
            msg = f"address {address} is blocked: {reason}"
        else:
            msg = f"hostname {_echo(hostname)} resolves to blocked address {address}: {reason}"
        super().__init__(msg)
        self.address = address
        self.reason = reason
        self.hostname = hostname


class RedirectError(PolicyViolationError):
    """A redirect was refused."""

    code = "redirect_not_allowed"


class TooManyRedirectsError(RedirectError):
    """More than ``Policy.max_redirects`` redirects were followed."""

    code = "too_many_redirects"


class RedirectSchemeError(RedirectError):
    """A redirect changes the scheme in a way ``Policy.redirect_scheme_changes`` forbids."""

    code = "redirect_scheme_change"


class ResolutionError(SSRFGuardError):
    """The hostname could not be resolved, or resolved to no usable address.

    Resolution failures are reported (and the request refused) rather than
    retried with a different resolver: fail closed.
    """

    code = "resolution_failed"


class UnsupportedConfigurationError(SSRFGuardError):
    """The HTTP client is configured in a way that would bypass the guard (e.g. a proxy)."""

    code = "unsupported_configuration"
