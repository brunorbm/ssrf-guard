"""ssrf_guard: resolve-and-pin protection against Server-Side Request Forgery.

Typical use::

    from ssrf_guard import Guard

    target = Guard().resolve(user_supplied_url)   # raises SSRFGuardError
    # connect to target.ip:target.port, send Host: target.host_header,
    # verify TLS against target.host

or let an integration do the pinning for you::

    from ssrf_guard.integrations.httpx import guarded_client
    with guarded_client() as client:
        client.get(user_supplied_url)
"""

from .errors import (
    BlockedAddressError,
    BlockedHostnameError,
    InvalidHostError,
    InvalidPortError,
    InvalidURLError,
    NonCanonicalAddressError,
    ParserDifferentialError,
    PolicyViolationError,
    PortNotAllowedError,
    RedirectError,
    RedirectSchemeError,
    ResolutionError,
    SchemeNotAllowedError,
    SSRFGuardError,
    TooManyRedirectsError,
    UnsupportedConfigurationError,
    UserinfoNotAllowedError,
)
from .guard import Guard, PinnedTarget, validate_url
from .policy import DEFAULT_BLOCKED_DOMAINS, DEFAULT_BLOCKED_NETWORKS, Policy
from .resolver import Resolver, SystemResolver
from .url import ParsedURL, parse_url

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_BLOCKED_DOMAINS",
    "DEFAULT_BLOCKED_NETWORKS",
    "BlockedAddressError",
    "BlockedHostnameError",
    "Guard",
    "InvalidHostError",
    "InvalidPortError",
    "InvalidURLError",
    "NonCanonicalAddressError",
    "ParsedURL",
    "ParserDifferentialError",
    "PinnedTarget",
    "Policy",
    "PolicyViolationError",
    "PortNotAllowedError",
    "RedirectError",
    "RedirectSchemeError",
    "ResolutionError",
    "Resolver",
    "SSRFGuardError",
    "SchemeNotAllowedError",
    "SystemResolver",
    "TooManyRedirectsError",
    "UnsupportedConfigurationError",
    "UserinfoNotAllowedError",
    "__version__",
    "parse_url",
    "validate_url",
]
