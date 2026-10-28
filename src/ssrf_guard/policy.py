"""Destination policy: which schemes, ports, hostnames and IP addresses are reachable."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import (
    IPv4Address,
    IPv4Network,
    IPv6Address,
    IPv6Network,
    ip_address,
    ip_network,
)
from typing import Literal, TypeAlias

from .errors import BlockedAddressError, BlockedHostnameError

IPAddress: TypeAlias = IPv4Address | IPv6Address
IPNetwork: TypeAlias = IPv4Network | IPv6Network
RedirectSchemeChanges = Literal["none", "upgrade", "any"]

__all__ = [
    "DEFAULT_BLOCKED_DOMAINS",
    "DEFAULT_BLOCKED_NETWORKS",
    "IPAddress",
    "IPNetwork",
    "Policy",
    "embedded_ipv4",
]


def _nets(*entries: tuple[str, str]) -> tuple[tuple[IPNetwork, str], ...]:
    return tuple((ip_network(cidr), reason) for cidr, reason in entries)


#: Special-purpose ranges that are never a legitimate destination for a
#: server-side fetch of a user-supplied URL. Sources: IANA IPv4/IPv6
#: Special-Purpose Address Registries (RFC 6890 and updates). Order matters
#: only for the reason reported: more specific entries come first.
DEFAULT_BLOCKED_NETWORKS: tuple[tuple[IPNetwork, str], ...] = _nets(
    # IPv4
    ("0.0.0.0/8", "'this network' / unspecified (RFC 791)"),
    ("10.0.0.0/8", "private network (RFC 1918)"),
    ("100.64.0.0/10", "carrier-grade NAT shared space (RFC 6598)"),
    ("127.0.0.0/8", "loopback (RFC 1122)"),
    ("169.254.0.0/16", "link-local, includes cloud metadata 169.254.169.254 (RFC 3927)"),
    ("172.16.0.0/12", "private network (RFC 1918)"),
    ("192.0.0.0/24", "IETF protocol assignments (RFC 6890)"),
    ("192.0.2.0/24", "documentation TEST-NET-1 (RFC 5737)"),
    ("192.88.99.0/24", "deprecated 6to4 relay anycast (RFC 7526)"),
    ("192.168.0.0/16", "private network (RFC 1918)"),
    ("198.18.0.0/15", "benchmarking (RFC 2544)"),
    ("198.51.100.0/24", "documentation TEST-NET-2 (RFC 5737)"),
    ("203.0.113.0/24", "documentation TEST-NET-3 (RFC 5737)"),
    ("224.0.0.0/4", "multicast (RFC 5771)"),
    ("240.0.0.0/4", "reserved, includes limited broadcast (RFC 1112, RFC 919)"),
    # IPv6
    ("::/128", "unspecified (RFC 4291)"),
    ("::1/128", "loopback (RFC 4291)"),
    ("::/96", "deprecated IPv4-compatible IPv6 (RFC 4291)"),
    ("::ffff:0:0:0/96", "IPv4-translated (RFC 2765)"),
    ("64:ff9b:1::/48", "local-use NAT64 (RFC 8215)"),
    ("100::/64", "discard-only (RFC 6666)"),
    ("2001:db8::/32", "documentation (RFC 3849)"),
    ("2001::/23", "IETF protocol assignments, includes Teredo 2001::/32 (RFC 2928, RFC 4380)"),
    ("3fff::/20", "documentation (RFC 9637)"),
    ("5f00::/16", "SRv6 SIDs (RFC 9602)"),
    ("fc00::/7", "unique local, includes AWS IMDS fd00:ec2::254 (RFC 4193)"),
    ("fe80::/10", "link-local (RFC 4291)"),
    ("fec0::/10", "deprecated site-local (RFC 3879)"),
    ("ff00::/8", "multicast (RFC 4291)"),
)

#: A host equal to, or a subdomain of, one of these names is refused before
#: any DNS query is made. This is defense in depth: such names normally
#: resolve to blocked addresses anyway, but an internal resolver could map
#: them to anything.
DEFAULT_BLOCKED_DOMAINS: frozenset[str] = frozenset(
    {
        "localhost",  # RFC 6761
        "localdomain",
        "local",  # mDNS, RFC 6762
        "internal",  # ICANN private-use TLD; GCP/AWS metadata names live here
        "home.arpa",  # RFC 8375
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.goog",
        "instance-data",
    }
)

_NAT64_WKP = IPv6Network("64:ff9b::/96")
_SIXTOFOUR = IPv6Network("2002::/16")
_TEREDO = IPv6Network("2001::/32")


def embedded_ipv4(ip: IPv6Address) -> list[tuple[str, IPv4Address]]:
    """Return the IPv4 addresses an IPv6 address embeds, with the mechanism name.

    A packet to any of these IPv6 forms can end up delivered to the embedded
    IPv4 address (by the local stack, a NAT64 gateway, or a 6to4/Teredo relay),
    so the embedded address must pass the policy too.
    """
    found: list[tuple[str, IPv4Address]] = []
    if ip.ipv4_mapped is not None:
        found.append(("IPv4-mapped", ip.ipv4_mapped))
    if ip in _NAT64_WKP:
        found.append(("NAT64", IPv4Address(int(ip) & 0xFFFFFFFF)))
    if ip in _SIXTOFOUR and ip.sixtofour is not None:
        found.append(("6to4", ip.sixtofour))
    if ip in _TEREDO and ip.teredo is not None:
        server, client = ip.teredo
        found.append(("Teredo server", server))
        found.append(("Teredo client", client))
    return found


def _as_network(value: str | IPNetwork) -> IPNetwork:
    if isinstance(value, (IPv4Network, IPv6Network)):
        return value
    if isinstance(value, str):
        return ip_network(value, strict=True)
    raise TypeError(f"expected a CIDR string or ip_network, got {type(value).__name__}")


def _strip_scope(ip: IPAddress) -> IPAddress:
    if isinstance(ip, IPv6Address) and ip.scope_id is not None:
        return IPv6Address(ip.compressed.split("%", 1)[0])
    return ip


@dataclass(frozen=True)
class Policy:
    """Immutable description of what a guarded request may reach.

    The defaults are deliberately strict; loosen them explicitly.

    IP evaluation order (first match wins):

    1. the literal address is in ``deny_cidrs``            -> blocked
    2. the literal address is in ``allow_cidrs``           -> allowed
    3. an embedded IPv4 address (IPv4-mapped, NAT64, 6to4, Teredo) is
       evaluated recursively with these same rules         -> blocked if it is
    4. the address is in ``blocked_networks``              -> blocked
    5. otherwise                                           -> allowed
    """

    #: Lower-case URL schemes that may be fetched.
    allowed_schemes: frozenset[str] = frozenset({"http", "https"})
    #: If not None, the only destination ports allowed (after applying defaults).
    allowed_ports: frozenset[int] | None = None
    #: Networks always allowed (exceptions to ``blocked_networks``). Strings or ip_network.
    allow_cidrs: tuple[str | IPNetwork, ...] = ()
    #: Networks always blocked, even if also in ``allow_cidrs``.
    deny_cidrs: tuple[str | IPNetwork, ...] = ()
    #: Special-purpose ranges blocked by default, with the reason reported.
    blocked_networks: tuple[tuple[IPNetwork, str], ...] = DEFAULT_BLOCKED_NETWORKS
    #: Hostnames blocked together with all of their subdomains.
    blocked_domains: frozenset[str] = DEFAULT_BLOCKED_DOMAINS
    #: Allow hosts without a dot (``http://intranet/``), which resolvers may
    #: expand with local search domains.
    allow_single_label_hosts: bool = False
    #: Accept IPv4 literals in legacy forms (``0x7f.1``) for *allowed* addresses,
    #: normalizing them to dotted-quad. Blocked addresses are refused regardless.
    allow_noncanonical_ipv4: bool = False
    #: Accept internationalized (non-ASCII) hostnames, converted with IDNA 2003.
    allow_idna: bool = True
    #: Maximum number of redirects a guarded client follows.
    max_redirects: int = 5
    #: Which scheme changes a redirect may make: ``"none"``, ``"upgrade"``
    #: (http -> https only) or ``"any"`` (https -> http downgrades too).
    redirect_scheme_changes: RedirectSchemeChanges = "upgrade"
    #: URLs longer than this are refused outright.
    max_url_length: int = 8192

    _allow: tuple[IPNetwork, ...] = field(init=False, repr=False, compare=False)
    _deny: tuple[IPNetwork, ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        schemes = frozenset(s.lower() for s in self.allowed_schemes)
        object.__setattr__(self, "allowed_schemes", schemes)
        if self.allowed_ports is not None:
            ports = frozenset(self.allowed_ports)
            if not all(isinstance(p, int) and 0 < p < 65536 for p in ports):
                raise ValueError("allowed_ports must contain integers in 1..65535")
            object.__setattr__(self, "allowed_ports", ports)
        object.__setattr__(self, "allow_cidrs", tuple(self.allow_cidrs))
        object.__setattr__(self, "deny_cidrs", tuple(self.deny_cidrs))
        object.__setattr__(self, "_allow", tuple(_as_network(n) for n in self.allow_cidrs))
        object.__setattr__(self, "_deny", tuple(_as_network(n) for n in self.deny_cidrs))
        domains = frozenset(d.lower().strip(".") for d in self.blocked_domains)
        object.__setattr__(self, "blocked_domains", domains)
        if self.redirect_scheme_changes not in ("none", "upgrade", "any"):
            raise ValueError("redirect_scheme_changes must be 'none', 'upgrade' or 'any'")
        if self.max_redirects < 0:
            raise ValueError("max_redirects must be >= 0")
        if self.max_url_length < 16:
            raise ValueError("max_url_length is unreasonably small")

    # -- addresses -------------------------------------------------------

    def address_block_reason(self, ip: IPAddress | str) -> str | None:
        """Return why ``ip`` is blocked, or None if it is allowed."""
        if isinstance(ip, str):
            ip = ip_address(ip)
        ip = _strip_scope(ip)
        if any(ip in net for net in self._deny if net.version == ip.version):
            return "in deny_cidrs"
        if any(ip in net for net in self._allow if net.version == ip.version):
            return None
        if isinstance(ip, IPv6Address):
            for mechanism, inner in embedded_ipv4(ip):
                reason = self.address_block_reason(inner)
                if reason is not None:
                    return f"{mechanism} address embedding {inner}, which is {reason}"
        for net, reason in self.blocked_networks:
            if net.version == ip.version and ip in net:
                return reason
        return None

    def is_address_allowed(self, ip: IPAddress | str) -> bool:
        """True if the policy allows connecting to ``ip``."""
        return self.address_block_reason(ip) is None

    def check_address(self, ip: IPAddress | str, hostname: str | None = None) -> None:
        """Raise :class:`BlockedAddressError` if ``ip`` is not allowed."""
        addr = ip_address(ip) if isinstance(ip, str) else ip
        reason = self.address_block_reason(addr)
        if reason is not None:
            raise BlockedAddressError(addr, reason, hostname)

    # -- hostnames -------------------------------------------------------

    def hostname_block_reason(self, hostname: str) -> str | None:
        """Return why the (normalized, ASCII) DNS name is blocked, or None."""
        name = hostname.lower().rstrip(".")
        labels = name.split(".")
        for i in range(len(labels)):
            if ".".join(labels[i:]) in self.blocked_domains:
                return f"matches blocked domain {'.'.join(labels[i:])!r}"
        if len(labels) == 1 and not self.allow_single_label_hosts:
            return "single-label hostnames are not allowed"
        return None

    def check_hostname(self, hostname: str) -> None:
        """Raise :class:`BlockedHostnameError` if the DNS name is blocked."""
        reason = self.hostname_block_reason(hostname)
        if reason is not None:
            raise BlockedHostnameError(hostname, reason)
