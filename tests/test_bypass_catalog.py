"""Table-driven catalog of SSRF bypass techniques.

Every row is one technique seen in the wild (or in the literature) for
getting a server-side HTTP client to reach something it should not. Each
row runs through the full ``Guard.resolve`` path with a scripted resolver,
so DNS-based tricks are covered without touching the network.

The README's "Bypass catalog" table is generated from ``CASES`` by
``scripts/render_catalog.py``; ``test_readme_table_is_current`` fails if the
two drift apart.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from pathlib import Path

import pytest

from ssrf_guard import (
    BlockedAddressError,
    BlockedHostnameError,
    Guard,
    InvalidHostError,
    InvalidPortError,
    InvalidURLError,
    NonCanonicalAddressError,
    Policy,
    PortNotAllowedError,
    ResolutionError,
    SchemeNotAllowedError,
    SSRFGuardError,
    UserinfoNotAllowedError,
)
from tests.conftest import FakeResolver

PUBLIC = "93.184.215.14"


@dataclass(frozen=True)
class Case:
    id: str
    category: str
    url: str
    expect: type[SSRFGuardError] | None
    note: str
    dns: tuple[str, ...] = ()
    policy: Policy | None = None
    host: str | None = None
    """For accepted URLs: the host the guard must have resolved."""
    cwe: str = "CWE-918"


B = BlockedAddressError
H = BlockedHostnameError

CASES: tuple[Case, ...] = (
    # -- loopback and "this host" ------------------------------------------
    Case("loopback-v4", "loopback", "http://127.0.0.1/", B, "IPv4 loopback"),
    Case("loopback-v4-range", "loopback", "http://127.200.1.1/", B, "all of 127/8 is loopback"),
    Case("loopback-v6", "loopback", "http://[::1]/", B, "IPv6 loopback"),
    Case("unspecified-v4", "loopback", "http://0.0.0.0/", B, "0.0.0.0 connects to the local host"),
    Case("unspecified-short", "loopback", "http://0/", B, "'0' is 0.0.0.0 to inet_aton"),
    Case("unspecified-v6", "loopback", "http://[::]/", B, "IPv6 unspecified"),
    Case("localhost", "loopback", "http://localhost/", H, "reserved name (RFC 6761)"),
    Case("localhost-sub", "loopback", "http://a.b.localhost/", H, "every subdomain too"),
    Case("localhost-dot", "loopback", "http://localhost./", H, "absolute (trailing-dot) form"),
    Case("localhost-case", "loopback", "http://LocalHost/", H, "case-insensitive"),
    # -- legacy IPv4 spellings (inet_aton / WHATWG) ----------------------------
    Case("ipv4-decimal", "ipv4-encoding", "http://2130706433/", B, "32-bit integer"),
    Case("ipv4-hex", "ipv4-encoding", "http://0x7f000001/", B, "hex integer"),
    Case("ipv4-octal", "ipv4-encoding", "http://0177.0.0.1/", B, "octal octet"),
    Case("ipv4-short2", "ipv4-encoding", "http://127.1/", B, "two-part form"),
    Case("ipv4-short3", "ipv4-encoding", "http://127.0.1/", B, "three-part form"),
    Case("ipv4-mixed", "ipv4-encoding", "http://0x7f.0.0.01/", B, "mixed radixes"),
    Case(
        "ipv4-octal-meta",
        "ipv4-encoding",
        "http://0251.0376.0251.0376/",
        B,
        "169.254.169.254 in octal",
    ),
    Case("ipv4-trailing-dot", "ipv4-encoding", "http://127.0.0.1./", B, "trailing dot"),
    Case(
        "ipv4-public-legacy",
        "ipv4-encoding",
        "http://134744072/",
        NonCanonicalAddressError,
        "legacy forms refused even when public (8.8.8.8)",
    ),
    Case(
        "ipv4-public-legacy-opt-in",
        "ipv4-encoding",
        "http://0x8.0x8.0x8.0x8/",
        None,
        "opt-in normalizes to dotted quad",
        policy=Policy(allow_noncanonical_ipv4=True),
        host="8.8.8.8",
    ),
    Case(
        "ipv4-out-of-range", "ipv4-encoding", "http://256.0.0.1/", InvalidHostError, "octet > 255"
    ),
    Case(
        "ipv4-five-parts",
        "ipv4-encoding",
        "http://1.2.3.4.5/",
        InvalidHostError,
        "ends in a number but is not IPv4",
    ),
    Case(
        "ipv4-octal-invalid",
        "ipv4-encoding",
        "http://08.0.0.1/",
        InvalidHostError,
        "'08' is not octal",
    ),
    # -- Unicode ---------------------------------------------------------------
    Case(
        "fullwidth-digits",
        "unicode",
        "http://１２７.０.０.１/",
        B,
        "fullwidth digits fold to 127.0.0.1 (NFKC)",
    ),
    Case("ideographic-dots", "unicode", "http://127。0。0。1/", B, "U+3002 is a label separator"),
    Case(
        "circled-letters", "unicode", "http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/", H, "circled letters fold to 'localhost'"
    ),
    Case(
        "zero-width",
        "unicode",
        "http://local\u200bhost/",
        H,
        "zero-width space removed by nameprep",
    ),
    Case("soft-hyphen", "unicode", "http://local\u00adhost/", H, "soft hyphen removed too"),
    Case(
        "idn-ok",
        "unicode",
        "http://bücher.example/",
        None,
        "legitimate IDN resolved by its punycode",
        dns=(PUBLIC,),
        host="xn--bcher-kva.example",
    ),
    Case(
        "idn-disabled",
        "unicode",
        "http://bücher.example/",
        InvalidHostError,
        "allow_idna=False refuses non-ASCII",
        policy=Policy(allow_idna=False),
    ),
    # -- IPv6 forms that embed IPv4 ---------------------------------------------
    Case("v4-mapped", "ipv6-embedding", "http://[::ffff:127.0.0.1]/", B, "IPv4-mapped"),
    Case("v4-mapped-hex", "ipv6-embedding", "http://[::ffff:7f00:1]/", B, "IPv4-mapped, hex"),
    Case(
        "v4-mapped-meta",
        "ipv6-embedding",
        "http://[::ffff:a9fe:a9fe]/",
        B,
        "IPv4-mapped metadata address",
    ),
    Case(
        "v4-compatible", "ipv6-embedding", "http://[::127.0.0.1]/", B, "deprecated IPv4-compatible"
    ),
    Case(
        "nat64",
        "ipv6-embedding",
        "http://[64:ff9b::a9fe:a9fe]/",
        B,
        "NAT64 well-known prefix to 169.254.169.254",
    ),
    Case(
        "nat64-local",
        "ipv6-embedding",
        "http://[64:ff9b:1::a00:1]/",
        B,
        "local-use NAT64 prefix (RFC 8215)",
    ),
    Case("6to4", "ipv6-embedding", "http://[2002:7f00:1::]/", B, "6to4 of 127.0.0.1"),
    Case("6to4-private", "ipv6-embedding", "http://[2002:c0a8:101::1]/", B, "6to4 of 192.168.1.1"),
    Case(
        "teredo",
        "ipv6-embedding",
        "http://[2001:0:4136:e378:8000:63bf:80ff:fffe]/",
        B,
        "Teredo client 127.0.0.1",
    ),
    # -- other IPv6 special ranges ----------------------------------------------
    Case("ipv6-ula", "ipv6", "http://[fd00::1]/", B, "unique local (fc00::/7)"),
    Case("ipv6-link-local", "ipv6", "http://[fe80::1]/", B, "link-local"),
    Case(
        "ipv6-zone-id",
        "ipv6",
        "http://[fe80::1%25eth0]/",
        InvalidHostError,
        "zone identifiers refused",
    ),
    Case("ipv6-site-local", "ipv6", "http://[fec0::1]/", B, "deprecated site-local"),
    Case("ipv6-multicast", "ipv6", "http://[ff02::1]/", B, "multicast"),
    Case("ipv6-doc", "ipv6", "http://[2001:db8::1]/", B, "documentation"),
    Case("ipv6-unbalanced", "ipv6", "http://[::1/", InvalidURLError, "missing ']'"),
    Case("ipv6-garbage", "ipv6", "http://[::1]x/", InvalidURLError, "text after ']'"),
    # -- cloud metadata ------------------------------------------------------
    Case(
        "imds",
        "metadata",
        "http://169.254.169.254/latest/meta-data/",
        B,
        "AWS/GCP/Azure/OpenStack link-local metadata",
    ),
    Case("imds-v6", "metadata", "http://[fd00:ec2::254]/", B, "AWS IMDS over IPv6"),
    Case(
        "ecs-metadata",
        "metadata",
        "http://169.254.170.2/v2/credentials",
        B,
        "AWS ECS task credentials",
    ),
    Case("gcp-name", "metadata", "http://metadata.google.internal/", H, "GCP metadata hostname"),
    Case("gcp-short", "metadata", "http://metadata/", H, "single-label metadata alias"),
    Case("alibaba", "metadata", "http://100.100.100.200/", B, "Alibaba Cloud (CGNAT range)"),
    Case("oracle", "metadata", "http://192.0.0.192/", B, "Oracle Cloud (IETF protocol range)"),
    Case(
        "azure-wireserver",
        "metadata",
        "http://168.63.129.16/",
        B,
        "public address; NOT blocked by default, needs deny_cidrs",
        policy=Policy(deny_cidrs=("168.63.129.16/32",)),
    ),
    # -- private and special IPv4 ranges -------------------------------------
    Case("rfc1918-10", "private", "http://10.0.0.1/", B, "RFC 1918"),
    Case("rfc1918-172", "private", "http://172.16.0.1/", B, "RFC 1918"),
    Case("rfc1918-192", "private", "http://192.168.1.1/", B, "RFC 1918"),
    Case("cgnat", "private", "http://100.64.0.1/", B, "shared address space (RFC 6598)"),
    Case("link-local-v4", "private", "http://169.254.1.1/", B, "link-local"),
    Case("benchmark", "private", "http://198.18.0.1/", B, "benchmarking (RFC 2544)"),
    Case("multicast-v4", "private", "http://224.0.0.1/", B, "multicast"),
    Case("reserved-v4", "private", "http://240.0.0.1/", B, "reserved (class E)"),
    Case("broadcast", "private", "http://255.255.255.255/", B, "limited broadcast"),
    Case(
        "deny-cidr",
        "private",
        "http://8.8.8.8/",
        B,
        "user deny list beats everything",
        policy=Policy(deny_cidrs=("8.8.8.0/24",)),
    ),
    Case(
        "allow-cidr",
        "private",
        "http://10.1.2.3/",
        None,
        "explicit allow list exception",
        policy=Policy(allow_cidrs=("10.1.2.0/24",)),
        host="10.1.2.3",
    ),
    # -- URL syntax confusion --------------------------------------------------
    Case(
        "userinfo",
        "syntax",
        "http://user:pass@example.com/",
        UserinfoNotAllowedError,
        "credentials in URL",
    ),
    Case(
        "userinfo-confusion",
        "syntax",
        "http://example.com@127.0.0.1/",
        UserinfoNotAllowedError,
        "host after '@'",
    ),
    Case(
        "userinfo-colon",
        "syntax",
        "http://example.com:80@127.0.0.1/",
        UserinfoNotAllowedError,
        "port-looking userinfo",
    ),
    Case(
        "at-in-path",
        "syntax",
        "http://example.com/@127.0.0.1",
        None,
        "'@' after the path starts is harmless",
        dns=(PUBLIC,),
        host="example.com",
    ),
    Case(
        "fragment-confusion",
        "syntax",
        "http://example.com#@127.0.0.1/",
        None,
        "'@' in the fragment is harmless",
        dns=(PUBLIC,),
        host="example.com",
    ),
    Case(
        "query-confusion",
        "syntax",
        "http://example.com?@127.0.0.1/",
        None,
        "'@' in the query is harmless",
        dns=(PUBLIC,),
        host="example.com",
    ),
    Case(
        "backslash-at",
        "syntax",
        "http://example.com\\@127.0.0.1/",
        InvalidURLError,
        "WHATWG treats '\\' as '/', RFC 3986 does not",
    ),
    Case(
        "backslash-slashes",
        "syntax",
        "http:\\\\127.0.0.1\\",
        InvalidURLError,
        "backslashes instead of '//'",
    ),
    Case("tab-in-host", "syntax", "http://127.0.0.\t1/", InvalidURLError, "WHATWG strips tabs"),
    Case(
        "crlf",
        "syntax",
        "http://example.com/\r\nX-Injected: 1",
        InvalidURLError,
        "header injection",
        cwe="CWE-918, CWE-93",
    ),
    Case("nul", "syntax", "http://example.com\x00.127.0.0.1/", InvalidURLError, "NUL byte"),
    Case(
        "space-host",
        "syntax",
        "http://127.0.0.1 example.com/",
        InvalidURLError,
        "space in authority",
    ),
    Case("c1-control", "syntax", "http://example.com\x85/", InvalidURLError, "C1 control (NEL)"),
    Case("scheme-relative", "syntax", "//127.0.0.1/", InvalidURLError, "no scheme"),
    Case(
        "single-slash",
        "syntax",
        "http:/127.0.0.1/",
        InvalidURLError,
        "WHATWG repairs, RFC 3986 does not",
    ),
    Case("triple-slash", "syntax", "http:///127.0.0.1/", InvalidHostError, "empty authority"),
    Case("empty-host", "syntax", "http://", InvalidHostError, "no host"),
    Case("empty-host-port", "syntax", "http://:80/", InvalidHostError, "port without host"),
    Case(
        "percent-host",
        "syntax",
        "http://%31%32%37.0.0.1/",
        InvalidHostError,
        "percent-encoded host",
    ),
    Case("percent-dot", "syntax", "http://127%2e0.0.1/", InvalidHostError, "percent-encoded dot"),
    Case(
        "bad-label", "syntax", "http://exa$mple.com/", InvalidHostError, "forbidden host character"
    ),
    Case(
        "overlong",
        "syntax",
        "http://example.com/" + "a" * 9000,
        InvalidURLError,
        "length limit (DoS)",
    ),
    Case(
        "upper-scheme",
        "syntax",
        "HTTP://Example.COM/",
        None,
        "scheme and host are case-folded",
        dns=(PUBLIC,),
        host="example.com",
    ),
    # -- ports ---------------------------------------------------------------
    Case("port-zero", "port", "http://example.com:0/", InvalidPortError, "port 0"),
    Case(
        "port-overflow",
        "port",
        "http://example.com:65616/",
        InvalidPortError,
        "wraps to 80 in some parsers",
    ),
    Case("port-empty", "port", "http://example.com:/", InvalidPortError, "empty port"),
    Case("port-sign", "port", "http://example.com:+80/", InvalidPortError, "signed port"),
    Case(
        "port-fullwidth", "port", "http://example.com:８０/", InvalidPortError, "non-ASCII digits"
    ),
    Case("port-double", "port", "http://127.0.0.1:80:80/", InvalidPortError, "two ports"),
    Case(
        "port-policy",
        "port",
        "http://example.com:6379/",
        PortNotAllowedError,
        "allowed_ports",
        policy=Policy(allowed_ports=frozenset({80, 443})),
    ),
    # -- schemes -------------------------------------------------------------
    Case("file", "scheme", "file:///etc/passwd", SchemeNotAllowedError, "local file read"),
    Case(
        "gopher",
        "scheme",
        "gopher://127.0.0.1:6379/_FLUSHALL",
        SchemeNotAllowedError,
        "raw TCP payloads (Redis, SMTP...)",
    ),
    Case("dict", "scheme", "dict://127.0.0.1:11211/stat", SchemeNotAllowedError, "dict://"),
    Case("ftp", "scheme", "ftp://example.com/", SchemeNotAllowedError, "ftp://"),
    Case("data", "scheme", "data:text/plain,hi", SchemeNotAllowedError, "data:"),
    Case(
        "no-default-port",
        "scheme",
        "foo://example.com/",
        InvalidPortError,
        "allowed scheme without a default port must give one",
        policy=Policy(allowed_schemes=frozenset({"foo"})),
    ),
    # -- DNS -----------------------------------------------------------------
    Case(
        "dns-private",
        "dns",
        "http://intranet.example/",
        B,
        "A record to RFC 1918",
        dns=("10.0.0.5",),
    ),
    Case(
        "dns-loopback",
        "dns",
        "http://127.0.0.1.nip.io/",
        B,
        "wildcard DNS services echo the IP",
        dns=("127.0.0.1",),
    ),
    Case(
        "dns-mixed",
        "dns",
        "http://mixed.example/",
        B,
        "one bad answer among good ones blocks",
        dns=(PUBLIC, "127.0.0.1"),
    ),
    Case(
        "dns-aaaa-mapped",
        "dns",
        "http://aaaa.example/",
        B,
        "AAAA record with IPv4-mapped metadata",
        dns=("::ffff:169.254.169.254",),
    ),
    Case(
        "dns-nxdomain", "dns", "http://nxdomain.example/", ResolutionError, "unresolvable", dns=()
    ),
    Case(
        "dns-public",
        "dns",
        "http://example.com/",
        None,
        "ordinary public host",
        dns=(PUBLIC, "2606:2800:21f:cb07:6820:80da:af6b:8b2c"),
        host="example.com",
    ),
    Case("single-label", "dns", "http://intranet/", H, "search-domain expansion"),
    Case("internal-tld", "dns", "http://db.internal/", H, "private-use TLD"),
    Case("mdns", "dns", "http://printer.local/", H, "multicast DNS"),
    Case("home-arpa", "dns", "http://router.home.arpa/", H, "home networks (RFC 8375)"),
)


def _resolver_for(case: Case) -> FakeResolver:
    if not case.dns:
        return FakeResolver({})
    host = Guard(case.policy).parse(case.url).host
    return FakeResolver({host: list(case.dns)})


@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_catalog(case: Case) -> None:
    resolver = _resolver_for(case)
    guard = Guard(case.policy, resolver)
    if case.expect is None:
        target = guard.resolve(case.url)
        assert target.host == case.host
        for ip in target.addresses:
            assert guard.policy.is_address_allowed(ip)
    else:
        with pytest.raises(case.expect) as info:
            guard.resolve(case.url)
        # The most specific class is raised, not just a parent.
        assert type(info.value) is case.expect
    if not case.dns and case.expect is not ResolutionError:
        # Refused (or accepted as a literal) without asking DNS.
        assert resolver.calls == []


def test_ids_are_unique() -> None:
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids))


def _display(url: str, limit: int = 56) -> str:
    out = []
    for ch in url:
        cat = unicodedata.category(ch)
        if cat.startswith(("C", "Z")) or ch == "|":
            out.append(f"\\x{ord(ch):02x}" if ord(ch) < 256 else f"\\u{ord(ch):04x}")
        elif ch == "\\":
            out.append("\\\\")
        else:
            out.append(ch)
    text = "".join(out)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def render_table() -> str:
    """Markdown table of ``CASES`` (embedded in README.md)."""
    lines = [
        "| ID | Category | Input | Result | CWE | Note |",
        "|---|---|---|---|---|---|",
    ]
    for c in CASES:
        result = "allowed" if c.expect is None else f"`{c.expect.code}`"
        test = f"[`{c.id}`](tests/test_bypass_catalog.py)"
        lines.append(
            f"| {test} | {c.category} | `{_display(c.url)}` | {result} | {c.cwe} | {c.note} |"
        )
    return "\n".join(lines)


BEGIN = "<!-- catalog:begin (generated by scripts/render_catalog.py) -->"
END = "<!-- catalog:end -->"


def test_readme_table_is_current() -> None:
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
    start = readme.index(BEGIN) + len(BEGIN)
    stop = readme.index(END)
    assert readme[start:stop].strip() == render_table(), (
        "README catalog is stale: run `python scripts/render_catalog.py`"
    )
