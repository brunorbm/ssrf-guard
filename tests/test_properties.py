"""Property-based tests (Hypothesis).

The central property: *a blocked address stays blocked whatever its
spelling*. Every textual form a WHATWG-style or inet_aton-style parser
accepts for an IPv4 address is generated, plus the IPv6 forms that embed
an IPv4 address, and must be refused under both settings of
``allow_noncanonical_ipv4``.
"""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address

from hypothesis import assume, example, given
from hypothesis import strategies as st

from ssrf_guard import (
    DEFAULT_BLOCKED_NETWORKS,
    BlockedAddressError,
    NonCanonicalAddressError,
    Policy,
    SSRFGuardError,
    parse_url,
)
from ssrf_guard.policy import embedded_ipv4

STRICT = Policy()
LENIENT = Policy(allow_noncanonical_ipv4=True)

_V4_BLOCKED = [n for n, _ in DEFAULT_BLOCKED_NETWORKS if isinstance(n, IPv4Network)]
_V6_BLOCKED = [n for n, _ in DEFAULT_BLOCKED_NETWORKS if isinstance(n, IPv6Network)]


def _in(net: IPv4Network | IPv6Network) -> st.SearchStrategy[int]:
    return st.integers(int(net.network_address), int(net.broadcast_address))


blocked_v4 = st.sampled_from(_V4_BLOCKED).flatmap(_in)
blocked_v6 = st.sampled_from(_V6_BLOCKED).flatmap(_in).map(IPv6Address)
any_v4 = st.integers(0, 2**32 - 1)
# Unicast space minus 0/8; most of it is public, so ``assume`` rarely discards.
unicast_v4 = st.integers(int(IPv4Address("1.0.0.0")), int(IPv4Address("223.255.255.255")))


def _number(value: int, radix: str, zeros: int) -> str:
    if radix == "dec":
        return str(value)
    if radix == "oct":
        return "0" * (zeros + 1) + format(value, "o")
    return "0" + "xX"[zeros % 2] + "0" * zeros + format(value, "x" if zeros % 3 else "X")


@st.composite
def ipv4_spellings(draw: st.DrawFn, value: int) -> str:
    """Any of the 1- to 4-part forms ``inet_aton``/WHATWG accept."""
    nparts = draw(st.integers(1, 4))
    octets = value.to_bytes(4, "big")
    head = list(octets[: nparts - 1])
    tail = int.from_bytes(octets[nparts - 1 :], "big")
    parts = [*head, tail]
    text = ".".join(
        _number(p, draw(st.sampled_from(["dec", "oct", "hex"])), draw(st.integers(0, 3)))
        for p in parts
    )
    return text + draw(st.sampled_from(["", "."]))


def _v6_wrappers(v4: IPv4Address) -> list[str]:
    n = int(v4)
    hi, lo = n >> 16, n & 0xFFFF
    return [
        f"[::ffff:{v4}]",
        f"[::ffff:{hi:x}:{lo:x}]",
        f"[64:ff9b::{v4}]",
        f"[2002:{hi:x}:{lo:x}::1]",
        f"[::{v4}]",
    ]


@given(data=st.data(), value=blocked_v4)
def test_blocked_ipv4_is_blocked_in_every_spelling(data: st.DataObject, value: int) -> None:
    spelling = data.draw(ipv4_spellings(value))
    for policy in (STRICT, LENIENT):
        try:
            parse_url(f"http://{spelling}/", policy)
        except BlockedAddressError as exc:
            assert exc.address == IPv4Address(value)
        else:  # pragma: no cover - the property failed
            raise AssertionError(f"{spelling!r} ({IPv4Address(value)}) was allowed")


@given(value=blocked_v4, index=st.integers(0, 4))
def test_blocked_ipv4_is_blocked_inside_ipv6(value: int, index: int) -> None:
    host = _v6_wrappers(IPv4Address(value))[index]
    for policy in (STRICT, LENIENT):
        try:
            parse_url(f"http://{host}/", policy)
        except BlockedAddressError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"{host} was allowed")


@given(addr=blocked_v6)
def test_blocked_ipv6_is_blocked(addr: IPv6Address) -> None:
    for text in (addr.compressed, addr.exploded, addr.exploded.upper()):
        try:
            parse_url(f"http://[{text}]/", STRICT)
        except BlockedAddressError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"{text} was allowed")


@given(data=st.data(), value=unicast_v4)
def test_public_ipv4_spellings(data: st.DataObject, value: int) -> None:
    addr = IPv4Address(value)
    assume(STRICT.is_address_allowed(addr))
    assert parse_url(f"http://{addr}/").ip == addr
    spelling = data.draw(ipv4_spellings(value))
    assert parse_url(f"http://{spelling}/", LENIENT).ip == addr
    if spelling != str(addr):
        try:
            parse_url(f"http://{spelling}/", STRICT)
        except NonCanonicalAddressError:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"{spelling!r} accepted as canonical")


@given(st.one_of(any_v4.map(IPv4Address), st.integers(0, 2**128 - 1).map(IPv6Address)))
@example(IPv4Address("100.64.0.1"))
@example(IPv6Address("::ffff:127.0.0.1"))
@example(IPv6Address("2002:8000::feff:0:0"))  # found by Atheris, see fuzz/README.md
def test_allowed_implies_globally_routable(addr: IPv4Address | IPv6Address) -> None:
    """Differential check against the stdlib's IANA special-purpose registry.

    The policy may be stricter than ``is_global`` (it blocks e.g. all of
    2001::/23, Teredo, multicast) but never more permissive. Any IPv4
    address embedded in an allowed IPv6 address must be global as well.
    """
    if not STRICT.is_address_allowed(addr):
        return
    targets: list[IPv4Address | IPv6Address] = [addr]
    if isinstance(addr, IPv6Address):
        targets += [v4 for _, v4 in embedded_ipv4(addr)]
    for target in targets:
        assert target.is_global, addr
        assert not target.is_multicast, addr


url_text = st.one_of(
    st.text(max_size=80),
    st.builds(
        lambda scheme, host, rest: f"{scheme}://{host}{rest}",
        st.sampled_from(["http", "https", "HTTP", "ftp", "h ttp"]),
        st.text(alphabet=st.sampled_from(list("abcxyz0189.:[]@%-_ü。。．")), max_size=30),
        st.text(max_size=20),
    ),
)


@given(url_text)
def test_parse_url_fails_closed_and_is_idempotent(text: str) -> None:
    """Arbitrary input either parses, or raises SSRFGuardError: never anything else.

    And whatever parses is a fixed point of normalization.
    """
    try:
        parsed = parse_url(text, LENIENT)
    except SSRFGuardError:
        return
    again = parse_url(parsed.url, STRICT)
    assert again == parsed
    if parsed.ip is not None:
        assert ip_address(parsed.host) == parsed.ip
