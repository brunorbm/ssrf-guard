"""Host parsing: the WHATWG IPv4 parser, IPv6 literals and DNS names."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address

import pytest

from ssrf_guard import InvalidHostError
from ssrf_guard._host import HostKind, parse_host, parse_ipv4


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("127.0.0.1", "127.0.0.1"),
        ("2130706433", "127.0.0.1"),
        ("0x7f000001", "127.0.0.1"),
        ("0X7F000001", "127.0.0.1"),
        ("017700000001", "127.0.0.1"),
        ("127.1", "127.0.0.1"),
        ("127.0.1", "127.0.0.1"),
        ("0x7f.1", "127.0.0.1"),
        ("0", "0.0.0.0"),
        ("0x", "0.0.0.0"),
        ("00", "0.0.0.0"),
        ("1.2.3.4.", "1.2.3.4"),
        ("255.255.255.255", "255.255.255.255"),
        ("4294967295", "255.255.255.255"),
        ("1.16777215", "1.255.255.255"),
    ],
)
def test_parse_ipv4_accepts_inet_aton_forms(text: str, expected: str) -> None:
    assert parse_ipv4(text) == IPv4Address(expected)


@pytest.mark.parametrize(
    "text",
    [
        "4294967296",  # 2**32
        "256.0.0.1",
        "1.2.3.256",
        "1.2.65536",
        "1.2.3.4.5",
        "08",  # not octal
        "0x1g",
        "1_0",  # int() would accept this
        " 1",
        "1..2",
        "",
        "..",
        "١",  # ARABIC-INDIC DIGIT ONE: int() would accept this
    ],
)
def test_parse_ipv4_rejects(text: str) -> None:
    assert parse_ipv4(text) is None


def test_ipv4_literal_canonical_flag() -> None:
    assert parse_host("10.0.0.1").canonical
    host = parse_host("0xa.1")
    assert host.kind is HostKind.IPV4
    assert host.name == "10.0.0.1"
    assert not host.canonical


@pytest.mark.parametrize(
    ("raw", "name"),
    [
        ("[::1]", "::1"),
        ("::1", "::1"),  # as HTTP clients pass it at connect time
        ("[2001:DB8::1]", "2001:db8::1"),
        ("[::ffff:127.0.0.1]", "::ffff:127.0.0.1"),
    ],
)
def test_ipv6_literals(raw: str, name: str) -> None:
    host = parse_host(raw)
    assert host.kind is HostKind.IPV6
    assert host.name == name
    assert isinstance(host.ip, IPv6Address)


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        "[::1",
        "::1]",
        "[[::1]]",
        "[fe80::1%eth0]",
        "[fe80::1%25eth0]",
        "[::g]",
        "[1:2]",
        "[::1 ]",
        "a:b",
    ],
)
def test_bad_ipv6_literals(raw: str) -> None:
    with pytest.raises(InvalidHostError):
        parse_host(raw)


@pytest.mark.parametrize(
    ("raw", "name"),
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("under_score.example", "under_score.example"),
        ("xn--bcher-kva.example", "xn--bcher-kva.example"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("EXAMPLE．COM", "example.com"),  # fullwidth full stop
        ("a" * 63 + ".example", "a" * 63 + ".example"),
    ],
)
def test_dns_names(raw: str, name: str) -> None:
    host = parse_host(raw)
    assert host.kind is HostKind.DNS
    assert host.name == name
    assert host.ip is None


@pytest.mark.parametrize(
    "raw",
    [
        "",
        ".",
        "a..b",
        ".example.com",
        "-a.example",
        "a-.example",
        "a" * 64 + ".example",
        ("a" * 60 + ".") * 5,
        "exa mple.com",
        "exa%41mple.com",
        "a/b",
        "1.2.3.foo.0x",  # ends in a number, is not IPv4
        "�.example",  # not valid IDNA
        "x" * 2000 + "ü",  # IDNA label too long
    ],
)
def test_bad_dns_names(raw: str) -> None:
    with pytest.raises(InvalidHostError):
        parse_host(raw)


def test_idna_can_be_disabled() -> None:
    with pytest.raises(InvalidHostError, match="non-ASCII"):
        parse_host("bücher.example", allow_idna=False)
    assert parse_host("bucher.example", allow_idna=False).name == "bucher.example"


@pytest.mark.parametrize(
    ("host", "expected"),
    [("", False), (".", False), ("a.1", True), ("a.0x1.", True), ("a.b", False), ("1.a", False)],
)
def test_ends_in_a_number(host: str, expected: bool) -> None:
    from ssrf_guard._host import _ends_in_a_number

    assert _ends_in_a_number(host) is expected
