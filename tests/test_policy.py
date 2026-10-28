"""IP and hostname policy."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network

import pytest

from ssrf_guard import (
    DEFAULT_BLOCKED_NETWORKS,
    BlockedAddressError,
    BlockedHostnameError,
    Policy,
)
from ssrf_guard.policy import embedded_ipv4


@pytest.mark.parametrize(
    "addr",
    [
        "93.184.215.14",
        "8.8.8.8",
        "1.1.1.1",
        "2606:4700:4700::1111",
        "2a00:1450:4001::1",
        "::ffff:8.8.8.8",
    ],
)
def test_public_addresses_allowed(addr: str) -> None:
    assert Policy().is_address_allowed(addr)


def test_every_default_network_is_blocked_at_both_ends() -> None:
    policy = Policy()
    for net, reason in DEFAULT_BLOCKED_NETWORKS:
        assert reason
        assert not policy.is_address_allowed(net.network_address)
        assert not policy.is_address_allowed(net.broadcast_address)


def test_default_list_covers_stdlib_non_global() -> None:
    """Anything the stdlib calls private/reserved/... and is not global is blocked.

    (The stdlib is the yardstick, not the source of truth: e.g. it treats
    100.64/10 as neither private nor global.)
    """
    policy = Policy()
    samples = [
        "0.1.2.3",
        "10.9.8.7",
        "100.64.0.1",
        "127.0.0.2",
        "169.254.169.254",
        "172.31.255.255",
        "192.0.0.8",
        "192.0.2.1",
        "192.168.0.1",
        "198.18.5.5",
        "198.51.100.1",
        "203.0.113.9",
        "224.1.1.1",
        "240.1.1.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:10.0.0.1",
        "100::1",
        "2001:db8::1",
        "2001:10::1",
        "fc00::1",
        "fe80::1",
        "ff05::1",
        "fd00:ec2::254",
    ]
    for s in samples:
        ip = ip_address(s)
        assert not policy.is_address_allowed(ip), s


def test_reason_is_reported() -> None:
    with pytest.raises(BlockedAddressError, match="RFC 1918") as info:
        Policy().check_address("10.0.0.1")
    assert info.value.reason.startswith("private network")
    reason = Policy().address_block_reason("::ffff:169.254.169.254")
    assert reason is not None
    assert reason.startswith("IPv4-mapped address embedding 169.254.169.254")


def test_scope_id_is_ignored_for_matching() -> None:
    assert not Policy().is_address_allowed(IPv6Address("fe80::1%eth0"))
    assert Policy(allow_cidrs=("fe80::/10",)).is_address_allowed(IPv6Address("fe80::1%1"))


def test_allow_and_deny_order() -> None:
    p = Policy(allow_cidrs=("10.0.0.0/8",), deny_cidrs=("10.0.0.0/24",))
    assert p.is_address_allowed("10.1.0.1")
    assert not p.is_address_allowed("10.0.0.1")
    assert p.address_block_reason("10.0.0.1") == "in deny_cidrs"
    # Deny also applies to public space.
    assert not Policy(deny_cidrs=(ip_network("8.8.8.0/24"),)).is_address_allowed("8.8.8.8")


def test_allow_cidr_does_not_unblock_embedded_mapping_by_accident() -> None:
    p = Policy(allow_cidrs=("10.0.0.0/8",))
    # The mapped form embeds an allowed IPv4 address, so it is allowed...
    assert p.is_address_allowed("::ffff:10.0.0.1")
    # ...but an embedded *blocked* address keeps the wrapper blocked.
    assert not p.is_address_allowed("::ffff:127.0.0.1")
    # Denying the IPv4 range also denies its IPv6 spellings.
    q = Policy(deny_cidrs=("8.8.8.0/24",))
    assert not q.is_address_allowed("::ffff:8.8.8.8")
    assert not q.is_address_allowed("64:ff9b::808:808")
    assert not q.is_address_allowed("2002:808:808::")


def test_allowing_a_translation_prefix_keeps_embedded_checks() -> None:
    # 6to4 is blocked wholesale by default, even around a public address.
    assert "6to4" in (Policy().address_block_reason("2002:808:808::") or "")
    p = Policy(allow_cidrs=("2002::/16", "64:ff9b::/96"))
    assert p.is_address_allowed("2002:808:808::")
    assert p.is_address_allowed("64:ff9b::808:808")
    # Allowing the prefix must not open a path to a blocked IPv4 address.
    assert not p.is_address_allowed("2002:7f00:1::")
    assert not p.is_address_allowed("64:ff9b::a9fe:a9fe")


def test_embedded_ipv4_mechanisms() -> None:
    assert embedded_ipv4(IPv6Address("::ffff:1.2.3.4")) == [("IPv4-mapped", IPv4Address("1.2.3.4"))]
    assert embedded_ipv4(IPv6Address("64:ff9b::102:304")) == [("NAT64", IPv4Address("1.2.3.4"))]
    assert embedded_ipv4(IPv6Address("2002:102:304::")) == [("6to4", IPv4Address("1.2.3.4"))]
    teredo = embedded_ipv4(IPv6Address("2001:0:4136:e378:8000:63bf:3fff:fdd2"))
    assert [m for m, _ in teredo] == ["Teredo server", "Teredo client"]
    assert teredo[1][1] == IPv4Address("192.0.2.45")
    assert embedded_ipv4(IPv6Address("2606:4700::1")) == []


@pytest.mark.parametrize(
    "name",
    [
        "localhost",
        "LOCALHOST",
        "x.localhost",
        "localhost.",
        "printer.local",
        "db.internal",
        "metadata.google.internal",
        "metadata",
        "metadata.goog",
        "a.home.arpa",
        "intranet",
        "instance-data",
    ],
)
def test_blocked_hostnames(name: str) -> None:
    with pytest.raises(BlockedHostnameError):
        Policy().check_hostname(name)


@pytest.mark.parametrize(
    "name", ["example.com", "localhost.example.com", "notlocal", "internal.com"]
)
def test_hostnames_not_blocked(name: str) -> None:
    p = Policy(allow_single_label_hosts=True)
    assert p.hostname_block_reason(name) is None


def test_custom_blocked_domains_are_normalized() -> None:
    p = Policy(blocked_domains=frozenset({".Corp.Example."}))
    assert p.hostname_block_reason("svc.corp.example") == "matches blocked domain 'corp.example'"
    assert p.hostname_block_reason("db.internal") is None  # replaced, not merged


def test_single_label_hosts_opt_in() -> None:
    assert Policy().hostname_block_reason("intranet") is not None
    assert Policy(allow_single_label_hosts=True).hostname_block_reason("intranet") is None


def test_policy_is_frozen_and_normalizes() -> None:
    p = Policy(allowed_schemes=frozenset({"HTTPS"}), allowed_ports=frozenset({443}))
    assert p.allowed_schemes == frozenset({"https"})
    with pytest.raises(AttributeError):
        p.max_redirects = 9  # type: ignore[misc]
    assert p == Policy(allowed_schemes=frozenset({"https"}), allowed_ports=frozenset({443}))


@pytest.mark.parametrize(
    ("kwargs", "exc"),
    [
        ({"allowed_ports": frozenset({0})}, ValueError),
        ({"allowed_ports": frozenset({70000})}, ValueError),
        ({"allow_cidrs": ("10.0.0.1/8",)}, ValueError),  # host bits set
        ({"deny_cidrs": ("nonsense",)}, ValueError),
        ({"deny_cidrs": (42,)}, TypeError),
        ({"redirect_scheme_changes": "sometimes"}, ValueError),
        ({"max_redirects": -1}, ValueError),
        ({"max_url_length": 3}, ValueError),
    ],
)
def test_policy_validation(kwargs: dict[str, object], exc: type[Exception]) -> None:
    with pytest.raises(exc):
        Policy(**kwargs)  # type: ignore[arg-type]
