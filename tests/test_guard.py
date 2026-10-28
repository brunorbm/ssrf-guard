"""Guard: resolution, pinning, redirects and DNS rebinding (fake resolver)."""

from __future__ import annotations

from collections.abc import Sequence
from ipaddress import ip_address

import pytest

from ssrf_guard import (
    BlockedAddressError,
    Guard,
    InvalidURLError,
    Policy,
    PortNotAllowedError,
    RedirectSchemeError,
    ResolutionError,
    SchemeNotAllowedError,
    SystemResolver,
    TooManyRedirectsError,
    validate_url,
)
from ssrf_guard.policy import IPAddress

from .conftest import FakeResolver

PUBLIC = "93.184.215.14"


def test_resolve_pins_first_address_and_keeps_all() -> None:
    resolver = FakeResolver(
        {"example.com": [PUBLIC, "2606:2800:21f:cb07:6820:80da:af6b:8b2c", PUBLIC]}
    )
    target = Guard(resolver=resolver).resolve("https://Example.com:8443/p?q#f")
    assert target.ip == ip_address(PUBLIC)
    assert len(target.addresses) == 2  # de-duplicated, order preserved
    assert (target.host, target.port, target.target) == ("example.com", 8443, "/p?q")
    assert target.host_header == "example.com:8443"
    assert target.url == "https://example.com:8443/p?q"
    assert target.pinned_url == f"https://{PUBLIC}:8443/p?q"
    assert resolver.calls == ["example.com"]


def test_pinned_url_ipv6_default_port() -> None:
    resolver = FakeResolver({"example.com": ["2606:4700::1"]})
    target = validate_url("http://example.com/", resolver=resolver)
    assert target.pinned_url == "http://[2606:4700::1]/"


def test_ip_literal_never_hits_dns() -> None:
    resolver = FakeResolver({})
    target = Guard(resolver=resolver).resolve("https://[2606:4700::1]/")
    assert target.addresses == (ip_address("2606:4700::1"),)
    assert resolver.calls == []


def test_every_answer_must_pass() -> None:
    """One bad A record poisons the whole answer: the OS might pick it."""
    resolver = FakeResolver({"mixed.example": [PUBLIC, "10.0.0.7"]})
    with pytest.raises(BlockedAddressError) as info:
        Guard(resolver=resolver).resolve("https://mixed.example/")
    assert info.value.hostname == "mixed.example"
    assert info.value.address == ip_address("10.0.0.7")


def test_empty_and_garbage_answers() -> None:
    class Weird:
        def __init__(self, answer: Sequence[object]) -> None:
            self.answer = answer

        def resolve(self, host: str, port: int) -> Sequence[IPAddress]:
            return self.answer  # type: ignore[return-value]

    with pytest.raises(ResolutionError, match="did not resolve"):
        Guard(resolver=Weird([])).resolve("https://example.com/")
    with pytest.raises(ResolutionError, match="non-address"):
        Guard(resolver=Weird(["not-an-ip"])).resolve("https://example.com/")
    # Strings are accepted (and checked) too.
    with pytest.raises(BlockedAddressError):
        Guard(resolver=Weird(["127.0.0.1"])).resolve("https://example.com/")


def test_dns_rebinding_is_caught_on_each_resolution() -> None:
    """A rebinding name answers public first, then internal.

    A "validate, then let the client resolve again" design would check the
    first answer and connect to the second. The guard pins: the value it
    returns is the address it checked, and a later resolution is checked
    again on its own.
    """
    resolver = FakeResolver({"rebind.example": [[PUBLIC], ["169.254.169.254"]]})
    guard = Guard(resolver=resolver)
    first = guard.resolve("http://rebind.example/")
    assert first.addresses == (ip_address(PUBLIC),)
    with pytest.raises(BlockedAddressError, match="link-local"):
        guard.resolve("http://rebind.example/")
    assert resolver.calls == ["rebind.example", "rebind.example"]


def test_resolve_host_as_called_by_clients() -> None:
    resolver = FakeResolver({"example.com": [PUBLIC]})
    guard = Guard(Policy(allowed_ports=frozenset({443})), resolver)
    assert guard.resolve_host("example.com", 443) == (ip_address(PUBLIC),)
    assert guard.resolve_host("2606:4700::1", 443) == (ip_address("2606:4700::1"),)
    with pytest.raises(PortNotAllowedError):
        guard.resolve_host("example.com", 80)
    for bad in (0, 65536, "443"):
        with pytest.raises(InvalidURLError):
            guard.resolve_host("example.com", bad)  # type: ignore[arg-type]
    with pytest.raises(BlockedAddressError):
        guard.resolve_host("::1", 443)


def test_default_resolver_and_properties() -> None:
    guard = Guard()
    assert isinstance(guard.resolver, SystemResolver)
    assert guard.policy == Policy()


class TestRedirects:
    guard = Guard(Policy(max_redirects=2), FakeResolver({}))

    def test_relative_and_absolute(self) -> None:
        nxt = self.guard.check_redirect("https://a.example/x/y", "../z?k", redirects_so_far=0)
        assert nxt.url == "https://a.example/z?k"
        nxt = self.guard.check_redirect("https://a.example/", "//b.example/", 1)
        assert nxt.host == "b.example"

    def test_limit(self) -> None:
        with pytest.raises(TooManyRedirectsError):
            self.guard.check_redirect("https://a.example/", "/next", redirects_so_far=2)
        # None: the HTTP client counts.
        self.guard.check_redirect("https://a.example/", "/next", redirects_so_far=None)

    def test_target_is_policy_checked(self) -> None:
        with pytest.raises(BlockedAddressError):
            self.guard.check_redirect("https://a.example/", "http://169.254.169.254/", 0)
        with pytest.raises(SchemeNotAllowedError):
            self.guard.check_redirect("https://a.example/", "file:///etc/passwd", 0)

    @pytest.mark.parametrize(
        ("mode", "current", "location", "ok"),
        [
            ("upgrade", "http://a.example/", "https://a.example/", True),
            ("upgrade", "https://a.example/", "http://a.example/", False),
            ("none", "http://a.example/", "https://a.example/", False),
            ("any", "https://a.example/", "http://a.example/", True),
            ("none", "https://a.example/", "https://b.example/", True),
        ],
    )
    def test_scheme_changes(self, mode: str, current: str, location: str, ok: bool) -> None:
        guard = Guard(Policy(redirect_scheme_changes=mode), FakeResolver({}))  # type: ignore[arg-type]
        if ok:
            guard.check_redirect(current, location, 0)
        else:
            with pytest.raises(RedirectSchemeError):
                guard.check_redirect(current, location, 0)
