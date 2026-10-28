"""URL parsing and normalization (no DNS)."""

from __future__ import annotations

from ipaddress import ip_address

import pytest

from ssrf_guard import (
    InvalidPortError,
    InvalidURLError,
    ParsedURL,
    ParserDifferentialError,
    Policy,
    PortNotAllowedError,
    SchemeNotAllowedError,
    parse_url,
)


@pytest.mark.parametrize(
    ("url", "scheme", "host", "port", "target", "host_header"),
    [
        ("https://Example.COM", "https", "example.com", 443, "/", "example.com"),
        ("HTTP://example.com:80/a?b=1#frag", "http", "example.com", 80, "/a?b=1", "example.com"),
        ("http://example.com:8080?q", "http", "example.com", 8080, "/?q", "example.com:8080"),
        ("https://example.com#only-fragment", "https", "example.com", 443, "/", "example.com"),
        (
            "https://[2606:4700::1]:8443/x",
            "https",
            "2606:4700::1",
            8443,
            "/x",
            "[2606:4700::1]:8443",
        ),
        ("https://8.8.8.8/", "https", "8.8.8.8", 443, "/", "8.8.8.8"),
        ("https://example.com:0443/", "https", "example.com", 443, "/", "example.com"),
    ],
)
def test_parse_and_normalize(
    url: str, scheme: str, host: str, port: int, target: str, host_header: str
) -> None:
    parsed = parse_url(url)
    assert (parsed.scheme, parsed.host, parsed.port, parsed.target) == (scheme, host, port, target)
    assert parsed.host_header == host_header
    # Normalization is idempotent.
    assert parse_url(parsed.url) == parsed


def test_ip_field() -> None:
    assert parse_url("https://8.8.8.8").ip == ip_address("8.8.8.8")
    assert parse_url("https://example.com").ip is None


@pytest.mark.parametrize(
    "url",
    [
        "",
        "example.com",
        "://example.com",
        "1http://example.com",
        "https:example.com",
        "https:/example.com",
        "https://",
        "https://:443/",
        "https://[::1",
        "https://[2606:4700::1]x/",
        "https://exa mple.com/",
        "https://example.com/\\@evil",
        "https://example.com/\x00",
        "https://example.com/\t",
    ],
)
def test_invalid_urls(url: str) -> None:
    with pytest.raises(InvalidURLError):
        parse_url(url)


def test_non_str_is_rejected() -> None:
    with pytest.raises(InvalidURLError, match="must be str"):
        parse_url(b"https://example.com")  # type: ignore[arg-type]


def test_length_limit() -> None:
    policy = Policy(max_url_length=64)
    parse_url("https://example.com/" + "a" * 44, policy)
    with pytest.raises(InvalidURLError, match="longer than 64"):
        parse_url("https://example.com/" + "a" * 45, policy)


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com:/",
        "https://example.com:x/",
        "https://example.com:+1/",
        "https://example.com:123456/",
        "https://example.com:0/",
        "https://example.com:65536/",
    ],
)
def test_invalid_ports(url: str) -> None:
    with pytest.raises(InvalidPortError):
        parse_url(url)


def test_scheme_without_default_port() -> None:
    policy = Policy(allowed_schemes=frozenset({"http", "https", "gopher"}))
    with pytest.raises(InvalidPortError, match="no default port"):
        parse_url("gopher://example.com/", policy)
    assert parse_url("gopher://example.com:7070/", policy).port == 7070


def test_scheme_and_port_policy() -> None:
    with pytest.raises(SchemeNotAllowedError):
        parse_url("ftp://example.com/")
    https_only = Policy(allowed_schemes=frozenset({"https"}), allowed_ports=frozenset({443}))
    with pytest.raises(SchemeNotAllowedError):
        parse_url("http://example.com/", https_only)
    with pytest.raises(PortNotAllowedError):
        parse_url("https://example.com:8443/", https_only)


def test_host_header_for_ipv6_default_port() -> None:
    parsed = ParsedURL(scheme="https", host="::1", port=443, target="/", ip=ip_address("::1"))
    assert parsed.host_header == "[::1]"
    assert parsed.url == "https://[::1]/"


@pytest.mark.parametrize(
    "url",
    [
        # Our parser and urllib.parse would disagree on the port.
        "https://[2606:4700::1]:443:80/",
    ],
)
def test_parser_differential_or_invalid(url: str) -> None:
    with pytest.raises((ParserDifferentialError, InvalidPortError)):
        parse_url(url)


def test_differential_check_detects_disagreement(monkeypatch: pytest.MonkeyPatch) -> None:
    """Simulate a urllib.parse that sees a different host/port or rejects the URL."""
    import ssrf_guard.url as url_mod

    class Fake:
        def __init__(self, hostname: str | None, port: int | None) -> None:
            self.hostname = hostname
            self.port = port

    monkeypatch.setattr(url_mod, "urlsplit", lambda _u: Fake("evil.example", None))
    with pytest.raises(ParserDifferentialError, match="host"):
        parse_url("https://example.com/")
    monkeypatch.setattr(url_mod, "urlsplit", lambda _u: Fake("example.com", 81))
    with pytest.raises(ParserDifferentialError, match="port"):
        parse_url("https://example.com/")

    def boom(_u: str) -> None:
        raise ValueError("nope")

    monkeypatch.setattr(url_mod, "urlsplit", boom)
    with pytest.raises(ParserDifferentialError, match="rejects"):
        parse_url("https://example.com/")
