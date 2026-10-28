"""SystemResolver with a monkeypatched getaddrinfo (no real DNS)."""

from __future__ import annotations

import socket
from ipaddress import ip_address
from typing import Any

import pytest

from ssrf_guard import ResolutionError, SystemResolver


def _info(family: int, addr: str) -> tuple[Any, ...]:
    sockaddr: tuple[Any, ...] = (addr, 443) if family == socket.AF_INET else (addr, 443, 0, 0)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


def test_dedupes_strips_scope_and_skips_other_families(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[Any, ...]] = []

    def fake(*args: Any) -> list[tuple[Any, ...]]:
        seen.append(args)
        return [
            _info(socket.AF_INET6, "2606:4700::1"),
            _info(socket.AF_INET, "93.184.215.14"),
            _info(socket.AF_INET, "93.184.215.14"),
            _info(socket.AF_INET6, "fe80::1%eth0"),
            (socket.AF_UNIX, socket.SOCK_STREAM, 0, "", "/tmp/sock"),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    result = SystemResolver(socket.AF_INET6).resolve("example.com", 443)
    assert list(result) == [
        ip_address("2606:4700::1"),
        ip_address("93.184.215.14"),
        ip_address("fe80::1"),
    ]
    assert seen == [("example.com", 443, socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)]


@pytest.mark.parametrize(
    "exc", [socket.gaierror(-2, "Name or service not known"), UnicodeError("label too long")]
)
def test_errors_become_resolution_error(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> None:
    def fake(*_args: Any) -> list[Any]:
        raise exc

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    with pytest.raises(ResolutionError, match="cannot resolve"):
        SystemResolver().resolve("nx.example", 80)
