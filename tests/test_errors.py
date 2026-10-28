"""The exception hierarchy and its stable codes are public API."""

from __future__ import annotations

from ipaddress import ip_address

import pytest

import ssrf_guard
from ssrf_guard import errors

EXPECTED_CODES = {
    "SSRFGuardError": "ssrf_guard_error",
    "InvalidURLError": "invalid_url",
    "InvalidHostError": "invalid_host",
    "InvalidPortError": "invalid_port",
    "ParserDifferentialError": "parser_differential",
    "PolicyViolationError": "policy_violation",
    "SchemeNotAllowedError": "scheme_not_allowed",
    "UserinfoNotAllowedError": "userinfo_not_allowed",
    "PortNotAllowedError": "port_not_allowed",
    "NonCanonicalAddressError": "noncanonical_address",
    "BlockedHostnameError": "blocked_hostname",
    "BlockedAddressError": "blocked_address",
    "RedirectError": "redirect_not_allowed",
    "TooManyRedirectsError": "too_many_redirects",
    "RedirectSchemeError": "redirect_scheme_change",
    "ResolutionError": "resolution_failed",
    "UnsupportedConfigurationError": "unsupported_configuration",
}


@pytest.mark.parametrize(("name", "code"), sorted(EXPECTED_CODES.items()))
def test_codes_are_stable(name: str, code: str) -> None:
    cls = getattr(ssrf_guard, name)
    assert cls.code == code
    assert issubclass(cls, ssrf_guard.SSRFGuardError)


def test_every_exported_error_is_listed() -> None:
    exported = set(errors.__all__)
    assert exported == set(EXPECTED_CODES)
    assert len(set(EXPECTED_CODES.values())) == len(EXPECTED_CODES)


def test_blocked_address_attributes() -> None:
    err = ssrf_guard.BlockedAddressError(ip_address("10.0.0.1"), "private", "db.example")
    assert err.address == ip_address("10.0.0.1")
    assert err.hostname == "db.example"
    assert "db.example" in str(err)
    assert "10.0.0.1" in str(err)
    bare = ssrf_guard.BlockedAddressError(ip_address("10.0.0.1"), "private")
    assert bare.hostname is None
    assert str(bare).startswith("address 10.0.0.1")


def test_echo_truncates_attacker_input() -> None:
    err = ssrf_guard.BlockedHostnameError("x" * 5000 + "\n", "test")
    assert len(str(err)) < 400
    assert "\n" not in str(err)
    assert err.reason == "test"
