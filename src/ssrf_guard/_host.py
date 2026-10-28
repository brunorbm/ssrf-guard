"""Host parsing: DNS names, IPv4 literals in every legacy spelling, IPv6 literals.

The IPv4 rules follow the WHATWG URL Standard ("ends in a number" and the
IPv4 parser), which is also what ``inet_aton(3)`` and every major browser
implement. Interpreting legacy forms such as ``0x7f.1`` *exactly* the way a
resolver or browser would is the only robust way to know which address they
denote; refusing to interpret them would leave the decision to whatever
library sits downstream.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv6Address

from .errors import InvalidHostError, _echo

_DIGITS = frozenset("0123456789")
_OCTAL = frozenset("01234567")
_HEX = frozenset("0123456789abcdefABCDEF")
_IPV6_CHARS = frozenset("0123456789abcdefABCDEF:.")
_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")
# Full stops that UTS #46 / IDNA treat as label separators.
_IDEOGRAPHIC_DOTS = ("\u3002", "\uff0e", "\uff61")

MAX_HOSTNAME_LENGTH = 253
MAX_LABEL_LENGTH = 63


class HostKind(Enum):
    """What the host component denotes."""

    DNS = "dns"
    IPV4 = "ipv4"
    IPV6 = "ipv6"


@dataclass(frozen=True)
class Host:
    """A parsed and normalized host.

    ``name`` is the ASCII, lower-case form used for DNS, the ``Host`` header
    and TLS SNI. For IP literals it is the canonical textual address (IPv6
    without brackets). ``canonical`` is false when the input spelled an IPv4
    address in a legacy form (octal, hex, integer, short, trailing dot, or
    non-ASCII digits).
    """

    kind: HostKind
    name: str
    ip: IPv4Address | IPv6Address | None
    canonical: bool = True


def _parse_ipv4_number(part: str) -> int | None:
    """WHATWG "IPv4 number parser". Returns None on failure.

    Character classes are checked explicitly: :func:`int` alone would accept
    ``"1_0"``, ``" 1"`` and non-ASCII digits, all of which must fail here.
    """
    if part == "":
        return None
    radix = 10
    digits = part
    if len(part) >= 2 and part[:2] in ("0x", "0X"):
        radix, digits = 16, part[2:]
        allowed = _HEX
    elif len(part) >= 2 and part[0] == "0":
        radix, digits = 8, part[1:]
        allowed = _OCTAL
    else:
        allowed = _DIGITS
    if digits == "":
        return 0
    if not set(digits) <= allowed:
        return None
    return int(digits, radix)


def _ends_in_a_number(host: str) -> bool:
    """WHATWG "ends in a number checker"."""
    parts = host.split(".")
    if parts[-1] == "":
        if len(parts) == 1:
            return False
        parts.pop()
    last = parts[-1]
    if last != "" and set(last) <= _DIGITS:
        return True
    return _parse_ipv4_number(last) is not None


def parse_ipv4(host: str) -> IPv4Address | None:
    """WHATWG "IPv4 parser". Returns None if ``host`` is not a valid IPv4 address.

    Accepts 1 to 4 dot-separated parts in decimal, octal (leading ``0``) or
    hexadecimal (``0x``), with an optional trailing dot, exactly like
    ``inet_aton``: ``127.1``, ``0x7f.1``, ``2130706433``, ``0177.0.0.1``.
    """
    parts = host.split(".")
    if parts[-1] == "" and len(parts) > 1:
        parts.pop()
    if len(parts) > 4:
        return None
    numbers: list[int] = []
    for part in parts:
        n = _parse_ipv4_number(part)
        if n is None:
            return None
        numbers.append(n)
    if any(n > 255 for n in numbers[:-1]):
        return None
    if numbers[-1] >= 256 ** (5 - len(numbers)):
        return None
    value = numbers[-1]
    for i, n in enumerate(numbers[:-1]):
        value += n * 256 ** (3 - i)
    return IPv4Address(value)


def _idna_to_ascii(host: str) -> str:
    """Map a non-ASCII host to its ASCII (punycode) form.

    NFKC folds compatibility characters (fullwidth digits, circled letters,
    ideographic full stops) *before* any decision is taken, so ``１２７。０。０。１``
    and ``ⓛⓞⓒⓐⓛⓗⓞⓢⓣ`` are recognized for what they are. The stdlib codec
    implements IDNA 2003 (RFC 3490) with nameprep, which also removes
    zero-width characters.
    """
    folded = unicodedata.normalize("NFKC", host)
    for dot in _IDEOGRAPHIC_DOTS:
        folded = folded.replace(dot, ".")
    try:
        return folded.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidHostError(f"host {_echo(host)} is not a valid IDNA name") from exc


def _validate_dns_name(name: str, original: str) -> str:
    if name.endswith("."):
        name = name[:-1]
    if name == "":
        raise InvalidHostError(f"host {_echo(original)} is empty")
    if len(name) > MAX_HOSTNAME_LENGTH:
        raise InvalidHostError(f"host {_echo(original)} is longer than {MAX_HOSTNAME_LENGTH}")
    for label in name.split("."):
        if label == "":
            raise InvalidHostError(f"host {_echo(original)} has an empty label")
        if len(label) > MAX_LABEL_LENGTH:
            raise InvalidHostError(
                f"host {_echo(original)} has a label longer than {MAX_LABEL_LENGTH}"
            )
        if not set(label) <= _LABEL_CHARS:
            raise InvalidHostError(f"host {_echo(original)} contains forbidden characters")
        if label[0] == "-" or label[-1] == "-":
            raise InvalidHostError(f"host {_echo(original)} has a label starting or ending in '-'")
    return name


def parse_host(raw: str, *, allow_idna: bool = True) -> Host:
    """Parse the host component of a URL (or a bare host passed by an HTTP client).

    ``raw`` may be a bracketed IPv6 literal (``[::1]``), an unbracketed IPv6
    literal (only accepted when it contains ``:``, as HTTP clients pass it),
    an IPv4 literal in any WHATWG form, or a DNS name (ASCII or, if
    ``allow_idna``, Unicode).

    Raises :class:`InvalidHostError` for anything else. No policy is applied.
    """
    if raw == "":
        raise InvalidHostError("host is empty")

    if raw.startswith("[") or ":" in raw:
        inner = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
        if inner.startswith("[") or inner.endswith("]"):
            raise InvalidHostError(f"host {_echo(raw)} has unbalanced brackets")
        if "%" in inner:
            raise InvalidHostError(f"host {_echo(raw)}: IPv6 zone identifiers are not allowed")
        if inner == "" or not set(inner) <= _IPV6_CHARS:
            raise InvalidHostError(f"host {_echo(raw)} is not a valid IPv6 literal")
        try:
            ip6 = IPv6Address(inner)
        except ValueError as exc:
            raise InvalidHostError(f"host {_echo(raw)} is not a valid IPv6 literal") from exc
        return Host(HostKind.IPV6, ip6.compressed, ip6)

    if "%" in raw:
        raise InvalidHostError(f"host {_echo(raw)}: percent-encoding is not allowed in hosts")

    if raw.isascii():
        ascii_host = raw
    elif allow_idna:
        ascii_host = _idna_to_ascii(raw)
    else:
        raise InvalidHostError(f"host {_echo(raw)} contains non-ASCII characters")
    ascii_host = ascii_host.lower()

    if _ends_in_a_number(ascii_host):
        ip4 = parse_ipv4(ascii_host)
        if ip4 is None:
            raise InvalidHostError(f"host {_echo(raw)} looks like an IPv4 address but is invalid")
        return Host(HostKind.IPV4, str(ip4), ip4, canonical=raw == str(ip4))

    return Host(HostKind.DNS, _validate_dns_name(ascii_host, raw), None)
