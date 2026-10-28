"""Coverage-guided fuzzing of the URL parser and the address policy.

Input layout (so that seeds stay human-readable)::

    byte 0           number of resolver answers (low 2 bits)
    per answer       1 flag byte (even: 4-byte IPv4, odd: 16-byte IPv6) + address
    rest             the URL, decoded as UTF-8 with ``surrogateescape``

Oracles, checked on every input:

1. ``Guard.resolve`` either returns or raises an ``SSRFGuardError``; any other
   exception is a bug (a crash in the parser is a fail-open risk for callers
   that catch only the library's errors).
2. If it returns, every address it hands back, and every IPv4 address
   embedded in an IPv6 one, is globally routable and not multicast
   according to the standard library's ``ipaddress`` (differential oracle).
3. Re-parsing ``target.url`` is a fixed point: same host, port and target.

Run with Atheris (``pip install atheris``)::

    python fuzz/fuzz_url.py -max_total_time=180 fuzz/seeds

Without Atheris the same oracles run on random mutations of the seeds, which
is much weaker but keeps the harness exercisable everywhere.
"""

from __future__ import annotations

import random
import sys
from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path

from ssrf_guard import Guard, Policy, ResolutionError, SSRFGuardError
from ssrf_guard.policy import IPAddress, embedded_ipv4


class _ScriptedResolver:
    def __init__(self, answers: Sequence[IPAddress]) -> None:
        self.answers = list(answers)

    def resolve(self, host: str, port: int) -> Sequence[IPAddress]:
        if not self.answers:
            raise ResolutionError(f"no answers for {host!r}")
        return self.answers


def _decode(data: bytes) -> tuple[list[IPAddress], str]:
    if not data:
        return [], ""
    count, pos = data[0] & 3, 1
    answers: list[IPAddress] = []
    for _ in range(count):
        if pos >= len(data):
            break
        size = 16 if data[pos] & 1 else 4
        raw = data[pos + 1 : pos + 1 + size]
        pos += 1 + size
        if len(raw) == size:
            answers.append(ip_address(raw))
    return answers, data[pos:].decode("utf-8", "surrogateescape")


def _assert_public(ip: IPAddress, url: str) -> None:
    checked: list[IPv4Address | IPv6Address] = [ip]
    if isinstance(ip, IPv6Address):
        checked += [v4 for _, v4 in embedded_ipv4(ip)]
    for addr in checked:
        assert addr.is_global, (url, ip, addr)
        assert not addr.is_multicast, (url, ip, addr)


POLICIES = (Policy(), Policy(allow_noncanonical_ipv4=True, allow_single_label_hosts=True))


def test_one_input(data: bytes) -> None:
    answers, url = _decode(data)
    policy = POLICIES[len(data) & 1]
    guard = Guard(policy, _ScriptedResolver(answers))
    try:
        target = guard.resolve(url)
    except SSRFGuardError:
        return
    for ip in (target.ip, *target.addresses):
        _assert_public(ip, url)
    again = guard.parse(target.url)
    assert (again.host, again.port, again.target) == (target.host, target.port, target.target), (
        url,
        target.url,
    )


def _fallback(argv: list[str]) -> None:
    iterations = 200_000
    for arg in argv:
        if arg.startswith("-runs="):
            iterations = int(arg.split("=", 1)[1])
    seeds = [p.read_bytes() for d in argv if Path(d).is_dir() for p in sorted(Path(d).iterdir())]
    seeds = seeds or [b"\x00http://example.com/"]
    rng = random.Random(0)  # noqa: S311 - not cryptographic
    alphabet = b"%.:[]@/\\0123456789abcdefxX\x00\xff\xe3\x80\x82"
    for _ in range(iterations):
        buf = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 8)):
            op = rng.randrange(3)
            at = rng.randrange(len(buf) + 1)
            if op == 0:
                buf[at:at] = bytes([rng.choice(alphabet)])
            elif op == 1 and buf:
                del buf[min(at, len(buf) - 1)]
            elif buf:
                buf[min(at, len(buf) - 1)] = rng.randrange(256)
        test_one_input(bytes(buf))
    print(f"fallback fuzzer: {iterations} inputs, no oracle violation")


def main() -> None:
    try:
        import atheris
    except ImportError:
        _fallback(sys.argv[1:])
        return
    atheris.instrument_all()  # coverage feedback for the (pure-Python) library
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
