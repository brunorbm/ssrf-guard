"""Cheap micro-benchmarks of the guard's overhead.

    PYTHONPATH=src python benchmarks/bench_guard.py

Numbers are per call, best of 5 repeats (``timeit``), on whatever machine
runs this; compare rows with each other, not with other machines.
The end-to-end rows talk to a loopback HTTP server, with a new connection
per request (``Connection: close``) so the connect-time hook runs every time,
and with keep-alive, where the guard only parses the URL.
"""

from __future__ import annotations

import threading
import timeit
from collections.abc import Callable, Sequence
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address

import httpx
import requests

from ssrf_guard import Guard, Policy, parse_url
from ssrf_guard.integrations.httpx import guarded_client
from ssrf_guard.integrations.requests import guarded_session
from ssrf_guard.policy import IPAddress

PUBLIC = [ip_address("93.184.215.14")]


class _Static:
    def resolve(self, host: str, port: int) -> Sequence[IPAddress]:
        return PUBLIC


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Headers and body are separate writes; without TCP_NODELAY, Nagle plus
    # delayed ACKs add ~40 ms to every keep-alive response.
    disable_nagle_algorithm = True

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Length", "2")
        if self.close_connection:  # echo it, or urllib3 tries to reuse the socket
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: object) -> None:
        pass


def _bench(label: str, fn: Callable[[], object], number: int) -> None:
    best = min(timeit.repeat(fn, number=number, repeat=5)) / number
    unit, scale = ("us", 1e6) if best < 1e-3 else ("ms", 1e3)
    print(f"{label:<52} {best * scale:9.2f} {unit}")


def main() -> None:
    url = "https://www.example.com:8443/a/b?c=d#e"
    guard = Guard(Policy(), _Static())
    policy = Policy()
    _bench("parse_url (hostname URL)", lambda: parse_url(url), 20_000)
    _bench("parse_url (IPv6 literal)", lambda: parse_url("http://[2606:4700::1111]/"), 20_000)
    _bench("Guard.resolve (static resolver)", lambda: guard.resolve(url), 20_000)
    v4, v6 = ip_address("8.8.8.8"), ip_address("2606:4700::1111")
    _bench("Policy.is_address_allowed (IPv4)", lambda: policy.is_address_allowed(v4), 50_000)
    _bench("Policy.is_address_allowed (IPv6)", lambda: policy.is_address_allowed(v6), 50_000)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    local = f"http://localhost:{server.server_address[1]}/"
    # "localhost" is a blocked name by default; lift that for the benchmark only.
    loopback = Policy(
        allow_cidrs=("127.0.0.0/8", "::1/128"),
        allow_single_label_hosts=True,
        blocked_domains=frozenset(),
    )
    close = {"Connection": "close"}
    try:
        with httpx.Client() as plain, guarded_client(loopback) as guarded:
            _bench("httpx new connection: plain", lambda: plain.get(local, headers=close), 300)
            _bench("httpx new connection: guarded", lambda: guarded.get(local, headers=close), 300)
            _bench("httpx keep-alive: plain", lambda: plain.get(local), 1_000)
            _bench("httpx keep-alive: guarded", lambda: guarded.get(local), 1_000)
        with requests.Session() as rplain, guarded_session(loopback) as rguarded:
            _bench(
                "requests new connection: plain",
                lambda: rplain.get(local, headers=close, timeout=5),
                300,
            )
            _bench(
                "requests new connection: guarded",
                lambda: rguarded.get(local, headers=close, timeout=5),
                300,
            )
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
