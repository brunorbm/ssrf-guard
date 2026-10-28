"""Shared fixtures: a scriptable resolver and loopback HTTP(S) servers."""

from __future__ import annotations

import os
import ssl
import threading
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from typing import cast

import pytest
import trustme
from hypothesis import settings

from ssrf_guard import Policy, ResolutionError
from ssrf_guard.policy import IPAddress

# HYPOTHESIS_PROFILE=thorough for a long local run.
settings.register_profile("default", max_examples=300, deadline=None)
settings.register_profile("thorough", max_examples=20_000, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))

#: Hostname the test certificate is issued for. ``.test`` is reserved (RFC 6761).
TEST_HOST = "service.test"


class FakeResolver:
    """Resolver returning scripted answers.

    ``answers`` maps a hostname to either a list of addresses (returned on
    every call) or a list of lists (one per successive call, the last one
    repeating) to simulate DNS rebinding.
    """

    def __init__(self, answers: Mapping[str, Sequence[str] | Sequence[Sequence[str]]]) -> None:
        self._answers = dict(answers)
        self.calls: list[str] = []

    def resolve(self, host: str, port: int) -> Sequence[IPAddress]:
        self.calls.append(host)
        try:
            entry = self._answers[host]
        except KeyError:
            raise ResolutionError(f"NXDOMAIN {host}") from None
        if entry and isinstance(entry[0], str):
            seq: Sequence[str] = cast("Sequence[str]", entry)
        else:
            n = sum(1 for h in self.calls if h == host)
            seq = entry[min(n, len(entry)) - 1]
        return [ip_address(a) for a in seq]


#: Default policy plus loopback, for talking to the local test servers.
LOOPBACK_POLICY = Policy(allow_cidrs=("127.0.0.0/8",))


@dataclass
class Server:
    """A loopback server and what it observed."""

    port: int
    scheme: str
    hosts: list[str] = field(default_factory=list)
    sni: list[str | None] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)

    def url(self, path: str = "/", host: str = TEST_HOST) -> str:
        return f"{self.scheme}://{host}:{self.port}{path}"


def _handler(server_state: Server) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            server_state.hosts.append(self.headers.get("Host", ""))
            server_state.paths.append(self.path)
            if self.path.startswith("/redirect?to="):
                location = self.path.split("=", 1)[1]
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"hello from " + self.headers.get("Host", "").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            pass

    return Handler


@dataclass
class TLSMaterial:
    ca: trustme.CA
    ca_file: str


@pytest.fixture(scope="session")
def tls(tmp_path_factory: pytest.TempPathFactory) -> TLSMaterial:
    ca = trustme.CA()
    path = tmp_path_factory.mktemp("ca") / "ca.pem"
    ca.cert_pem.write_to_path(str(path))
    return TLSMaterial(ca=ca, ca_file=str(path))


def _serve(state: Server, httpd: ThreadingHTTPServer) -> Iterator[Server]:
    thread = threading.Thread(target=httpd.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        yield state
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(5)


@pytest.fixture
def http_server() -> Iterator[Server]:
    state = Server(port=0, scheme="http")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
    state.port = httpd.server_address[1]
    yield from _serve(state, httpd)


@pytest.fixture
def https_server(tls: TLSMaterial) -> Iterator[Server]:
    state = Server(port=0, scheme="https")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
    state.port = httpd.server_address[1]
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    tls.ca.issue_cert(TEST_HOST).configure_cert(ctx)

    def record_sni(sock: ssl.SSLObject | ssl.SSLSocket, name: str | None, _: object) -> None:
        state.sni.append(name)

    ctx.sni_callback = record_sni
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    yield from _serve(state, httpd)


@pytest.fixture
def resolver() -> FakeResolver:
    return FakeResolver({TEST_HOST: ["127.0.0.1"], "public.example": ["93.184.215.14"]})
