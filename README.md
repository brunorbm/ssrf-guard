# ssrf-guard

[![CI](https://github.com/brunorbm/ssrf-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/brunorbm/ssrf-guard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/brunorbm/ssrf-guard/actions/workflows/codeql.yml/badge.svg)](https://github.com/brunorbm/ssrf-guard/actions/workflows/codeql.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.10-3.13](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)
![Typed: mypy --strict](https://img.shields.io/badge/typing-mypy%20--strict-informational.svg)

Server-Side Request Forgery (SSRF, [CWE-918](https://cwe.mitre.org/data/definitions/918.html))
protection for Python HTTP clients, built on **resolve-and-pin**: the
address that passes the policy is the address the socket connects to. The
check runs where the TCP connection is opened, so it also covers every
redirect hop and every new pooled connection, and TLS still verifies the
certificate against the hostname from the URL.

- Core library: zero runtime dependencies, fully typed (`py.typed`, `mypy --strict`), Python 3.10+.
- Integrations: an [httpx](https://www.python-httpx.org/) transport (sync and async) and a
  [requests](https://requests.readthedocs.io/) adapter.
- Evidence: 100 % line and branch coverage, a 112-case [bypass catalog](#bypass-catalog),
  Hypothesis properties, real-socket DNS-rebinding and TLS tests, an Atheris
  harness (which found one policy bug, now fixed), and Semgrep rules for
  finding unguarded fetches in *your* code.

Status: alpha (0.1.0). Not published on PyPI yet.

## Contents

- [The problem](#the-problem)
- [Threat model](#threat-model)
- [Quick start](#quick-start)
- [Blocklist vs resolve-and-pin](#blocklist-vs-resolve-and-pin)
- [Design decisions](#design-decisions)
- [Bypass catalog](#bypass-catalog)
- [How it is tested](#how-it-is-tested)
- [Performance](#performance)
- [Limitations](#limitations)
- [Semgrep rules](#semgrep-rules)

## The problem

A feature that fetches a URL supplied by a user (webhooks, link previews,
"import from URL", PDF/HTML renderers, OAuth/OIDC discovery, image proxies)
lets that user make *your server* send requests. Pointed inward, those
requests reach things that trust the server's network position: cloud
instance metadata (`169.254.169.254`, `fd00:ec2::254`) and the credentials
it hands out, admin panels on `localhost`, databases and caches on private
networks, and internal HTTP APIs.

The usual fix, "parse the URL, look up the host, refuse private IPs, then
call `requests.get(url)`", is broken in several independent ways:

1. **Parser differentials.** The validator and the HTTP client disagree on
   what the host is (`http://example.com\@127.0.0.1/`, tabs, `%2e`,
   fullwidth dots, `[::ffff:127.0.0.1]`).
2. **Alternate spellings.** `2130706433`, `0x7f.1`, `0177.0.0.1`, `127.1`
   and `[::ffff:7f00:1]` are all `127.0.0.1` to some layer of the stack.
3. **Time-of-check to time-of-use (DNS rebinding).** The validator resolves
   the name once, the HTTP client resolves it again. A name with a TTL of 0
   can answer a public address the first time and `127.0.0.1` the second.
4. **Redirects.** The first URL is fine; its `302 Location` is not, and the
   client follows it without asking the validator.
5. **Multiple answers.** The validator checks the first A record; the client
   (or Happy Eyeballs) connects to another one.

ssrf-guard closes 3 to 5 structurally (there is only one resolution, its
result is pinned, and every connection goes through the check) and treats 1
and 2 by refusing anything ambiguous rather than trying to interpret it the
way some particular client would.

## Threat model

**Attacker:** controls the URL string (fully), the DNS records of any domain
they own (including TTL 0 and mixed public/private answers), and the HTTP
server at any public address (so they control redirects and response
contents).

**Assets:** anything reachable from the server's network position that is
not reachable from the internet: loopback services, RFC 1918 / ULA
networks, link-local cloud metadata, and other special-purpose ranges.

**What ssrf-guard defends against**

- Requests to special-purpose IPv4 and IPv6 ranges ([list](src/ssrf_guard/policy.py)), however the address is spelled.
- IPv6 forms that deliver to an embedded IPv4 address: IPv4-mapped, NAT64
  (`64:ff9b::/96`), 6to4 and Teredo; the embedded address is checked too.
- Reserved and metadata hostnames (`localhost`, `*.internal`, `*.local`,
  `metadata.google.internal`, ...) before any DNS query, and single-label
  names that a resolver might expand with a search domain.
- DNS rebinding between the check and the connection: the vetted address is
  the one connected to. Every resolved address must pass, not just the first.
- Redirect chains: each hop is a new connection, so each hop is checked.
  Scheme changes are limited (default: `http` to `https` upgrades only).
- Parser-differential tricks: backslashes, whitespace and control
  characters, credentials in the URL, percent-encoded hosts, IPv6 zone IDs,
  and anything `urllib.parse` reads differently. Unicode look-alikes
  (fullwidth digits, ideographic dots) are folded with NFKC before any
  decision, so they are judged as the address or name they spell.
- Non-HTTP schemes (`file:`, `gopher:`, `dict:`, ...) and, optionally,
  non-allowlisted ports.

**What it does not defend against**

- Requests that do not go through a guarded client. A `requests.get()`
  elsewhere in your code is not protected; the [Semgrep rules](#semgrep-rules) help find them.
- Proxies. Through an HTTP proxy the guard would vet the proxy, not the
  destination, so the integrations refuse proxy configuration.
- Allowed destinations that are themselves dangerous. If your policy allows
  `10.0.0.0/8` or a public host that is an open redirector to an internal
  network you do not control, the guard does what you asked.
- Attacks on the response (XXE, deserialization, decompression bombs,
  oversized bodies) and request smuggling. Set timeouts and size limits.
- Side channels: timing, error messages and status codes can still tell an
  attacker whether a public host is up. Do not echo upstream errors.
- Non-TCP/HTTP protocols, and HTTP/3.
- Hostile DNS *at your resolver* that answers public addresses for names you
  consider internal: the guard trusts the addresses, not the names.

## Quick start

```sh
pip install "ssrf-guard[httpx]"      # or [requests]; the core needs neither
```

(Until a release is published, install from a checkout: `pip install ".[httpx]"`.)

### httpx

```python
from ssrf_guard import SSRFGuardError
from ssrf_guard.integrations.httpx import guarded_client

with guarded_client(timeout=10.0) as client:
    try:
        response = client.get(untrusted_url)
    except SSRFGuardError as exc:
        log.warning("refused %s: %s", exc.code, exc)  # don't echo exc to the user
```

`guarded_async_client()` is the `httpx.AsyncClient` counterpart. To keep an
existing client configuration, use the transport directly:
`httpx.Client(transport=SSRFGuardTransport(), trust_env=False)`. Connections
are still guarded, but redirect *scheme* checks need the event hook that
`guarded_client` installs.

### requests

```python
from ssrf_guard.integrations.requests import guarded_session

with guarded_session() as session:
    response = session.get(untrusted_url, timeout=10)
```

### Any other client

`Guard.resolve` validates a URL, resolves it, checks every address and
returns a `PinnedTarget`. Connect to `target.ip`, send `target.host_header`
as the `Host` header and use `target.host` for SNI and certificate checks.
Do **not** pass `target.url` back to a client that resolves DNS on its own:
that recreates the rebinding window.

```python
from ssrf_guard import Guard

target = Guard().resolve("https://example.com/hook")
target.ip, target.port, target.host_header  # (IPv4Address('...'), 443, 'example.com')
```

### Policy

The defaults are strict. Loosen them explicitly:

```python
from ssrf_guard import Policy
from ssrf_guard.integrations.httpx import guarded_client

policy = Policy(
    allowed_ports=frozenset({80, 443, 8443}),
    allow_cidrs=("10.20.0.0/16",),  # reach one internal network on purpose
    deny_cidrs=("168.63.129.16/32",),  # block extra addresses (here: Azure WireServer)
    redirect_scheme_changes="none",
    max_redirects=3,
)
client = guarded_client(policy)
```

Evaluation order for an address: `deny_cidrs` (blocked), then any embedded
IPv4 address checked recursively, then `allow_cidrs` (allowed), then the
special-purpose blocklist, then allowed. Every exception is a subclass of
`SSRFGuardError` with a stable `code` (`blocked_address`, `parser_differential`,
`redirect_scheme_change`, ...) suitable for metrics.

## Blocklist vs resolve-and-pin

| Concern | Naive "validate, then fetch" | Allowlist of hostnames | ssrf-guard (resolve-and-pin at connect time) |
|---|---|---|---|
| `127.1`, `0x7f000001`, `[::ffff:7f00:1]` | Missed unless every spelling is normalized | Not applicable | Refused (non-canonical) or decoded and blocked |
| DNS rebinding (TTL 0) | **Bypassed**: two resolutions | Bypassed if an allowed name can be repointed | Closed: one resolution, pinned |
| Mixed A records (public + private) | Often checks only the first | Same | Every address must pass |
| Redirect to internal host | **Bypassed** unless redirects are disabled | Each hop must be re-checked by hand | Each hop is a new connection, checked |
| Parser differentials (`\`, `@`, tabs) | Depends on two parsers agreeing | Same | Ambiguous input refused; cross-checked with `urllib.parse` |
| TLS | Unaffected | Unaffected | SNI and certificate still use the hostname |
| New pooled connection to same host | Not re-checked | Not re-checked | Checked (keep-alive reuse is not re-resolved) |
| Usability | Any destination | Only listed hosts | Any public destination, plus explicit `allow_cidrs` |

A hostname allowlist is stronger when the set of destinations is known in
advance; use it *in addition* (and still pin), not instead. Firewalling the
fetcher into its own egress-restricted network is stronger still, and
ssrf-guard is meant to complement that, not replace it.

## Design decisions

Short version; the reasoning is in [docs/design.md](docs/design.md).

- **Pin at the socket, not before the request.** The httpx integration wraps
  httpcore's network backend; the requests integration overrides urllib3's
  `HTTPConnection._new_conn`. Both receive the hostname exactly as the
  client will use it, resolve it once through the guard and connect to the
  vetted IP. TLS code above that layer is untouched.
- **Refuse, don't repair.** The URL parser is narrower than RFC 3986 and
  WHATWG. Anything two parsers might read differently is an error, and the
  result is compared with `urllib.parse.urlsplit` as a final cross-check.
- **Canonical IPv4 only by default.** Legacy forms (`0x7f.1`) are refused
  even when public, because they are almost always an evasion attempt; the
  policy can opt into normalizing them.
- **Every answer must pass.** A resolver answer that mixes a public and a
  blocked address is refused as a whole.
- **Block the special-purpose registries, not just RFC 1918.** The default
  list follows the IANA IPv4/IPv6 special-purpose registries, including
  CGNAT, benchmarking, documentation, 6to4 and Teredo prefixes.
- **Fail closed on library drift, where possible.** The integrations depend
  on two internals (httpcore's `_network_backend`, urllib3's `_new_conn`).
  The httpx transport refuses to start if the attribute is missing; for
  urllib3 the dependency is capped below 3.0 and the real-socket tests
  assert that the guard ran on every connection.

## Bypass catalog

Each row is one technique, run through `Guard.resolve` with a scripted DNS
resolver in [`tests/test_bypass_catalog.py`](tests/test_bypass_catalog.py).
The table is generated from that file by `scripts/render_catalog.py`, and
`test_readme_table_is_current` fails if they drift. "Result" is the
exception `code` (or `allowed` for the controls that must keep working).
Real-socket versions of the DNS-rebinding, redirect and TLS rows live in
[`tests/test_integration_httpx.py`](tests/test_integration_httpx.py) and
[`tests/test_integration_requests.py`](tests/test_integration_requests.py)
(`test_dns_rebinding_between_connections`, `test_redirect_to_metadata_is_blocked`,
`test_tls_keeps_sni_host_and_cert_verification`, ...).

<!-- catalog:begin (generated by scripts/render_catalog.py) -->
| ID | Category | Input | Result | CWE | Note |
|---|---|---|---|---|---|
| [`loopback-v4`](tests/test_bypass_catalog.py) | loopback | `http://127.0.0.1/` | `blocked_address` | CWE-918 | IPv4 loopback |
| [`loopback-v4-range`](tests/test_bypass_catalog.py) | loopback | `http://127.200.1.1/` | `blocked_address` | CWE-918 | all of 127/8 is loopback |
| [`loopback-v6`](tests/test_bypass_catalog.py) | loopback | `http://[::1]/` | `blocked_address` | CWE-918 | IPv6 loopback |
| [`unspecified-v4`](tests/test_bypass_catalog.py) | loopback | `http://0.0.0.0/` | `blocked_address` | CWE-918 | 0.0.0.0 connects to the local host |
| [`unspecified-short`](tests/test_bypass_catalog.py) | loopback | `http://0/` | `blocked_address` | CWE-918 | '0' is 0.0.0.0 to inet_aton |
| [`unspecified-v6`](tests/test_bypass_catalog.py) | loopback | `http://[::]/` | `blocked_address` | CWE-918 | IPv6 unspecified |
| [`localhost`](tests/test_bypass_catalog.py) | loopback | `http://localhost/` | `blocked_hostname` | CWE-918 | reserved name (RFC 6761) |
| [`localhost-sub`](tests/test_bypass_catalog.py) | loopback | `http://a.b.localhost/` | `blocked_hostname` | CWE-918 | every subdomain too |
| [`localhost-dot`](tests/test_bypass_catalog.py) | loopback | `http://localhost./` | `blocked_hostname` | CWE-918 | absolute (trailing-dot) form |
| [`localhost-case`](tests/test_bypass_catalog.py) | loopback | `http://LocalHost/` | `blocked_hostname` | CWE-918 | case-insensitive |
| [`ipv4-decimal`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://2130706433/` | `blocked_address` | CWE-918 | 32-bit integer |
| [`ipv4-hex`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://0x7f000001/` | `blocked_address` | CWE-918 | hex integer |
| [`ipv4-octal`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://0177.0.0.1/` | `blocked_address` | CWE-918 | octal octet |
| [`ipv4-short2`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://127.1/` | `blocked_address` | CWE-918 | two-part form |
| [`ipv4-short3`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://127.0.1/` | `blocked_address` | CWE-918 | three-part form |
| [`ipv4-mixed`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://0x7f.0.0.01/` | `blocked_address` | CWE-918 | mixed radixes |
| [`ipv4-octal-meta`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://0251.0376.0251.0376/` | `blocked_address` | CWE-918 | 169.254.169.254 in octal |
| [`ipv4-trailing-dot`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://127.0.0.1./` | `blocked_address` | CWE-918 | trailing dot |
| [`ipv4-public-legacy`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://134744072/` | `noncanonical_address` | CWE-918 | legacy forms refused even when public (8.8.8.8) |
| [`ipv4-public-legacy-opt-in`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://0x8.0x8.0x8.0x8/` | allowed | CWE-918 | opt-in normalizes to dotted quad |
| [`ipv4-out-of-range`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://256.0.0.1/` | `invalid_host` | CWE-918 | octet > 255 |
| [`ipv4-five-parts`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://1.2.3.4.5/` | `invalid_host` | CWE-918 | ends in a number but is not IPv4 |
| [`ipv4-octal-invalid`](tests/test_bypass_catalog.py) | ipv4-encoding | `http://08.0.0.1/` | `invalid_host` | CWE-918 | '08' is not octal |
| [`fullwidth-digits`](tests/test_bypass_catalog.py) | unicode | `http://１２７.０.０.１/` | `blocked_address` | CWE-918 | fullwidth digits fold to 127.0.0.1 (NFKC) |
| [`ideographic-dots`](tests/test_bypass_catalog.py) | unicode | `http://127。0。0。1/` | `blocked_address` | CWE-918 | U+3002 is a label separator |
| [`circled-letters`](tests/test_bypass_catalog.py) | unicode | `http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/` | `blocked_hostname` | CWE-918 | circled letters fold to 'localhost' |
| [`zero-width`](tests/test_bypass_catalog.py) | unicode | `http://local\u200bhost/` | `blocked_hostname` | CWE-918 | zero-width space removed by nameprep |
| [`soft-hyphen`](tests/test_bypass_catalog.py) | unicode | `http://local\xadhost/` | `blocked_hostname` | CWE-918 | soft hyphen removed too |
| [`idn-ok`](tests/test_bypass_catalog.py) | unicode | `http://bücher.example/` | allowed | CWE-918 | legitimate IDN resolved by its punycode |
| [`idn-disabled`](tests/test_bypass_catalog.py) | unicode | `http://bücher.example/` | `invalid_host` | CWE-918 | allow_idna=False refuses non-ASCII |
| [`v4-mapped`](tests/test_bypass_catalog.py) | ipv6-embedding | `http://[::ffff:127.0.0.1]/` | `blocked_address` | CWE-918 | IPv4-mapped |
| [`v4-mapped-hex`](tests/test_bypass_catalog.py) | ipv6-embedding | `http://[::ffff:7f00:1]/` | `blocked_address` | CWE-918 | IPv4-mapped, hex |
| [`v4-mapped-meta`](tests/test_bypass_catalog.py) | ipv6-embedding | `http://[::ffff:a9fe:a9fe]/` | `blocked_address` | CWE-918 | IPv4-mapped metadata address |
| [`v4-compatible`](tests/test_bypass_catalog.py) | ipv6-embedding | `http://[::127.0.0.1]/` | `blocked_address` | CWE-918 | deprecated IPv4-compatible |
| [`nat64`](tests/test_bypass_catalog.py) | ipv6-embedding | `http://[64:ff9b::a9fe:a9fe]/` | `blocked_address` | CWE-918 | NAT64 well-known prefix to 169.254.169.254 |
| [`nat64-local`](tests/test_bypass_catalog.py) | ipv6-embedding | `http://[64:ff9b:1::a00:1]/` | `blocked_address` | CWE-918 | local-use NAT64 prefix (RFC 8215) |
| [`6to4`](tests/test_bypass_catalog.py) | ipv6-embedding | `http://[2002:7f00:1::]/` | `blocked_address` | CWE-918 | 6to4 of 127.0.0.1 |
| [`6to4-private`](tests/test_bypass_catalog.py) | ipv6-embedding | `http://[2002:c0a8:101::1]/` | `blocked_address` | CWE-918 | 6to4 of 192.168.1.1 |
| [`teredo`](tests/test_bypass_catalog.py) | ipv6-embedding | `http://[2001:0:4136:e378:8000:63bf:80ff:fffe]/` | `blocked_address` | CWE-918 | Teredo client 127.0.0.1 |
| [`ipv6-ula`](tests/test_bypass_catalog.py) | ipv6 | `http://[fd00::1]/` | `blocked_address` | CWE-918 | unique local (fc00::/7) |
| [`ipv6-link-local`](tests/test_bypass_catalog.py) | ipv6 | `http://[fe80::1]/` | `blocked_address` | CWE-918 | link-local |
| [`ipv6-zone-id`](tests/test_bypass_catalog.py) | ipv6 | `http://[fe80::1%25eth0]/` | `invalid_host` | CWE-918 | zone identifiers refused |
| [`ipv6-site-local`](tests/test_bypass_catalog.py) | ipv6 | `http://[fec0::1]/` | `blocked_address` | CWE-918 | deprecated site-local |
| [`ipv6-multicast`](tests/test_bypass_catalog.py) | ipv6 | `http://[ff02::1]/` | `blocked_address` | CWE-918 | multicast |
| [`ipv6-doc`](tests/test_bypass_catalog.py) | ipv6 | `http://[2001:db8::1]/` | `blocked_address` | CWE-918 | documentation |
| [`ipv6-unbalanced`](tests/test_bypass_catalog.py) | ipv6 | `http://[::1/` | `invalid_url` | CWE-918 | missing ']' |
| [`ipv6-garbage`](tests/test_bypass_catalog.py) | ipv6 | `http://[::1]x/` | `invalid_url` | CWE-918 | text after ']' |
| [`imds`](tests/test_bypass_catalog.py) | metadata | `http://169.254.169.254/latest/meta-data/` | `blocked_address` | CWE-918 | AWS/GCP/Azure/OpenStack link-local metadata |
| [`imds-v6`](tests/test_bypass_catalog.py) | metadata | `http://[fd00:ec2::254]/` | `blocked_address` | CWE-918 | AWS IMDS over IPv6 |
| [`ecs-metadata`](tests/test_bypass_catalog.py) | metadata | `http://169.254.170.2/v2/credentials` | `blocked_address` | CWE-918 | AWS ECS task credentials |
| [`gcp-name`](tests/test_bypass_catalog.py) | metadata | `http://metadata.google.internal/` | `blocked_hostname` | CWE-918 | GCP metadata hostname |
| [`gcp-short`](tests/test_bypass_catalog.py) | metadata | `http://metadata/` | `blocked_hostname` | CWE-918 | single-label metadata alias |
| [`alibaba`](tests/test_bypass_catalog.py) | metadata | `http://100.100.100.200/` | `blocked_address` | CWE-918 | Alibaba Cloud (CGNAT range) |
| [`oracle`](tests/test_bypass_catalog.py) | metadata | `http://192.0.0.192/` | `blocked_address` | CWE-918 | Oracle Cloud (IETF protocol range) |
| [`azure-wireserver`](tests/test_bypass_catalog.py) | metadata | `http://168.63.129.16/` | `blocked_address` | CWE-918 | public address; NOT blocked by default, needs deny_cidrs |
| [`rfc1918-10`](tests/test_bypass_catalog.py) | private | `http://10.0.0.1/` | `blocked_address` | CWE-918 | RFC 1918 |
| [`rfc1918-172`](tests/test_bypass_catalog.py) | private | `http://172.16.0.1/` | `blocked_address` | CWE-918 | RFC 1918 |
| [`rfc1918-192`](tests/test_bypass_catalog.py) | private | `http://192.168.1.1/` | `blocked_address` | CWE-918 | RFC 1918 |
| [`cgnat`](tests/test_bypass_catalog.py) | private | `http://100.64.0.1/` | `blocked_address` | CWE-918 | shared address space (RFC 6598) |
| [`link-local-v4`](tests/test_bypass_catalog.py) | private | `http://169.254.1.1/` | `blocked_address` | CWE-918 | link-local |
| [`benchmark`](tests/test_bypass_catalog.py) | private | `http://198.18.0.1/` | `blocked_address` | CWE-918 | benchmarking (RFC 2544) |
| [`multicast-v4`](tests/test_bypass_catalog.py) | private | `http://224.0.0.1/` | `blocked_address` | CWE-918 | multicast |
| [`reserved-v4`](tests/test_bypass_catalog.py) | private | `http://240.0.0.1/` | `blocked_address` | CWE-918 | reserved (class E) |
| [`broadcast`](tests/test_bypass_catalog.py) | private | `http://255.255.255.255/` | `blocked_address` | CWE-918 | limited broadcast |
| [`deny-cidr`](tests/test_bypass_catalog.py) | private | `http://8.8.8.8/` | `blocked_address` | CWE-918 | user deny list beats everything |
| [`allow-cidr`](tests/test_bypass_catalog.py) | private | `http://10.1.2.3/` | allowed | CWE-918 | explicit allow list exception |
| [`userinfo`](tests/test_bypass_catalog.py) | syntax | `http://user:pass@example.com/` | `userinfo_not_allowed` | CWE-918 | credentials in URL |
| [`userinfo-confusion`](tests/test_bypass_catalog.py) | syntax | `http://example.com@127.0.0.1/` | `userinfo_not_allowed` | CWE-918 | host after '@' |
| [`userinfo-colon`](tests/test_bypass_catalog.py) | syntax | `http://example.com:80@127.0.0.1/` | `userinfo_not_allowed` | CWE-918 | port-looking userinfo |
| [`at-in-path`](tests/test_bypass_catalog.py) | syntax | `http://example.com/@127.0.0.1` | allowed | CWE-918 | '@' after the path starts is harmless |
| [`fragment-confusion`](tests/test_bypass_catalog.py) | syntax | `http://example.com#@127.0.0.1/` | allowed | CWE-918 | '@' in the fragment is harmless |
| [`query-confusion`](tests/test_bypass_catalog.py) | syntax | `http://example.com?@127.0.0.1/` | allowed | CWE-918 | '@' in the query is harmless |
| [`backslash-at`](tests/test_bypass_catalog.py) | syntax | `http://example.com\\@127.0.0.1/` | `invalid_url` | CWE-918 | WHATWG treats '\' as '/', RFC 3986 does not |
| [`backslash-slashes`](tests/test_bypass_catalog.py) | syntax | `http:\\\\127.0.0.1\\` | `invalid_url` | CWE-918 | backslashes instead of '//' |
| [`tab-in-host`](tests/test_bypass_catalog.py) | syntax | `http://127.0.0.\x091/` | `invalid_url` | CWE-918 | WHATWG strips tabs |
| [`crlf`](tests/test_bypass_catalog.py) | syntax | `http://example.com/\x0d\x0aX-Injected:\x201` | `invalid_url` | CWE-918, CWE-93 | header injection |
| [`nul`](tests/test_bypass_catalog.py) | syntax | `http://example.com\x00.127.0.0.1/` | `invalid_url` | CWE-918 | NUL byte |
| [`space-host`](tests/test_bypass_catalog.py) | syntax | `http://127.0.0.1\x20example.com/` | `invalid_url` | CWE-918 | space in authority |
| [`c1-control`](tests/test_bypass_catalog.py) | syntax | `http://example.com\x85/` | `invalid_url` | CWE-918 | C1 control (NEL) |
| [`scheme-relative`](tests/test_bypass_catalog.py) | syntax | `//127.0.0.1/` | `invalid_url` | CWE-918 | no scheme |
| [`single-slash`](tests/test_bypass_catalog.py) | syntax | `http:/127.0.0.1/` | `invalid_url` | CWE-918 | WHATWG repairs, RFC 3986 does not |
| [`triple-slash`](tests/test_bypass_catalog.py) | syntax | `http:///127.0.0.1/` | `invalid_host` | CWE-918 | empty authority |
| [`empty-host`](tests/test_bypass_catalog.py) | syntax | `http://` | `invalid_host` | CWE-918 | no host |
| [`empty-host-port`](tests/test_bypass_catalog.py) | syntax | `http://:80/` | `invalid_host` | CWE-918 | port without host |
| [`percent-host`](tests/test_bypass_catalog.py) | syntax | `http://%31%32%37.0.0.1/` | `invalid_host` | CWE-918 | percent-encoded host |
| [`percent-dot`](tests/test_bypass_catalog.py) | syntax | `http://127%2e0.0.1/` | `invalid_host` | CWE-918 | percent-encoded dot |
| [`bad-label`](tests/test_bypass_catalog.py) | syntax | `http://exa$mple.com/` | `invalid_host` | CWE-918 | forbidden host character |
| [`overlong`](tests/test_bypass_catalog.py) | syntax | `http://example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa...` | `invalid_url` | CWE-918 | length limit (DoS) |
| [`upper-scheme`](tests/test_bypass_catalog.py) | syntax | `HTTP://Example.COM/` | allowed | CWE-918 | scheme and host are case-folded |
| [`port-zero`](tests/test_bypass_catalog.py) | port | `http://example.com:0/` | `invalid_port` | CWE-918 | port 0 |
| [`port-overflow`](tests/test_bypass_catalog.py) | port | `http://example.com:65616/` | `invalid_port` | CWE-918 | wraps to 80 in some parsers |
| [`port-empty`](tests/test_bypass_catalog.py) | port | `http://example.com:/` | `invalid_port` | CWE-918 | empty port |
| [`port-sign`](tests/test_bypass_catalog.py) | port | `http://example.com:+80/` | `invalid_port` | CWE-918 | signed port |
| [`port-fullwidth`](tests/test_bypass_catalog.py) | port | `http://example.com:８０/` | `invalid_port` | CWE-918 | non-ASCII digits |
| [`port-double`](tests/test_bypass_catalog.py) | port | `http://127.0.0.1:80:80/` | `invalid_port` | CWE-918 | two ports |
| [`port-policy`](tests/test_bypass_catalog.py) | port | `http://example.com:6379/` | `port_not_allowed` | CWE-918 | allowed_ports |
| [`file`](tests/test_bypass_catalog.py) | scheme | `file:///etc/passwd` | `scheme_not_allowed` | CWE-918 | local file read |
| [`gopher`](tests/test_bypass_catalog.py) | scheme | `gopher://127.0.0.1:6379/_FLUSHALL` | `scheme_not_allowed` | CWE-918 | raw TCP payloads (Redis, SMTP...) |
| [`dict`](tests/test_bypass_catalog.py) | scheme | `dict://127.0.0.1:11211/stat` | `scheme_not_allowed` | CWE-918 | dict:// |
| [`ftp`](tests/test_bypass_catalog.py) | scheme | `ftp://example.com/` | `scheme_not_allowed` | CWE-918 | ftp:// |
| [`data`](tests/test_bypass_catalog.py) | scheme | `data:text/plain,hi` | `scheme_not_allowed` | CWE-918 | data: |
| [`no-default-port`](tests/test_bypass_catalog.py) | scheme | `foo://example.com/` | `invalid_port` | CWE-918 | allowed scheme without a default port must give one |
| [`dns-private`](tests/test_bypass_catalog.py) | dns | `http://intranet.example/` | `blocked_address` | CWE-918 | A record to RFC 1918 |
| [`dns-loopback`](tests/test_bypass_catalog.py) | dns | `http://127.0.0.1.nip.io/` | `blocked_address` | CWE-918 | wildcard DNS services echo the IP |
| [`dns-mixed`](tests/test_bypass_catalog.py) | dns | `http://mixed.example/` | `blocked_address` | CWE-918 | one bad answer among good ones blocks |
| [`dns-aaaa-mapped`](tests/test_bypass_catalog.py) | dns | `http://aaaa.example/` | `blocked_address` | CWE-918 | AAAA record with IPv4-mapped metadata |
| [`dns-nxdomain`](tests/test_bypass_catalog.py) | dns | `http://nxdomain.example/` | `resolution_failed` | CWE-918 | unresolvable |
| [`dns-public`](tests/test_bypass_catalog.py) | dns | `http://example.com/` | allowed | CWE-918 | ordinary public host |
| [`single-label`](tests/test_bypass_catalog.py) | dns | `http://intranet/` | `blocked_hostname` | CWE-918 | search-domain expansion |
| [`internal-tld`](tests/test_bypass_catalog.py) | dns | `http://db.internal/` | `blocked_hostname` | CWE-918 | private-use TLD |
| [`mdns`](tests/test_bypass_catalog.py) | dns | `http://printer.local/` | `blocked_hostname` | CWE-918 | multicast DNS |
| [`home-arpa`](tests/test_bypass_catalog.py) | dns | `http://router.home.arpa/` | `blocked_hostname` | CWE-918 | home networks (RFC 8375) |
<!-- catalog:end -->

## How it is tested

| Check | Result (2026-10-28, Python 3.12) |
|---|---|
| `pytest` | all tests pass (unit, catalog, property and integration) |
| Coverage | 100 % lines and branches; CI fails under 95 % |
| Hypothesis | 6 properties; also run once with 20,000 examples each, no counterexample |
| Integration | real sockets on loopback, `trustme` certificates, SNI and `Host` asserted server-side |
| Atheris | 2 × 180 s, ~8.2 M executions each; first run found the 6to4 issue below |
| `mypy --strict` | clean (sources, tests, fuzz harness, scripts, benchmarks) |
| `ruff` | clean, including the `S` (bandit) rule set |
| `semgrep --test` | 2/2 rules pass their annotated test file |

The fuzzer's oracle compares every address the guard allows with the
standard library's `ipaddress.is_global`. It found that `2002::/16` (6to4)
addresses with a public embedded IPv4 address were allowed, although IANA
marks the whole prefix as not globally reachable. 6to4 is now blocked
outright and the input is kept as a regression seed. See
[fuzz/README.md](fuzz/README.md).

## Performance

`benchmarks/bench_guard.py`, Python 3.12 in Docker on a shared VPS, best of 5:

| Operation | Time per call |
|---|---|
| `parse_url` (hostname URL) | ~15 µs |
| `parse_url` (IPv6 literal) | ~27 µs |
| `Guard.resolve` with a static resolver | ~22 µs |
| `Policy.is_address_allowed` (IPv4 / IPv6) | ~6.5 / ~7.4 µs |
| httpx, new loopback connection: plain / guarded | 0.99-1.01 / 1.00-1.15 ms |
| httpx, keep-alive: plain / guarded | ~0.41 / ~0.50 ms |
| requests, new loopback connection: plain / guarded | 1.00-1.33 / 1.16-1.46 ms |

The guard costs tens of microseconds of CPU per request, plus the DNS
lookup the client would have made anyway. Loopback round trips are the
best case for making that visible; across a real network it disappears in
the noise. Numbers vary by about ±15 % between runs.

## Limitations

These are known and deliberate, or known and not yet solved:

- **Internals.** The integrations use httpcore's `ConnectionPool._network_backend`
  and urllib3's `HTTPConnection._new_conn` / `_dns_host`. Version ranges are
  pinned in `pyproject.toml`, and the httpx integration refuses to start if
  the attribute is missing.
- **Keep-alive.** A pooled connection is not re-resolved for later requests;
  it was vetted when it was opened and still goes to that address.
- **IDNA.** Non-ASCII hostnames are converted with Python's IDNA 2003 codec,
  which differs from IDNA 2008/UTS 46 for some characters (e.g. `ß`). A name
  can therefore resolve to a different *public* host than a browser would
  pick, though never to a blocked address. Set `allow_idna=False` to refuse
  such names.
- **DNS timeouts.** `SystemResolver` calls `getaddrinfo`, which has no
  timeout. Supply your own `Resolver` if that matters.
- **Connect timeouts** apply per address, so a name with N vetted addresses
  can take up to N times the connect timeout to fail.
- **Redirect checks** run in a response hook. With `follow_redirects=False`
  a disallowed `Location` still raises, instead of returning the 3xx.
- **Policy choices you may want to change:** 6to4 (`2002::/16`) and all of
  `2001::/23` (including Teredo) are blocked wholesale; Azure's
  `168.63.129.16` is a public address and not blocked by default.
- **Fuzzing** has been a few minutes of CPU time; treat its results as a
  smoke test.

## Semgrep rules

[`semgrep/ssrf.yml`](semgrep/ssrf.yml) has two rules for Python services:

- `unguarded-request-to-user-url` (CWE-918): taint from Flask/Django request
  data into `requests`/`httpx`/`urllib` calls that are not guarded clients.
- `validate-then-fetch-toctou` (CWE-367): validating a URL and then fetching
  the original URL, which re-resolves it.

```sh
semgrep --config semgrep/ssrf.yml path/to/your/service
```

They are heuristics: they miss sources from other frameworks and the
`client.request("GET", url)` form on long-lived client objects.

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. Copyright 2026 Bruno Rangel Borges Marchetti. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
