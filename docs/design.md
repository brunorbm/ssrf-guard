# Design

This document explains how ssrf-guard is put together and why. The README
has the user-facing summary.

## Components

```
            URL string
                |
   +------------v-------------+
   | url.parse_url            |  strict syntax, scheme/port/userinfo policy,
   |  _host.parse_host        |  host normalization (IP literals, IDNA),
   |  urllib.parse cross-check|  differential check against urlsplit
   +------------+-------------+
                | ParsedURL (no DNS yet)
   +------------v-------------+
   | Guard                    |  resolve once with a Resolver,
   |  Policy.check_hostname   |  check reserved names before DNS,
   |  Resolver.resolve        |  check *every* answer,
   |  Policy.check_address    |  return PinnedTarget / tuple of IPs
   +------------+-------------+
                | vetted IPs
   +------------v-------------+       +-----------------------------+
   | httpx: _GuardedBackend   |  or   | requests: GuardedHTTP(S)    |
   |  (httpcore NetworkBackend|       |  Connection._new_conn       |
   |   .connect_tcp)          |       |  (urllib3)                  |
   +------------+-------------+       +--------------+--------------+
                |  TCP connect to the vetted IP; TLS above uses the hostname
                v
```

- `ssrf_guard.url` and `ssrf_guard._host` do no I/O. They turn a string
  into a `ParsedURL` or raise.
- `ssrf_guard.policy.Policy` is an immutable value object: which schemes,
  ports, names and addresses are reachable.
- `ssrf_guard.resolver.Resolver` is a one-method protocol. The default,
  `SystemResolver`, calls `getaddrinfo` so `/etc/hosts` and the system's
  RFC 6724 ordering apply. Tests use a scripted resolver.
- `ssrf_guard.guard.Guard` combines them. `resolve(url)` is the general
  API; `resolve_host(host, port)` is what the integrations call at connect
  time, when the client has already split the URL.

## Why resolve-and-pin, and why at the socket

The classic SSRF fix validates the URL and then hands the *URL* to an HTTP
client. That has a time-of-check to time-of-use gap (CWE-367): the client
resolves the hostname a second time. With an attacker-controlled
authoritative DNS server and TTL 0, the first answer is public and the
second is `127.0.0.1` ("DNS rebinding"). Caching does not reliably help;
the OS, a local stub resolver, or Happy Eyeballs may each make their own
query, and any of them can pick a different address from a multi-record
answer.

There are three places one could close that gap:

1. **Rewrite the URL to the IP** (`http://93.184.215.14/` with a `Host`
   header). This breaks TLS: SNI would carry the IP and the certificate
   would be checked against the IP. Workarounds (disabling hostname checks,
   custom SSL contexts per request) are easy to get wrong. `PinnedTarget`
   still offers `pinned_url` for clients that have no other hook, but the
   integrations do not use it.
2. **Patch DNS globally** (monkeypatch `socket.getaddrinfo`). This affects
   every library in the process, is not thread-safe to scope, and silently
   stops working if a library uses its own resolver.
3. **Hook the connect call of one client.** The client keeps the hostname
   for everything above TCP (Host header, SNI, certificate verification,
   connection pooling keys), and only the step that turns a name into a
   socket is replaced. This is what the integrations do.

For httpx, the hook is httpcore's `NetworkBackend.connect_tcp(host, port)`.
`SSRFGuardTransport` builds a normal `httpx.HTTPTransport` and wraps its
pool's backend. For requests, urllib3's `HTTPConnection._new_conn()` is
the single place that creates sockets, so the adapter installs pool classes
whose connection classes override it. In both cases the address list comes
from `Guard.resolve_host`, and the code tries each vetted address in order
(the same fallback a normal client does), never re-resolving.

Because the hook sits under the redirect logic and under the connection
pool, every redirect hop and every new pooled connection is checked
without any extra code. The redirect *hook* that the convenience
constructors add exists only for policy that the socket layer cannot see,
namely scheme changes (`https` to `http`) and the redirect count.

## Every answer must pass

`Guard` rejects the whole resolution if any address is blocked, rather than
filtering the bad ones out. Filtering looks friendlier, but it hands an
attacker an oracle (which of my records survived?) and, with clients that
re-resolve, a race. A legitimate public service has no reason to publish a
private address in the same record set.

## Parsing: refuse, don't repair

URL parsers disagree. The WHATWG standard (browsers, Node, some Python
libraries) strips tabs and newlines, treats `\` as `/` in special schemes,
decodes percent-encoded hosts and accepts `0x7f.1`; RFC 3986 parsers
(`urllib.parse`, most HTTP clients) do not. If a validator reads one host
and the client reads another, the validator is irrelevant.

The parser therefore accepts a deliberately small language:

- scheme, `//`, host, optional decimal port, then path/query/fragment;
- no whitespace, control characters (C0 and C1) or backslashes anywhere;
- no userinfo (`user:pass@`), because `@` is the most common differential;
- hosts are a DNS name (LDH labels, optionally IDNA), a canonical dotted-quad
  IPv4 address or a bracketed IPv6 address without a zone ID;
- percent-encoding in the host is refused;
- Unicode hosts are NFKC-normalized, and ideographic full stops mapped to
  `.`, *before* any decision, so `１２７。０。０。１` is recognized as the IPv4
  address it spells (and blocked), and a folded character that is not
  allowed in a DNS label is refused.

After parsing, the result is compared with `urllib.parse.urlsplit` (host
and port). Any disagreement raises `ParserDifferentialError`. The
cross-check is cheap and catches classes of mistakes in this parser that
the tests did not think of.

Legacy IPv4 spellings are decoded (with the same rules as `inet_aton` and
WHATWG) so that a blocked address is reported as blocked, but by default
they are refused even when the address is public: a URL with
`http://0x08.0x08.0x08.0x08/` is far more likely to be a probe than a
customer webhook. `Policy(allow_noncanonical_ipv4=True)` normalizes them
instead.

## Address policy

The default `blocked_networks` list is the union of the IANA IPv4 and IPv6
special-purpose address registries' "not globally reachable" entries that
matter for a server-side fetch, plus multicast and the reserved class E
range. Each entry carries the reason that ends up in the exception.

IPv6 has several ways to *embed* an IPv4 address so that a packet ends up
at that IPv4 destination: IPv4-mapped (`::ffff:a.b.c.d`, handled by the
local stack), NAT64 (`64:ff9b::/96`, by a gateway), 6to4 (`2002::/16`) and
Teredo (`2001::/32`, by relays). `Policy.address_block_reason` extracts
these and evaluates the embedded address with the same rules. The order is:

1. `deny_cidrs` on the literal address: blocked;
2. any embedded IPv4 address, recursively: blocked if it is;
3. `allow_cidrs` on the literal address: allowed;
4. `blocked_networks`: blocked;
5. otherwise allowed.

Embedded addresses come before `allow_cidrs` so that allowing a
translation prefix (for example `64:ff9b::/96` on a NAT64-only network)
cannot be used to reach `64:ff9b::7f00:1`, i.e. `127.0.0.1`.

6to4 and Teredo are blocked wholesale by default. Both are deprecated or
obsolete, IANA lists them as not globally reachable, and a fuzzing run
(see `fuzz/README.md`) showed that judging them only by the embedded
address made the policy disagree with the registry.

Hostnames in `blocked_domains` (`localhost`, `internal`, `local`,
`home.arpa`, the GCP metadata names, ...) and single-label names are
refused *before* DNS. This is defense in depth, not the main control: the
addresses those names resolve to are checked anyway, but an internal
resolver may map them to anything, and a query for them can itself leak.

## Comparison with a naive allow/deny list

| | Deny list on the URL string | Deny list after one `getaddrinfo` | ssrf-guard |
|---|---|---|---|
| Alternate IPv4 spellings | each spelling needs a rule | handled by the resolver | decoded, then refused |
| IPv4 inside IPv6 | usually missed | usually missed | checked recursively |
| DNS names pointing inside | missed | caught | caught |
| DNS rebinding | missed | **missed** (client resolves again) | closed (pinned) |
| Redirects | missed unless disabled | missed unless re-checked | every hop checked at connect |
| Parser differentials | missed | partly | refused, cross-checked |
| TLS hostname verification | kept | kept | kept |

An *allow* list of hostnames is a different, stronger control when it is
possible. It still needs pinning (an allowed name can be repointed if its
DNS is compromised or a subdomain is taken over), so the two compose:
check the host against your list, then use a guarded client.

## Things this design gives up

- **Keep-alive is trusted.** Once a connection is open, later requests
  reuse it without re-resolving. Re-resolving would not add safety: the
  connection already goes to the vetted address.
- **Private internals.** Hooking at the socket needs one non-public
  attribute in each client stack. The alternatives (URL rewriting, global
  DNS patching) are worse; the cost is a version cap and tests that fail
  loudly if the hook stops being called.
- **No proxy support.** Supporting `CONNECT` proxies correctly would mean
  resolving and checking at the proxy, which this library cannot do.
- **Blocking `getaddrinfo`.** The async integration runs it in a worker
  thread. A custom `Resolver` can use an async-capable or timeout-aware
  library if needed.
