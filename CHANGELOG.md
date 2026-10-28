# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-28

### Added

- Strict URL parser with an `urllib.parse` differential check, WHATWG-style
  IPv4 decoding, NFKC/IDNA host normalization and stable error codes.
- `Policy` with an IANA special-purpose blocklist, embedded-IPv4 checks
  (IPv4-mapped, NAT64, 6to4, Teredo), allow/deny CIDRs, blocked domains,
  port and scheme allowlists, and redirect limits.
- `Guard` / `validate_url`: resolve once, require every answer to pass and
  return a `PinnedTarget`.
- httpx integration (`SSRFGuardTransport`, `AsyncSSRFGuardTransport`,
  `guarded_client`, `guarded_async_client`) that pins at the network backend.
- requests integration (`SSRFGuardAdapter`, `guarded_session`) that pins in
  urllib3's connection class.
- Bypass catalog of 112 cases, Hypothesis properties, real-socket TLS and
  DNS-rebinding tests, an Atheris harness, Semgrep rules and benchmarks.

### Security

- 6to4 (`2002::/16`) is blocked as a whole, and embedded IPv4 addresses are
  judged before `allow_cidrs`. Found by fuzzing before the first release.

[Unreleased]: https://github.com/brunorbm/ssrf-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/brunorbm/ssrf-guard/releases/tag/v0.1.0
