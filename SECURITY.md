# Security policy

ssrf-guard is a security control, so a bypass is a vulnerability even when
it needs an unusual configuration.

## Supported versions

Only the latest release receives fixes while the project is pre-1.0.

## Reporting a vulnerability

Please report privately through GitHub's
[private vulnerability reporting](https://github.com/brunorbm/ssrf-guard/security/advisories/new)
for `brunorbm/ssrf-guard`. Do not open a public issue for a bypass.

A useful report contains:

- the URL (or resolver answers, redirect chain) that reaches a destination
  the policy should block, and the `Policy` used;
- Python, httpx/httpcore or requests/urllib3 versions;
- what the guard did and what you expected.

What to expect: an acknowledgement within 7 days, an assessment within 30
days, and a fix plus a GitHub security advisory (with credit, if you want
it) for confirmed issues. Every confirmed bypass also becomes a row in the
bypass catalog (`tests/test_bypass_catalog.py`).

## In scope

- A URL, DNS answer or redirect that makes a guarded client connect to an
  address the policy blocks.
- Parser differentials: a URL the guard validates as one host that the
  integrated client sends to another.
- A crash or exception other than `SSRFGuardError` from the parser on any
  input (the fuzz harness treats this as a bug).

## Out of scope

The limitations listed in the README, for example requests that do not go
through a guarded client, proxies, keep-alive reuse of an already vetted
connection, side channels, and destinations your policy allows on purpose.
