# Fuzzing

`fuzz_url.py` is an [Atheris](https://github.com/google/atheris) harness for
`Guard.resolve`: the URL parser, the host normalizer and the address policy,
with resolver answers taken from the fuzz input. Its oracles are described in
the module docstring; in short, only `SSRFGuardError` may escape, every
address the guard hands back (and every IPv4 address embedded in an IPv6
one) must be `is_global` and not multicast per the standard library, and
re-parsing the normalized URL must be a fixed point.

```sh
docker run --rm -v "$PWD:/w" -w /w -e PYTHONPATH=/w/src python:3.12-slim sh -c \
  'pip install -q atheris && python fuzz/fuzz_url.py -max_total_time=180 -artifact_prefix=/tmp/ fuzz/seeds'
```

Without Atheris installed the script falls back to a seeded random mutator
over `seeds/`; that mode is only a smoke test.

## Results

| Date       | Python | Duration | Executions | Outcome |
|------------|--------|----------|------------|---------|
| 2026-10-28 | 3.12   | 180 s    | ~8.2 M     | Oracle violation: `2002:8000::feff:0:0` (6to4) was allowed |
| 2026-10-28 | 3.12   | 181 s    | 8,240,990  | No violation after the fix below |

The finding was a disagreement between the policy and the IANA
special-purpose registry rather than a reachable bypass: the policy allowed
6to4 addresses whose embedded IPv4 address was public, while `2002::/16`
is not globally reachable per RFC 6890 / RFC 7526. 6to4 is now blocked
wholesale, embedded addresses are judged before `allow_cidrs`, and the input
is kept as `seeds/regression_6to4_public` plus a Hypothesis `@example`.

These are short campaigns on one machine; they say the oracles held for
those inputs, not that the parser is free of bugs.
