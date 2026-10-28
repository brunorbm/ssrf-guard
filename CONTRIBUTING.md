# Contributing

Thanks for helping. Bypass reports go through [SECURITY.md](SECURITY.md),
not public issues.

## Setup

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pre-commit install          # optional; mirrors the CI checks
```

Or without touching the host Python:

```sh
docker run --rm -v "$PWD:/w" -w /w python:3.12-slim sh -c \
  'pip install -q -e ".[dev]" && python -m pytest --cov'
```

## Checks (all run in CI)

```sh
python -m pytest --cov                 # 100 % line+branch today; CI fails under 95 %
ruff format --check . && ruff check .
mypy                                   # strict; covers src, tests, fuzz, scripts, benchmarks
python scripts/render_catalog.py --check
semgrep --test semgrep/
```

Optional, slower:

```sh
HYPOTHESIS_PROFILE=thorough python -m pytest tests/test_properties.py
pip install atheris && PYTHONPATH=src python fuzz/fuzz_url.py -max_total_time=300 fuzz/seeds
PYTHONPATH=src python benchmarks/bench_guard.py
```

## Adding a bypass case

1. Add a `Case(...)` to `CASES` in `tests/test_bypass_catalog.py` with the
   expected exception class (or `None` for something that must stay allowed).
   Use `dns=` to script resolver answers and `policy=` for a non-default policy.
2. Make it pass.
3. Run `python scripts/render_catalog.py` to regenerate the README table.
4. If the fuzzer found it, also add the input under `fuzz/seeds/` as
   `regression_<name>`.

## Changing the default policy

The default `blocked_networks` follows the IANA special-purpose address
registries. A change needs a source (RFC or registry entry) in the reason
string, a catalog case, and a CHANGELOG entry under "Security" if it blocks
or allows something new. Loosening a default is a breaking change.

## Commits and pull requests

- [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`,
  `fix(policy):`, `test:`, `docs:` ...), one logical change per commit.
- New behavior comes with tests; security fixes come with a catalog case.
- Keep the core free of runtime dependencies. Integration code may depend on
  its own extra only.
- Code is typed (`mypy --strict`) and formatted with `ruff format`.

By contributing you agree that your contributions are licensed under the
Apache License 2.0.
