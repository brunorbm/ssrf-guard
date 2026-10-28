"""Optional integrations with HTTP client libraries.

Each submodule imports its client library lazily and is only usable when the
matching extra is installed (``pip install ssrf-guard[httpx]`` or
``ssrf-guard[requests]``).
"""
