# BashSim

Docker Hub: [kylemc54321/assemblyline-service-bashsim](https://hub.docker.com/r/kylemc54321/assemblyline-service-bashsim)

An AssemblyLine v4 service that symbolically emulates a bash script's grammar
(variable substitution, loops over literal lists, safe base64/text-transform decoding)
**without ever executing it**, to reveal dynamically-built commands/URLs that a flat
text regex (as used by the sibling `PayloadFetcher` service) would miss. Any
resolved network-fetch command is optionally given a real, SSRF-guarded fetch
(reusing `PayloadFetcher`'s fetch logic verbatim). Everything else recognized
(persistence/system-mutation commands, direct execution of fetched/decoded content,
data exfiltration) is only ever logged, never performed.

## Safety

**This service has no code-execution surface at all.** It parses scripts with
[`bashlex`](https://github.com/idank/bashlex), a pure-Python grammar parser with no
subprocess, `eval`/`exec`, or networking code anywhere in it — it can only build a
syntax tree from text, never run anything. There is no `bash`/`sh` invocation, no
`eval`/`exec` of script text, anywhere in this service, in development or production.
This is a deliberate departure from services like `Overpower` (which shells out to a
real `pwsh` binary with overridden cmdlets) — a design that was in fact attempted for
bash and rejected, since bash's attack surface (arbitrary external binaries, `eval`,
`source`) is broader than PowerShell's cmdlet-name resolution and a `$PATH`-shim
around a real bash process has real, unclosed gaps. Pure emulation avoids that
category of risk entirely.

Residual risks, by design, are different in kind from execution risk:

1. **Incomplete coverage** — `bashlex`'s grammar can't parse everything (some
   advanced bash 4+ syntax, certain parameter-expansion/arithmetic forms).
   Unresolved parts are reported as opaque/unresolved, never silently guessed at. A
   sufficiently obfuscated script may yield a mostly-unresolved report — surfaced via
   heuristic 7, not hidden.
2. **Real network I/O on the fetch path** carries the same SSRF/resource-limit
   considerations already documented in `PayloadFetcher`'s README — the vendored
   `ssrf_guard.py`/`fetcher.py` here are byte-identical to the already-reviewed
   originals in that service.
3. **Conditional over-reporting** — actions found inside `if`/`while`/`until`
   bodies are walked unconditionally and flagged `conditional=True` rather than
   evaluated, since their real runtime truth value isn't available or safe to
   determine statically. This may report an action that wouldn't actually trigger
   at runtime — intentionally, never the reverse.

## Deployment note

Like `PayloadFetcher`, this service's real-fetch path deliberately reaches out to
live, often-malicious infrastructure and needs `docker_config.allow_internet_access:
true`. It should sit on a network-isolated, analysis-only egress path.

## Submission parameters

| Param | Default | Purpose |
|---|---|---|
| `max_loop_iterations` | 200 | Cap on how many times a resolvable `for` loop is unrolled. |
| `max_recursion_depth` | 25 | Cap on AST-walk recursion depth. |
| `max_urls` | 10 | (Reserved for future capping of resolved fetch URLs.) |
| `fetch_timeout_seconds` | 10 | Connect/read timeout per real fetch. |
| `max_download_size_mb` | 25 | Hard cap on a single fetched response, enforced while streaming. |
| `max_redirects` | 3 | Max redirect hops followed (each re-checked for SSRF). |
| `user_agent` | `Mozilla/5.0 (AssemblyLine BashSim)` | UA header sent on real fetches. |
| `simulate_downloads_only` | **true** | When true (default), resolved network commands are only reported, never actually fetched -- mirrors Overpower's own safe-by-default `fake_web_download=true` posture. |

## Development

This system's Python is externally managed (PEP 668); use an isolated virtualenv:

```bash
python3 -m venv .venv
.venv/bin/pip install bashlex requests assemblyline-v4-service assemblyline-service-utilities pytest requests-mock
.venv/bin/pytest test/
```

No test in this repo ever invokes real bash, runs against the real malware corpus, or
makes a real network/DNS call — the network layer is mocked (`requests_mock`) and DNS
resolution is mocked (`unittest.mock.patch("socket.getaddrinfo")`) throughout. Test
fixtures use RFC 5737 documentation-range IP addresses (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`), never real/live malicious infrastructure.
