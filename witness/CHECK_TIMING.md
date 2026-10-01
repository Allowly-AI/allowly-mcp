# Local /v1/check timing — 2026-09-26

The actual route is `POST /v1/check?wait=false`. This measures the runtime API
directly, with no MCP or TLSNotary. **Median 26.2 ms; observed
p95 46.6 ms.** It does not establish a sub-30 ms bound.

| Metric | Measured latency |
|---|---:|
| First request after readiness, before warm-up | 74.3 ms |
| Warm minimum | 10.2 ms |
| Warm median | 26.2 ms |
| Warm p95 (nearest rank) | 46.6 ms |
| Warm maximum | 182.2 ms |

62/100 measured requests were below 30 ms. All 110 requests
(ten warm-up, 100 measured) returned HTTP 200, `allow`, and a `pending` receipt.
The database held exactly 110 receipt rows. PostgreSQL `fsync` and
`synchronous_commit` were both `on`.

## Building blocks of one representative call

This is the upper middle whole call from the measured set, 26.263 ms.
Its stage durations add up to that call; they are not independently calculated
stage medians. Built-in `CheckTimingProfile` logs were matched to client timings
by request ID.

| Block | Time |
|---|---:|
| HTTP, middleware, authentication and other work outside the route profiler | 15.681 ms |
| Cache, budget, quota and policy checks | 0.443 ms |
| Authorization database lock | 1.933 ms |
| Prepare receipt | 0.295 ms |
| Record decision usage | 3.277 ms |
| Database commit | 4.207 ms |
| Remaining route work | 0.427 ms |
| **Total** | **26.263 ms** |

The 15.681 ms outer block is a measured residual,
not an isolated authentication timer. The HTTP middleware reports
20.986 ms; the check handler profiler reports
10.582 ms. Their difference includes authentication/dependencies,
validation, response work, logging and middleware. The remaining client interval
includes loopback transport and response consumption. No runtime source was
changed to add timers.

## Conditions and limits

- Current local runtime commit `f85539c3f6ed03a23410cb92be1959dd17ff6e99`; its pre-existing
  unrelated working-tree changes were left untouched.
- Python 3.12.13, Uvicorn with one worker on this Mac. Fresh isolated Docker
  Postgres 18.4 and Redis 8.8.1, reached over loopback port mappings. Existing
  local services remained running; this is not a dedicated benchmark host.
- 100 sequential requests paced at 5 RPS after ten warm-up calls, a reused HTTP
  connection, one real runtime API key, one authorization and one unrestricted
  action. Normal API-key authentication, origin rate limiting, policy checks,
  authorization locking, receipt creation, usage accounting and DB commit ran.
- Synthetic Enterprise workspace. No budget or external identity token was
  configured; no idempotency header or replay shortcut was used. Cache TTLs and
  database pool settings remained at their normal defaults.
- Service startup, public networking/TLS, edge proxy, MCP and TLSNotary excluded.
  Cloud receipt registration (`ENABLE_RECEIPT_EVIDENCE_WRITE=false`) and final
  KMS signing were excluded. No cloud credentials or production configuration
  were loaded. Pending receipts are not cryptographically signed receipts.
- Built-in stage profiling and HTTP success observations were enabled for every
  request; their small logging cost is included. This 100-request sample at
  5 RPS is not a production latency or capacity guarantee.

The largest outlier was 182.2 ms. Its check handler profiler was
22.748 ms and its HTTP middleware interval was 159.564 ms; the available timers
cannot attribute that outer delay to a single component.

## Reproduce

Run with the sibling API's existing Python environment and Docker Desktop:

```bash
cd /Users/yoda/Documents/AllowlyLLC/allowly/projects/allowly_mcp/witness
../../allowly-api/.venv/bin/python scripts/benchmark_check.py
```

The script uses cached images, fresh loopback-only ports and disposable data.
It applies real migrations and reuses the repository's stress-material helper.
After measurement it stops the API, removes its two containers and their volumes,
and deletes the temporary API-key seed. No existing stack or product source is
modified. The report is saved under `/tmp/allowly-check-bench-*`.

- [Raw report](artifacts/allowly-check-bench-5dgepmyr/report.json)
- [Per-request stage observations](artifacts/allowly-check-bench-5dgepmyr/api.log)
- [Database receipt/durability check](artifacts/allowly-check-bench-5dgepmyr/database-check.json)
- Runtime sweep copy: `/tmp/allowly-check-bench-5dgepmyr/report.json`
