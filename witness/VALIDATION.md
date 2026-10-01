# Validation record — mcp-allowly_tlsnotary

This folder packages the implementation from the sibling `allowly-witness-poc`
with the standalone MCP identity `mcp-allowly_tlsnotary`. The native Rust binary
keeps the name `allowly-witness-poc`. The existing `allowly_mcp` repository and
Allowly receipt contracts are unchanged. Packaging creates no cloud resources
and does not change IAM or deploy a service.

## Initial packaging checks in this folder — 2026-09-26

| Check | Result | Evidence |
|---|---|---|
| MCP adapter tests | 10 passed | `npm run test:mcp`; fake native executable for adapter tests |
| Python KMS adapter/authentication tests | 20 passed | `.venv/bin/python -m unittest discover -s kms -p 'test_*.py' -v`; local fake KMS, no cloud calls |
| Actual MCP initialize/list/call and real local TLSNotary MPC | Passed | `python3 scripts/demo.py`; [run report](artifacts/local-viwdsav9/report.json) |
| Independent verifier and required fixture opt-in | Passed | Same report; [presentation](artifacts/local-viwdsav9/evidence/mcp-3ba1c8e1-c032-4e4d-a268-ad57d3552412/presentation.json) |
| Wrong key and altered response/signature | Rejected | Same report |
| Unavailable destination or witness | MCP tool error | Same report |
| Credential-free request transcript | Passed | Same report |
| Cloud KMS signing | Not rerun here | See original implementation validation below |

At initial packaging, the three native Rust source files were byte-identical
to the original PoC. The initially copied executable matched it, with SHA-256:

```text
ed4ef0787005412eccbe670c50af231ffca70e2bb893bcf57bad92aa2ed844bd
```

TLSNotary remains at the pinned alpha.15 commit; its vendor checkout is clean.
The native code was reused from the verified build during that packaging step.
Later timing instrumentation and rebuilding are recorded below. Node dependencies and this folder's own Python environment were
used for the fresh checks above.

The local demo uses an ephemeral test signing key and the upstream HTTPS
fixture. Its report records all eight checks as passing. It does not use KMS.

## Original implementation validation

The [original run record](../allowly-witness-poc/VALIDATION.md) documents the
2026-09-26 tests performed in **the sibling PoC folder**, including real MCP,
TLSNotary against a local fixture and `example.com`, real Cloud KMS signing,
independent offline verification, rejection of altered evidence and wrong keys,
and 40 passing unit tests. Those historical results are not fresh runs of this
standalone package. Original evidence remains in the sibling folder:

- [Cloud run report](../allowly-witness-poc/artifacts/cloud-vrxr3l3_/report.json)
- [Cloud-signed presentation](../allowly-witness-poc/artifacts/cloud-vrxr3l3_/evidence/mcp-ad37ae16-4518-4e7b-ae30-0e1ca37562e9/presentation.json)
- [Independently retrieved public trust key](../allowly-witness-poc/artifacts/kms-independent-trusted-key.json)

From this folder, verify that original cloud artifact using:

```bash
target/release/allowly-witness-poc verify \
  --presentation ../allowly-witness-poc/artifacts/cloud-vrxr3l3_/evidence/mcp-ad37ae16-4518-4e7b-ae30-0e1ca37562e9/presentation.json \
  --trusted-key ../allowly-witness-poc/artifacts/kms-independent-trusted-key.json
```

The existing dedicated signing key is:

```text
projects/allowly/locations/global/keyRings/allowly-dev/cryptoKeys/allowly-witness-poc-p256/cryptoKeyVersions/1
```

Its public-key fingerprint from the original test is:

```text
8f4e4d01c2b5aae6e6eca0f7bcd28e4298d2337806d44fdabf86fb46ff5fc056
```

No new Cloud KMS signing run is claimed for this packaging step. With witness
credentials and Python dependencies configured, rerun the full cloud flow from
`/Users/yoda/Documents/AllowlyLLC/allowly/projects/mcp-allowly_tlsnotary`:

```bash
ALLOWLY_KMS_AUTH=gcloud python3 scripts/demo.py --public \
  --kms-key-version projects/allowly/locations/global/keyRings/allowly-dev/cryptoKeys/allowly-witness-poc-p256/cryptoKeyVersions/1
```

The original laptop run used an explicitly authorized `gcloud` account because
its default ADC identity lacked Allowly quota access. Service deployments should
use their own appropriately configured witness identity. The customer MCP needs
no KMS credentials.

## Scope

The only tool is a fixed harmless GET. Greenhouse integration, recruiting
writes, policy gating, remote deployment, and production readiness are outside
this implementation. TLSNotary remains experimental alpha software. A local
fixture run proves a controlled TLS exchange, not a public service's response.

The offline verifier was also run from this new folder against the original Cloud KMS presentation and independently retrieved trust key. It returned `verified: true` for `example.com`; the fresh verification output is [artifacts/original-cloud-verified.json](artifacts/original-cloud-verified.json). This checks existing cloud evidence and does not claim a new cloud signing request.

A later latency measurement ran three fresh real TLSNotary/MCP calls against
the local fixture and three fresh public calls signed by the existing Cloud
KMS key. All returned verified evidence. Results and measurement limits are
in [TIMING.md](TIMING.md); this adds new cloud runs beyond the earlier packaging
step, without changing any cloud resource or IAM.

## Timing instrumentation validation — 2026-09-26

The standalone package now has opt-in per-stage diagnostics and a freshly built
release binary. Evidence formats and MCP results are unchanged.

- Native Rust: 10 tests passed. Nine passed in the sandbox; the local socket
  cleanup test was blocked by sandbox networking, then passed with loopback access.
- MCP adapter: 10 existing tests passed.
- Python KMS adapter/authentication: 20 existing tests passed; enabled-timing
  smoke checks passed for public-key and signing operations with fake clients.
- Three real instrumented local MCP/TLSNotary calls and three public
  MCP/TLSNotary/Cloud KMS calls returned verified evidence. See [TIMING.md](TIMING.md)
  for the raw reports and limits. All additive stage sums match their call totals.
- The pinned TLSNotary vendor checkout remains clean. The original PoC and
  existing Allowly MCP sources are unchanged.

Rebuilt native SHA-256:

```text
00f4d0441736d8f9c3ec0b2a30234f4088515cef9ca702199d05b495ed224533
```
