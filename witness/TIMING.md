# Measured latency — 2026-09-26

The current implementation does **not** meet a sub-30 ms witnessed-call or added-latency target.

Three sequential samples per mode, optimized native binary, witness on the same
laptop, persistent initialized MCP connection. The measured tool-call interval
starts just before `client.callTool` and ends after its verified result returns.
Witness startup, MCP startup, discovery, build and negative tests are excluded.
Each call still starts a new native process, as the implementation currently does.

| Measurement | Median | Observed range |
|---|---:|---:|
| MCP `listTools` control round trip, local run | 0.65 ms | 0.56–0.85 ms |
| Plain TLS1.2 HTTPS to local fixture | 3.26 ms | 3.03–24.25 ms |
| Full witnessed MCP call, local fixture + local test signer | 596.75 ms | 538.45–731.55 ms |
| Plain TLS1.2 HTTPS to example.com | 71.48 ms | 68.37–1,254.66 ms |
| Full witnessed MCP call, example.com + real Cloud KMS signer | 2,052.50 ms | 2,014.49–2,083.89 ms |

The control-message measurement only checks MCP transport/dispatch; it is not a
measurement of the complete tool handler's overhead. The public HTTPS baseline
had a slow first sample. Three samples do not establish p95 or a production SLO.

The cloud measurement includes the PoC's Python subprocess, explicit gcloud
authentication helper, new Google client, public-key lookup and signing RPC.
It is not a measurement of Cloud KMS RPC latency alone. That earlier run had no component timers, so differences between the two modes
must not be assigned entirely to KMS. The instrumented runs below measure the stages. Request and response sizes also differ between the two destinations.

## Building blocks — fresh instrumented runs

These are two **median-duration whole calls**, each selected from three sequential
samples. Each column uses one call's actual stages, so its rows add up to that
call's total (subject to rounding). They are not sums of separate phase medians.
The local column uses sample 3; the cloud column uses
sample 1. The destinations and signer modes differ.

| Building block | Local fixture + local signer | Public HTTPS + Cloud KMS |
|---|---:|---:|
| MCP transport and wrapper work | 1.3 ms | 6.1 ms |
| Native process startup and remaining local work | 16.3 ms | 16.1 ms |
| Connect to witness and TLSNotary setup | 347.6 ms | 362.8 ms |
| Destination DNS and TCP connection | 0.2 ms | 242.9 ms |
| HTTPS exchange with live MPC-TLS | 112.7 ms | 179.3 ms |
| Finalize proof and prepare attestation request | 114.4 ms | 123.0 ms |
| Witness attestation, including signer path | 4.0 ms | 1070.4 ms |
| Build, verify and save evidence | 1.3 ms | 2.6 ms |
| **Complete MCP call** | **597.8 ms** | **2003.3 ms** |

| Inside the public attestation step | Time |
|---|---:|
| Authentication and KMS client setup | 367.3 ms |
| Public-key request and validation | 380.9 ms |
| KMS signing request (client + network + service) | 108.8 ms |
| Local signature validation | 5.7 ms |
| Remaining Python startup/imports, process exit, polling and helper bookkeeping | 203.1 ms |
| Remaining witness attestation work and transfer | 4.7 ms |
| **Attestation subtotal, already included above** | **1070.4 ms** |

The helper subprocess took 1065.8 ms in total. Its
`helper_work_total_ms` is a nested measurement, not an additional cost.
Authentication uses this laptop's explicit gcloud helper on every signing call.
KMS signing-request time includes the SDK and network, not only the remote
cryptographic operation. Public-key lookup is also repeated for each signature.

The native setup/teardown residual includes CLI parsing, loading the trust key,
output serialization and process exit. MCP/wrapper time includes the optional
timing sidecar write. It is not pure MCP protocol overhead. TLSNotary setup
completes before the destination connection; the HTTPS stage includes the
MPC-TLS handshake, request, full response and TLS task completion. Proof
finalization includes work with the witness. Timings are local diagnostics,
not authenticated performance claims or part of the signed evidence.

Cloud complete-call range: 1991.2–2062.6 ms.
Local complete-call range: 526.2–619.6 ms.
Three samples with a loopback witness do not establish production p95.
The fresh public plain-HTTPS median was 66.7 ms;
the public-run MCP control median was 0.67 ms.
Those baselines are separate requests, not additive stages of the witnessed call.

- [Instrumented cloud report](artifacts/timing-cloud-IL8SaZ/timing.json)
- [Instrumented local report](artifacts/timing-local-unl4PJ/timing.json)

The harness enables `ALLOWLY_TIMINGS=1`. Native phase durations are written to
an unsigned `timings.json` next to each presentation. The witness emits numeric
KMS durations into its local log. Sequential calls let the harness match each
signing log to its call. No credentials or signing messages enter timing logs.
MCP result shapes and signed evidence are unchanged. The standalone native
binary was rebuilt; upstream TLSNotary source remains unmodified.

## Timing boundaries

The current MCP handler awaits the native prover. The native prover connects to
the witness and completes MPC setup before connecting to the destination. After
the full HTTPS response arrives, it still completes the TLSNotary proof, waits
for the signed attestation, verifies the evidence and writes its artifacts.
Only then does the MCP tool return success.

“Pass-through” describes the client's direct connection to the destination.
The witness participates online and adds work on the critical path. See the
[official TLSNotary FAQ](https://tlsnotary.org/docs/faq/#does-tlsnotary-use-a-proxy).

Time to first destination dispatch and time to first HTTP response byte were
not measured separately. KMS signing is after the HTTPS exchange, so its cost
is part of the final verified tool return. Returning before evidence is complete
would require a distinct pending-evidence contract; that is not implemented.

Persistent native/helper processes, a reused KMS client and cached public key
could remove avoidable setup. These have not been implemented or benchmarked
and do not support a sub-30 ms promise for the TLSNotary workflow.

## Reproduce and inspect

```bash
cd /Users/yoda/Documents/AllowlyLLC/allowly/projects/mcp-allowly_tlsnotary
node scripts/benchmark.mjs
node scripts/benchmark.mjs --cloud
```

The cloud command explicitly uses the existing authorized gcloud identity and
the dedicated PoC P256 KMS version. It performs three plain HTTPS reads plus three witnessed public reads and
three KMS signatures. It creates no resources and changes no IAM. Each harness
stops its owned processes when it finishes.

- [Local raw measurements](artifacts/timing-local-inDAzY/timing.json)
- [Cloud raw measurements](artifacts/timing-cloud-6IIm1q/timing.json)

Each raw report points to the actual verified evidence for all three calls.
Both measurements passed. This is a later timing run, separate from the earlier
packaging validation and the original PoC cloud run.

## Direct Allowly decision API comparison

A separate real local `/v1/check` benchmark measured 26.2 ms median and 46.6 ms
p95 over 100 requests after warm-up. It includes Postgres/Redis and pending
receipt writes, but no TLSNotary, MCP, cloud registration or final KMS signature.
See [CHECK_TIMING.md](CHECK_TIMING.md) for the building blocks and scope.
