# Native execution transport

This package now includes an experimental customer-side HTTP execution helper
alongside its existing fixed-read MCP demonstration. The MCP tool itself is
unchanged. The helper uses real TLSNotary MPC, an online independent notary,
and customer-held full evidence. It is not a production deployment or a claim
that the catalog providers have passed live compatibility tests.

## Evidence boundary

The remote Allowly API evaluates identity and policy and returns an approval
descriptor and its RFC 8785 canonical JSON SHA-256 fingerprint. The SDK keeps
provider credentials and exact request bytes locally. It uses the admitted
witness session before requesting the API's one-use dispatch claim. Only an
allowed, current claim releases the native transport to contact the provider.

The online notary checks the TLS server identity and signs a native TLSNotary
attestation with a notary-owned approval-reference extension. It does not see
HTTP request or response plaintext. The extension explicitly says
`request_binding_verification: customer_held_bundle`; it does not claim that
Allowly compared hidden request parameters or credentials during the session.

The customer's full presentation proves the HTTP bytes. Independent verification
combines that presentation, the exact approval descriptor, the signed Allowly
decision receipt binding that descriptor, and an independently trusted notary
key. `verify-execute` checks the native proof and compares its authenticated HTTP
request with the descriptor. The caller must separately verify the Allowly
receipt signature, allowed decision, workspace, and descriptor-hash linkage;
an arbitrary caller-supplied approval file is not an Allowly signature.

`verify-execute-attestation` checks the compact notary signature and approval
reference only. Allowly can retain this compact record and fingerprints while
the customer keeps the full evidence. A reported successful business outcome is
not independently proved merely by an HTTP status or a customer's summary.
TLS session time also does not establish the exact time of every request byte.

## Native commands

`prove-execute --output NEW_PRIVATE_DIRECTORY --trusted-key PUBLIC_KEY_FILE`
reads this structure on stdin. Private header values never appear in command
arguments:

```json
{
  "approval_sha256": "sha256:<canonical approval hash>",
  "approval": {"profile": "allowly.execution.approval.v1"},
  "request": {"headers": {"authorization": "Bearer <customer token>"}, "body": ""},
  "require_dispatch_ack": true,
  "witness": {
    "url": "wss://witness.example/sessions/<session ID>",
    "session_id": "<session ID>",
    "workspace_id": "<workspace ID>",
    "admission_token": "<one-use admission token>"
  }
}
```

The abbreviated `approval` above must be replaced with the complete API
descriptor. The helper derives method, origin, path and query from it. It
recomputes the descriptor's canonical hash and checks raw UTF-8 body size/hash
and all caller header commitments before connecting. The header commitment is
SHA-256 of `allowly.execution.header.v1`, a zero byte, lowercase name, a zero
byte, and exact UTF-8 value. `Host`, `Content-Length`, `Connection`, and
`Accept-Encoding` are derived; callers cannot override them or inject framing.

After witness admission and MPC setup, the helper fsyncs `witness.ready.json`.
The SDK then obtains `/v1/executions/{operation_id}/dispatch` and atomically
writes `dispatch.approved.json` containing exactly `{"approval_sha256":"…"}`.
The helper checks the hash and expiry again before provider connection. It
records `dispatch.started.json` before sending request bytes. Production mode
requires this acknowledgement gate. This local gate coordinates the supplied
SDK; a customer who replaces the SDK controls its own runtime.

For an operator-provided authenticated private tunnel, `--witness 127.0.0.1:PORT`
can replace the stdin `witness` field. Plain public WebSockets are rejected.

Successful execution saves `presentation.json`, `attestation.json`,
`response.json`, and a derived `verified.json` in the customer directory, using
private file permissions on Unix. The full presentation includes credentials
and private response data: it stays in customer custody. stdout contains the
verified response and local artifact paths for the SDK, not a record intended
for upload to Allowly. Upload only the compact attestation and approved outcome
fields through the SDK's evidence path.

```text
BIN verify-execute --presentation PRESENTATION --trusted-key KEY --approval APPROVAL
BIN verify-execute-attestation --attestation ATTESTATION --trusted-key KEY --approval APPROVAL
```

Both commands exit nonzero on failure. `--approval` is a JSON file with
`approval_sha256` and `approval`. The public key is TLSNotary's JSON
`VerifyingKey` representation, P-256 (`alg: 2`), provisioned independently.
Never take the trust key from the untrusted evidence being checked.

## Recovery and tested capability

The helper never retries a provider request. Reusing its output directory is an
error. The SDK/API own the durable operation identity, one-use dispatch claim,
and outcome reconciliation. After any ambiguous send, keep the same operation
ID and reconcile; do not generate a replacement ID automatically. A complete
HTTP response is saved before proof/signing so a later witness failure leaves
an observable response plus an evidence gap. Retrying proof upload must not
invoke the provider again.

The currently tested native profile is deliberately bounded:

- HTTP/1.1 over TLS 1.2, HTTPS DNS origins on port 443;
- GET, POST, PUT, PATCH and DELETE; encoded ASCII target and UTF-8 body;
- at most **2 KiB request transcript** and **16 KiB response transcript**;
- one complete self-delimiting response, uncompressed UTF-8, no redirect follow;
- one validated public DNS resolution, pinned for the actual connection;
- at most 150 seconds per native session, and the API approval expiry still applies.

Larger 16/64 KiB limits failed MPC preprocessing in the local alpha.15 test, so
they are not advertised. Oversized or unsupported responses can be discovered
after the provider acted; that is an uncertain/evidence-gap outcome, not a reason
to repeat a write. Provider compatibility and provider idempotency support must
be tested separately. No exactly-once claim is made for arbitrary providers.

## Local verification

```bash
bash scripts/cargo.sh test --locked --offline --bin allowly-witness-poc
bash scripts/cargo.sh build --release --locked --offline
python3 scripts/execute_demo.py
```

The demonstration uses a local TLS fixture, public test CA, fake credential,
synthetic approval and ephemeral test notary key. It verifies real MPC exchange,
the dispatch acknowledgement gate, full request binding, compact reference-only
verification, altered-proof rejection, and private credential exclusion from the
notary record. It does not call production Allowly or execute a vendor write.
Local test signing keys are accepted only with explicit `--fixture`; a public
target run requires the dedicated KMS signing configuration.

See [EXECUTE_SERVICE.md](EXECUTE_SERVICE.md) for the separate witness service,
admission, deployment configuration and draining requirements.
