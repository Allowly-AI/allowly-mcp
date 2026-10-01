# Local GitHub execution demo

This page makes a real, read-only GitHub request, checks permission with a local
Allowly API, verifies a real TLSNotary proof, and reports the outcome to that
same local API. No GitHub token is needed.

From `allowly_mcp/witness`, run a credential-free local test with the
repository's publicly known P-256 test key:

```bash
.venv/bin/python demo/server.py --local-test-signer
```

This still runs the real Allowly API, TLSNotary prover and witness, and a public
GitHub HTTPS read. It does **not** test Cloud KMS custody: the test signer is
deliberately public and must never be used for real evidence. To use a dedicated
Cloud KMS key instead, supply the enabled version and an independently obtained
TLSNotary JSON public key (`{"alg":2,"data":[...33 compressed SEC1 bytes...]}`):

```bash
.venv/bin/python demo/server.py \
  --kms-key-version projects/PROJECT/locations/LOCATION/keyRings/WITNESS_RING/cryptoKeys/ws_local_witness_demo-tlsnotary/cryptoKeyVersions/1 \
  --trusted-key /private/path/to/trusted-notary-key.json
```

The CryptoKey must be named `ws_local_witness_demo-tlsnotary`, use
`EC_SIGN_P256_SHA256`, and have exactly one enabled version. The witness ring
must differ from the receipt-signing ring. The API resolves that workspace key
through KMS and pins the selected version and public key in each session; the
native witness uses the version in the authenticated claim. If a key rotates,
update the independent trust file before the next run. The demo creates no cloud
resources or IAM grants. For an already configured service identity, use
`--kms-auth adc`; the default uses the current gcloud login.

Open <http://127.0.0.1:8810> and click **Run witnessed request**. Keep the command
running; Ctrl-C stops the page server, waits for any in-flight request to finish,
then stops its local API. Use the printed
`127.0.0.1` address, because the demo rejects other Host headers.

Prerequisites are the existing sibling `allowly-api/.venv`, the built
`target/release/allowly-witness-poc`, and this directory's `.venv` with its existing
KMS dependencies. The test signer is opt-in; real KMS mode never falls back to
it.

The demo creates an **isolated** local Allowly installation on port 8811. It
does not use or modify your existing dashboard database or the hosted API.
The generated runtime API key and internal authentication secret stay in a
private local directory; neither is sent to the browser or GitHub.

## Use an existing local workspace

The adapter can also use a workspace already configured in the local Allowly
app and runtime. This mode does not create a second workspace. Keep the app's
`allowly-api` Docker service and the runtime API running. The app service mints
a fresh Auth0 machine token through its existing connection; the token stays
in the adapter process and is never sent to the browser or saved with a run.

Create a private JSON file outside Git and set its mode to `0600`. The values
must come from that same local workspace. These field names are required:

```json
{
  "workspace_id": "ws_s001_...",
  "api_base_url": "http://127.0.0.1:8085",
  "api_key": "LOCAL_RUNTIME_KEY",
  "internal_token": "LOCAL_RUNTIME_INTERNAL_TOKEN",
  "authorization_id": "LOCAL_GITHUB_AUTHORIZATION_ID",
  "enabled_executable_id": "LOCAL_GITHUB_EXECUTABLE_ID",
  "agent_id": "YOUR_CONNECTED_AGENT_ID",
  "auth0_subject": "MACHINE_CLIENT_ID@clients",
  "auth0_issuer": "https://YOUR_TENANT.us.auth0.com/",
  "auth0_audience": "https://allowly.ai/agent-identity",
  "witness_kms_key_version": "projects/PROJECT/locations/global/keyRings/RING/cryptoKeys/WORKSPACE_ID-tlsnotary/cryptoKeyVersions/1",
  "trusted_key_file": "/absolute/private/path/to/trusted-notary-key.json",
  "notary_fingerprint_sha256": "64_lowercase_hex_characters",
  "local_test_signer": false
}
```

Keep the file owner-only, for example `chmod 600 /private/path/demo-config.json`.
Check the live setup without contacting GitHub:

```bash
.venv/bin/python demo/server.py --existing-config /private/path/demo-config.json --preflight
```

The authorization must grant only `github.issues.list` on
`github:octocat/Hello-World`, bind the selected enabled executable, and require
`witnessed` evidence. The adapter checks the live authorization, current Auth0
binding, and workspace witness public key before requesting approval. A changed
binding or key stops the run before GitHub is called. The local runtime must
also have its native attestation verifier configured.

For a dedicated Cloud KMS witness key, run:

```bash
.venv/bin/python demo/server.py --existing-config /private/path/demo-config.json
```

A local-only test signer is allowed only when both the private config explicitly
sets `"local_test_signer": true` and the command includes
`--local-test-signer`. Its key version must use the `test-only` project and its
public key must match the repository's public test key. The existing runtime
must explicitly support that same test key; the adapter never silently changes
the runtime or falls back from Cloud KMS. In this mode the TLS protocol is real,
but the signing key is public test material and provides no Cloud KMS custody.
To preflight and then open the page with that explicit local-only test signer:

```bash
.venv/bin/python demo/server.py --existing-config /private/path/demo-config.json --local-test-signer --preflight
.venv/bin/python demo/server.py --existing-config /private/path/demo-config.json --local-test-signer
```

The page reports Auth0 as **configured** until the runtime accepts a request
using the fresh machine token. It reports the TLS proof and Allowly outcome
separately. The WSS SDK mode also waits for both Allowly receipts, checks their
signatures against the local workspace's published keys, and checks that the
signed after record links to this action and its decision. It saves both
receipts in the private run directory. If signing or verification does not
finish, the page says **unverified** even though the GitHub read may have run.
The isolated demo mode below still has no receipt signer.

### Test the local WSS bridge through the Python SDK

After starting the optional local witness Compose overlay, run `allowly setup
witness` for this workspace with the local helper and
`--witness-ca-cert` pointing to the generated local CA. The CLI saves the
workspace's public witness key and the local bridge CA in its owner-only
configuration. The SDK checks both pins before any provider request.

With the same private existing-workspace config described above, run:

```bash
../../allowly-api/.venv/bin/python demo/server.py \
  --existing-config /private/path/demo-config.json --sdk-wss --preflight
../../allowly-api/.venv/bin/python demo/server.py \
  --existing-config /private/path/demo-config.json --sdk-wss
```

The HTML page remains a fixed, read-only GitHub test. In this mode its backend
uses the Python SDK, which opens the real local WSS bridge, sends the provider
request from this host, keeps the full proof local, and reports the compact
attestation to the existing Allowly runtime. A missing or changed CA, witness
key, identity, or bridge stops the run; it does not fall back to the older
private TCP demo. Each click gets a fresh operation ID and is never retried
automatically.

## What runs

1. The browser asks the local demo adapter to run one fixed request.
2. The adapter sends header/body fingerprints, the action, authorization, and
   catalog operation to the real local `/v1/execute` route. Actual runtime
   authentication, identity handling, executable matching, and policy evaluation
   run. The permission is limited to `github:octocat/Hello-World` and requires
   witnessed evidence.
3. The adapter obtains a one-use witness token and authenticates the internal
   witness claim. The native witness starts using the exact workspace key
   version pinned in that claim.
4. Once the native prover signals readiness, the adapter requests the real
   one-use dispatch permission. Only then can the prover send the GitHub request.
5. The prover saves the observed response and proof. Separate native commands
   verify both the full presentation and the compact attestation.
6. The adapter reports response and evidence fingerprints plus the compact
   attestation to `/v1/executions/{operation_id}/outcome`. The local API verifies
   that attestation and records the result. The full proof remains local.

Each click creates a new operation. The adapter never automatically retries a
GitHub request. If reporting fails after dispatch, the page shows the remaining
uncertainty and retains the operation and report files for reconciliation.

## What the result means

- **TLS proof verified** means the native verifier accepted the real HTTPS
  exchange, approved request binding, public certificate chain, and pinned
  notary signature.
- **Report accepted** means the local Allowly API accepted the outcome and
  compact evidence. The API does not receive or independently check the full
  response plaintext.
- **Receipt pending** is expected: this isolated API has no Ed25519 receipt
  signing worker. A TLSNotary attestation is not an Allowly signed receipt.
- Identity is explicitly **unverified runtime-key identity**. No OIDC login or
  verified person/agent identity is invented for the demo.

The witness runs as a separate process on this computer. Real KMS mode tests
the protocol and key custody; local test signer mode tests the protocol only.
Neither mode shows independent organizational operation of the witness.

The original demo mode uses existing HTTP APIs plus native private-loopback TCP
transport. Its `wss://127.0.0.1:8810` value is metadata only; no WSS service
listens there. The `--sdk-wss` mode above instead uses the local bridge and
tests the normal SDK witness transport.

The target remains public HTTPS on port 443. The current witness profile does
not execute a plain HTTP localhost target. It supports up to 2 KiB of request
and 16 KiB of response transcript. The selected GitHub response fit at test
time; a larger future response must fail rather than claim a partial proof.

## Files and state

- `index.html`: page and browser JavaScript, with no external dependencies.
- `server.py`: fixed-request adapter and page server, bound to loopback only.
- `local_api.py`: real local API bootstrap with an isolated SQLite database.
- `native_runner.py`: supervised native witness, dispatch gate and verification.
- `witness_config.py`: fixed local workspace name and test-only key version.
- `test_demo.py`: credential-free API/claim and key-selection smoke tests.

Default private state is in the ignored `artifacts/github-html-demo-test/`
directory for the local test signer, or `artifacts/github-html-demo/` for real
KMS mode. Changing the signer or trust key requires a new state directory.
Its `api/` directory contains the local database and credentials. Each
`runs/<operation-id>/` directory contains the approval, dispatch/report state,
and `native/evidence/` proof files. Do not publish that directory; evidence can
contain complete request and response data. The page's evidence link returns
an index only, not private credentials or the complete proof.

The seeded permission expires after one day. To start a fresh isolated demo:

```bash
.venv/bin/python demo/server.py --local-test-signer --state-dir artifacts/github-html-demo-next
```

Optional `--port` and `--api-port` select other local ports. SQLite is used for
this one-process demo, not as a test of production database concurrency.

## Credential-free smoke test

```bash
../../allowly-api/.venv/bin/python -m unittest discover -s demo -p 'test_*.py' -v
```

This runs the real local API and tests preparation, witness admission, and the
authenticated claim in process. It confirms that the seeded workspace key is
used and that the claim pins the test key version and fingerprint. It makes no
GitHub request and opens no listening socket. The browser demo command above
performs the full native exchange when loopback networking is available.

On September 28, 2026, one full local test-signer run returned HTTP 200 from the
fixed GitHub read. The native full proof verified and the local API accepted the
compact attestation and outcome. That run did not use Cloud KMS.
