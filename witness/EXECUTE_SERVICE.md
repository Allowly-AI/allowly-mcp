# Remote execution witness bridge

`execute_service.py` is a small privileged service that joins an authenticated
customer WebSocket to one native TLSNotary witness process. It does not proxy
the provider connection. The customer-side native prover still opens TLS to the
provider and keeps the HTTP request, credentials, and response plaintext.

This code ships with `@allowly/mcp`, but the service is operator infrastructure:
customers install only the native helper and never run this privileged bridge. The
existing `ALLOWLY_INTERNAL_TOKEN` has broad internal authority, so the bridge
host, process environment, and runtime network route must be protected like
other privileged Allowly services. There is no public shared notary fallback.

## Protocol

The customer connects to `wss://HOST/sessions/SESSION_ID`. Credentials are
never placed in the URL. Its first text frame must be exactly:

```json
{"session_id":"wit_...","workspace_id":"...","admission_token":"..."}
```

The admission token is an unpadded base64url encoding of 32 random bytes. The
path and JSON session IDs must match. Unknown fields, duplicate JSON fields,
binary preflights, malformed IDs, and oversized messages are rejected before a
runtime claim or child process.

The bridge signs one internal request and calls:

```text
POST /internal/execution-witness/sessions/{session_id}/claim
```

The HMAC covers the exact JSON bytes with the existing Allowly internal request
format. A claim is never retried. Runtime responses other than a valid `200`,
including `401`, `409`, and `503`, fail closed before the native witness starts.
The trusted claim includes the workspace's exact P-256 KMS key **version** and
public-key fingerprint. The customer preflight cannot select either value.
The key must be named `<workspace_id>-tlsnotary`; malformed, missing, or
cross-workspace key data fails closed before a native process starts.

After a successful atomic claim, the bridge writes the exact trusted approval
envelope to a mode `0600` file inside a mode `0700` temporary directory. It
starts this fixed command without a shell:

```text
allowly-witness-poc witness \
  --execution-approval APPROVAL \
  --listen 127.0.0.1:0 \
  --public-key NEW_PUBLIC_KEY \
  --ready-file NEW_READY_FILE \
  --kms-key-version CLAIMED_WORKSPACE_KMS_VERSION \
  --kms-python PYTHON \
  --kms-helper HELPER
```

Only after the native readiness file is private, valid, loopback-bound, and its
bare lowercase signer fingerprint matches the runtime claim does the bridge
connect to that TCP listener and return `{"ready":true}`. All later WebSocket
messages must be binary. Their bytes are relayed without parsing in both
directions. The compact TLSNotary attestation is part of that native stream;
there is no separate bridge upload or attest request.

Each claim gets one native process. The process serves one session and exits.
The bridge does not restart it or create another process after a claimed
session fails. Temporary approval, readiness, and public-key files are removed
on every exit path.

## Production configuration

Build the bridge image from `allowly_mcp/witness` (the Docker build context):

```bash
docker build -f Dockerfile.bridge --build-arg GIT_SHA="$(git rev-parse HEAD)" \
  -t allowly-witness-bridge:local .
docker run --rm --entrypoint /usr/local/bin/allowly-witness-poc \
  allowly-witness-bridge:local --help
```

The build uses Rust 1.95.0, fetches the exact TLSNotary commit checked by
`scripts/prepare_tlsn.sh`, and builds with `Cargo.lock` and `--locked`. The
final Python image contains that native binary, the bridge, and the pinned
Python dependencies. A fresh build needs access to GitHub, the Rust package
registry, and the Python package index. Runtime credentials, certificates,
workspace keys, IAM grants, and the TLS proxy are supplied separately; they
are not included in the image. Record the built image digest when promoting it
to another host so the tested image is the one that runs. Build for the target
host architecture; an x86-64 host needs `docker build --platform linux/amd64`.

For production promotion, use the dedicated VM deployment helper in
`../../allowly_app/ops/deploy/witness/README.md`. It takes an immutable registry
digest, checks the full source revision and `workspace-kms-v1` image label,
drains and retains the previous container, and verifies health through the
host TLS proxy. The API's Alpine image cannot run this Debian native binary;
the runtime production witness overlay uses a Debian API image and copies the
helper from the same promoted bridge digest.

For a direct host-process installation instead, build the same pinned native
source and install the Python dependencies:

```bash
bash scripts/prepare_tlsn.sh
bash scripts/cargo.sh build --release --locked
python3 -m pip install -r execute_service_requirements.txt
python3 -m pip install -r kms/requirements.lock
```

Required environment:

| Variable | Purpose |
|---|---|
| `ALLOWLY_API_BASE_URL` | HTTPS runtime API origin. Paths, query strings, user info, and cleartext HTTP are rejected. |
| `ALLOWLY_INTERNAL_TOKEN` | Existing internal HMAC secret. It stays in the bridge and is removed from the native child environment. |
| `ALLOWLY_WITNESS_BRIDGE_INSTANCE_ID` | Stable replica ID matching `[A-Za-z0-9._:-]{1,128}`. |
| `ALLOWLY_WITNESS_LISTEN_ADDR` | Listener, default `127.0.0.1:8765`. Cleartext listeners must use a literal loopback address. |
| `WITNESS_KMS_KEY_RING` | Name of the dedicated witness KMS ring, for example `allowly-witness`. Required in production; the claimed key version must be in this ring. |

Optional environment:

| Variable | Default / purpose |
|---|---|
| `ALLOWLY_API_CA_CERT_FILE` | Optional private CA file for the API HTTPS claim. Use only for the local Caddy route; ordinary public HTTPS keeps system trust. |
| `ALLOWLY_WITNESS_NATIVE_BIN` | `/usr/local/bin/allowly-witness-poc` in the image; direct host runs default to `target/release/allowly-witness-poc`. Must be a regular executable file. |
| `ALLOWLY_WITNESS_KMS_PYTHON` | `/usr/local/bin/python` in the image; direct host runs default to `.venv/bin/python`. Fixed executable passed to the native KMS adapter. |
| `ALLOWLY_WITNESS_KMS_HELPER` | `/app/kms/gcp_signer.py` in the image; direct host runs default to `kms/gcp_signer.py`. Fixed readable helper path. |
| `ALLOWLY_WITNESS_TLS_CERT_FILE`, `ALLOWLY_WITNESS_TLS_KEY_FILE` | Both are required for direct TLS. Without them, bind loopback behind Caddy or another TLS load balancer. |
| `ALLOWLY_KMS_AUTH=token-file`, `ALLOWLY_KMS_ACCESS_TOKEN_FILE` | Local bridge can read a short-lived impersonated token JSON from a private mounted directory for each KMS RPC. The JSON contains `access_token` and UTC `expire_time`; expired or nearly expired tokens fail closed. |
| `ALLOWLY_WITNESS_MAX_CONCURRENT_SESSIONS` | `16`, allowed range 1–128. Capacity rejection occurs before claim. |
| `ALLOWLY_WITNESS_PREFLIGHT_TIMEOUT_SECONDS` | `5`, allowed range 1–30. |
| `ALLOWLY_WITNESS_CLAIM_TIMEOUT_SECONDS` | `10`, passed to the standard-library HTTP client. |
| `ALLOWLY_WITNESS_NATIVE_READY_TIMEOUT_SECONDS` | `20`, allowed range 1–60. |
| `ALLOWLY_WITNESS_SESSION_TIMEOUT_SECONDS` | `180`, allowed range 30–600. |
| `ALLOWLY_WITNESS_DRAIN_TIMEOUT_SECONDS` | `180`, allowed range 1–600. |

The bridge has no global witness signing key. The runtime pins a dedicated
P-256 KMS version and fingerprint for each workspace witness session and returns
them only in its authenticated internal claim. The bridge passes that exact
version to the native witness only if its key name matches the workspace and
its ring matches `WITNESS_KMS_KEY_RING`. The native witness reports the
public-key fingerprint at readiness. A mismatch stops the session before the
customer can dispatch the provider request. Legacy
`ALLOWLY_WITNESS_NOTARY_SIGNING_KEY` and
`ALLOWLY_WITNESS_NOTARY_KEY_FINGERPRINT_SHA256` settings are rejected. The
bridge service identity needs KMS public-key and signing access to the workspace
witness keys in a separate witness key ring; it must not have access to receipt
signing keys. The runtime API needs read access to the witness ring to list
versions and fetch public keys, but no signing access there. A bridge identity
that can sign every workspace key in the witness ring still has access across
those workspaces; distinct key objects alone do not isolate a bridge compromise.

For the initial one-enabled-version profile, pause new witnessed admissions
before adding another enabled version. Drain existing witness sessions and
outcome uploads, distribute the new version's public key through an independent
trusted path, then resume with exactly one enabled version. Do not disable a
pinned version while its sessions may still sign after a provider request.
When moving from the former global-key protocol, turn off witnessed admissions
and drain old sessions before deploying the new runtime and bridge together.
The two claim formats are incompatible during a blue/green overlap. Rollback
needs the same drain step; do not fall back to the global key for new sessions.

Start the service behind a TLS proxy on loopback:

```bash
python3 execute_service.py
```

For direct TLS, configure both certificate paths and expose only `wss://`.
Browser origins are rejected; the native customer client does not send an
`Origin` header. `/healthz` returns `200` while accepting sessions and `503`
while draining, so a load balancer can stop new routing before shutdown.

## Shutdown and failure behavior

`SIGTERM` and `SIGINT` stop the listener. Connections that have not begun a
claim are closed so the customer can reconnect to another replica. A claim
already in flight is treated as consumed because its result may commit after a
network timeout. Claimed sessions drain until the configured deadline. At the
deadline, the bridge closes them with an explicit unknown-outcome reason and
terminates their one-shot native process. It never retries a runtime claim,
native witness, or business request.

The runtime database claim is the cross-replica lock. The in-process capacity
limit only protects this host. A single WebSocket naturally owns its native
witness TCP connection.

Logs contain event categories and HTTP status numbers only. They do not contain
the admission token, claim body, approval descriptor, operation ID, workspace
ID, session ID, provider server name, or temporary file paths.

## Explicit fixture mode

Local test-key behavior is available only with the command-line switch:

```bash
python3 execute_service.py --test-fixture
```

Fixture mode requires a loopback `http://` API stub and loopback bridge bind. It
rejects production KMS and direct-TLS settings, passes `--local-test-key
--fixture` to the native binary, and allows the random local test signer to
differ from the stub's placeholder fingerprint. This bypass cannot be enabled
in production mode and must never be used to report production notary
availability.

Run the focused tests with:

```bash
python3 scripts/test_execute_service.py
```

The default suite uses a protocol-compatible fake native process for fast
failure, relay, drain, and cleanup coverage. The real integration test is
explicit because it performs a full local TLSNotary MPC session:

```bash
ALLOWLY_RUN_NATIVE_BRIDGE_FIXTURE=1 python3 scripts/test_execute_service.py
```

That test makes one synthetic claim against a loopback HTTP stub, runs the real
compiled witness and prover through a cleartext loopback WebSocket, exercises
the `witness.ready.json` / `dispatch.approved.json` gate before provider
connection, and sends a small synthetic POST to the upstream local HTTPS
fixture. The fixture returns HTTP 405, so no business write occurs. It verifies
both the full presentation and compact attestation and saves evidence under
`artifacts/execute-service-integration-*/`. To make the verifier trust key
available before WSS admission, it uses the repository's deterministic,
publicly known fake-KMS test scalar. This is not a Cloud KMS validation and is
never selected by the service CLI.
