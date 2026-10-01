# Witness KMS adapter

`gcp_signer.py` is a witness-side bridge from the TLSNotary Rust `Signer`
interface to the official Google Cloud KMS Python client. It defaults to ADC
on the witness host. The customer MCP process does not need Google credentials.

TLSNotary supplies the exact BCS-serialized attestation header. The helper
hashes those bytes **once** with SHA-256 and sends KMS a `digest.sha256` request.
It checks the KMS key version, P-256 algorithm, public-key checksum, confirmation
of the digest checksum, signature checksum, and the returned signature itself.
It converts the public key from SPKI PEM to compressed SEC1, and the DER ECDSA
signature to fixed-width `r || s`. The Rust adapter verifies that result using
the normal upstream TLSNotary P-256 verifier before returning it.

This does not use Allowly's Ed25519 receipt format, canonicalization, or keys.
KMS stores the long-lived signing key; the witness process still performs the
TLSNotary MPC protocol. The helper has no local-signing fallback.

Install in this PoC's own virtual environment:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r kms/requirements.lock
.venv/bin/python -m unittest discover -s kms -p 'test_*.py' -v
bash scripts/cargo.sh test --release kms::tests
```

Configure only a dedicated PoC key version. A read-only inventory on
2026-09-26 initially found no P-256 or `witness`/`tlsn`/`poc`-named key in the Allowly
project's three global key rings (`allowly`, `allowly-dev`, `allowly-s003-test`).
Other locations were not inventoried. The dedicated `allowly-witness-poc-p256`
key was then created for this PoC in `allowly-dev`; IAM was not changed.

The exact command to create a separate software-backed test signing key in
the existing development ring is:

```bash
gcloud kms keys create allowly-witness-poc-p256 \
  --project=allowly --location=global --keyring=allowly-dev \
  --purpose=asymmetric-signing --default-algorithm=ec-sign-p256-sha256 \
  --protection-level=software --labels=purpose=tlsnotary-poc
```

This creates a lasting, billable key resource. Run it only as an intended PoC
provisioning action; it is not part of setup or tests. KMS key rings and key
containers cannot be deleted. Dedicated key versions can later be disabled;
destruction is a separate, scheduled, irreversible cleanup decision.

Use the resulting **numeric version**, for example:

```bash
export WITNESS_KMS_KEY_VERSION=projects/allowly/locations/global/keyRings/allowly-dev/cryptoKeys/allowly-witness-poc-p256/cryptoKeyVersions/1
.venv/bin/python kms/gcp_signer.py public --key-version "$WITNESS_KMS_KEY_VERSION"
```

For a local operator demo, the helper also accepts **explicit**
`ALLOWLY_KMS_AUTH=gcloud`. This uses the account already authenticated in the
Google Cloud CLI on the witness host. It runs `gcloud auth print-access-token`
as a captured subprocess and passes the token in memory to the Google client.
The token is never printed or written to a file by this helper. Each helper
invocation gets a fresh token. The gcloud call has a ten-second timeout.

```bash
ALLOWLY_KMS_AUTH=gcloud .venv/bin/python kms/gcp_signer.py public \
  --key-version "$WITNESS_KMS_KEY_VERSION"
```

Use this mode only on the witness for the local demo. Keep the default
`ALLOWLY_KMS_AUTH=adc` for an appropriately configured service identity. There
is no automatic fallback between identities; invalid mode values fail before
authentication. The gcloud mode uses explicit credentials with no quota
project and changes no ADC configuration, gcloud configuration, or IAM.
The local ADC account's quota access failed during this run; this is why the
separately authorized gcloud account is selected explicitly for the demo.

The witness identity needs `cloudkms.cryptoKeyVersions.useToSign` and
`cloudkms.cryptoKeyVersions.viewPublicKey` on this dedicated key. If the
existing identity lacks them, an operator must approve any IAM change first,
as required by `../../Human-Workbook.md` in the workspace. Do not widen project
IAM or grant access to production receipt keys. The verifier only needs the
public key delivered through a trusted channel; it needs no cloud access.

The helper prints only public-key or signature JSON. On failure it prints a
fixed error category to stderr, with no partial success on stdout. The Rust
caller suppresses helper stderr and applies a 35-second deadline. Its
synchronous interface means the witness must run this work outside latency-
sensitive shared async executor threads.

`test_gcp_signer.py` runs **local fake-KMS adapter tests**, using Python
`cryptography` and real Google response types. These are not Cloud KMS tests.
`adapter_test_vector.json` is also explicitly a local adapter test vector;
the Rust unit test verifies it with TLSNotary's built-in verifier and rejects
changed messages, changed signatures, and a wrong public key. The local fake
signer is never imported by the production helper.

The Rust subprocess tests additionally invoke the actual adapter with
`fake_helper_for_rust_tests.py`, a clearly labelled fixture using a publicly
known test scalar. They reject helper process failures, missing or mismatched
public keys, wrong algorithm/version metadata, wrong signing keys, and invalid
signatures. This validates the bridge between languages without claiming
that Google signed the test artifacts.

References: [Google signing API examples](https://docs.cloud.google.com/kms/docs/create-validate-signatures),
[Google public-key API examples](https://docs.cloud.google.com/kms/docs/retrieve-public-key),
and the pinned upstream `vendor/tlsn/crates/attestation/src/signing.rs` and
`builder.rs` source.

## Tested cloud resource and independent trust

A real TLSNotary attestation was signed by this key on 2026-09-26 and verified
offline against a public key separately retrieved with the Google Cloud CLI:

- Project/ring/key/version: `allowly` / `global/allowly-dev` /
  `allowly-witness-poc-p256` / `1`.
- Algorithm: `EC_SIGN_P256_SHA256`; protection: `SOFTWARE`; state at test: `ENABLED`.
- SHA-256 of compressed SEC1 key:
  `8f4e4d01c2b5aae6e6eca0f7bcd28e4298d2337806d44fdabf86fb46ff5fc056`.
- Authentication tested: explicit `ALLOWLY_KMS_AUTH=gcloud`.
- No production key or IAM was changed. This dedicated key remains enabled for
  rerunning the PoC; no background service remains running.

For an independent trust file, from a trusted operator terminal:

```bash
gcloud kms keys versions get-public-key 1 --project=allowly --location=global \
  --keyring=allowly-dev --key=allowly-witness-poc-p256 \
  --output-file=artifacts/kms-public.pem
.venv/bin/python kms/trust_from_pem.py artifacts/kms-public.pem \
  artifacts/kms-independent-trusted-key.json
```

The converter refuses to overwrite an existing trust file. Securely deliver
that public file, or check the fingerprint through a trusted separate channel.

## Optional cloud cleanup (not performed)

After retaining the public key and any evidence you want to keep, an operator
can stop future signing with this **dedicated PoC version only**:

```bash
gcloud kms keys versions disable 1 --project=allowly --location=global \
  --keyring=allowly-dev --key=allowly-witness-poc-p256
```

This is an optional state change, not part of the test scripts. Do not destroy
key versions automatically. The empty key container remains in Cloud KMS.
