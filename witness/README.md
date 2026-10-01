# Native witness implementation

This directory belongs to the single `@allowly/mcp` package. Its TypeScript
middleware supports two execution modes: `receipt` (before and after) and
`witnessed` (before, during, and after). There is no second MCP server to install.

The witnessed path uses unchanged, pinned TLSNotary Rust libraries plus Allowly's
native adapter. The customer helper connects directly to the HTTPS provider and
to Allowly's secure WebSocket witness. The witness never proxies the provider
request. The customer's full request, response, and proof stay on that host;
Allowly receives the compact attestation and outcome.

TLSNotary alpha software remains experimental. A signature proves the recorded
exchange under the configured trust assumptions, not human approval, a complete
action history, or legal/court readiness. There is no silent unwitnessed fallback.

## Customer installation

Run the CLI after normal workspace setup:

```bash
allowly setup witness
allowly setup witness --build-from-source
```

The default installs a checked native release archive. The source option installs
the same executable after a local build; it requires Git, Rust 1.95.0, and a C
build toolchain. Both use independently pinned release checksums and the same
workspace witness trust settings. Offline `--archive` and an existing `--helper`
remain available. No Rust build runs during `npm install @allowly/mcp`.

These commands require published release assets. Local packaging does not
publish them. See [DISTRIBUTION.md](DISTRIBUTION.md) for the asset format,
release checks, and offline testing before publication.

## Source and service ownership

- `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `src/`: native helper and
  verifier, still named `allowly-witness-poc` version `0.1.1`.
- `scripts/prepare_tlsn.sh`: fetches official TLSNotary alpha.15 and rejects
  any commit except `47aee45b53e06648c1b2ad3689b367b8c923fdec` or local changes.
- [EXECUTE.md](EXECUTE.md): approved execution, dispatch gate, local proof,
  and offline verification.
- `execute_service.py`, `Dockerfile.bridge`, `kms/`: Allowly-operated Witness
  Bridge and P-256 KMS signer. This source ships here, but customers must not
  run the privileged service or receive its internal credentials.
- [EXECUTE_SERVICE.md](EXECUTE_SERVICE.md): bridge protocol, deployment, and
  drain requirements.
- `demo/`, `scripts/execute_demo.py`, `tests/signing_failure.py`: native and
  Execute tests. No legacy MCP stdio server or its Node dependencies remain.
- `VALIDATION.md`, `TIMING.md`: dated historical evidence retained unchanged;
  old names and old MCP commands in those records are not current instructions.

## Build and test from this directory

```bash
bash scripts/bootstrap.sh
bash scripts/cargo.sh test --release --locked --bin allowly-witness-poc
python3 -m unittest scripts/test_package_helper.py
python3 scripts/execute_demo.py
python3 tests/signing_failure.py
python3 scripts/test_execute_service.py
```

The last three commands use local loopback fixtures. Install the pinned Python
dependencies in a private `.venv` before bridge/KMS checks:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r execute_service_requirements.txt -r kms/requirements.lock
.venv/bin/python -m unittest discover -s kms -p 'test_*.py' -v
```

`vendor/`, `.toolchain/`, `.venv/`, `target/`, `dist/`, and `artifacts/` are local
generated data, excluded from Git and the npm package. Evidence can contain
private request and response data; never publish these directories.
