# Customer helper release artifacts

The Allowly CLI installs the native customer helper owned by `@allowly/mcp`
and used by the Python and TypeScript SDKs. Both SDKs run the same `allowly-witness-poc` executable for
`prove-execute`; they do not download a helper during `pip` or `npm` install.
This is an experimental binary. No helper release has been published by these
scripts.

`allowly setup witness` downloads a precompiled helper. Add
`--build-from-source` to download the pinned adapter source and build it with
Rust 1.95.0 and a C toolchain. The build fetches unchanged official TLSNotary at
its pinned commit. Both modes verify release checksums before any extraction
or build, run the installed helper's command checks, and use the same workspace
trust configuration. No Rust toolchain is needed for a precompiled archive.

## Artifact contract

For Cargo version `0.1.0`, each release asset is named
`allowly-witness-poc-0.1.0-<target>.tar.gz`. A tarball contains exactly one
root-level regular file, `allowly-witness-poc`, with executable mode `0755`.
There are no symlinks or path components to interpret. The release also has
`SHA256SUMS`, sorted by archive filename, with standard lines of the form
`<64 lowercase SHA-256 hex>  <archive filename>`.

The optional source asset is `allowly-witness-poc-0.1.0-source.tar.gz`. It uses
the same deterministic USTAR/gzip format, with regular files only and no
directory, link, PAX, or GNU metadata entries. Its root contains `Cargo.toml`,
`Cargo.lock`, `rust-toolchain.toml`, `src/*.rs`, `scripts/prepare_tlsn.sh`, and
`scripts/cargo.sh`. Build scripts have mode `0755`; other files use `0644`.
All times and owner IDs are zero. It contains no bridge, KMS service, vendored
source, caches, keys, or evidence. The source asset is included in `SHA256SUMS`
alongside the platform-specific binaries.

The native targets accepted by the packager are:

| Operating system | Rust target |
| --- | --- |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| macOS Intel | `x86_64-apple-darwin` |
| Linux ARM64 (glibc) | `aarch64-unknown-linux-gnu` |
| Linux x64 (glibc) | `x86_64-unknown-linux-gnu` |

This list defines names for native builds. A target becomes installable only
after its archive passes the native tests and is present in the published
checksum file. Windows and musl targets are not packaged here.
Build Linux assets on the oldest glibc version you intend to support, and test
the extracted binary on that baseline before adding its checksum to a release.

For a published `witness-v0.1.0` release of the consolidated MCP repository,
the base URL is
`https://github.com/Allowly-AI/allowly-mcp/releases/download/witness-v0.1.0/`.
The CLI should pin both the helper version and SHA-256 digest of the complete
`SHA256SUMS` file in its source. It must verify that digest before trusting any
archive digest from the file, then verify the selected archive before extracting
it. A checksum file fetched beside an archive without an independently pinned
digest is not a trust anchor. Installation should fail on an unknown platform,
absent asset, failed checksum, unexpected tar member, or helper process failure.

## Build and check locally

Use Python 3.9+ and Rust 1.95.0. `scripts/prepare_tlsn.sh` fetches the
TLSNotary alpha.15 source and verifies its exact commit; `Cargo.lock` pins
crates. This is a native build on each target, with no cross compilation.

```bash
cd allowly_mcp/witness
python3 scripts/package_helper.py build --local --offline
python3 scripts/package_helper.py source --local
python3 scripts/package_helper.py manifest
python3 scripts/package_helper.py verify
python3 -m unittest scripts/test_package_helper.py
bash scripts/cargo.sh test --release --locked --offline --bin allowly-witness-poc
```

`--local` permits an untagged or dirty development checkout, but its archive
must not be published. Omit `--offline` when first obtaining locked crates.
Without `--local`, the packager requires a clean checkout at a tag matching
the Cargo version, such as `witness-v0.1.0`. Run the build and Rust test on each native
target. Build the source asset once from that same tagged checkout. Gather
their tarballs in one directory, run `manifest --output DIR`,
then run `verify --output DIR` and record the printed SHA-256 digest of
`SHA256SUMS` for the CLI pin. Publish the exact checked tarballs and checksum
file together only through the normal release process. No command here uploads
or publishes anything.

The tar/gzip wrapper is repeatable for the same binary. Separate macOS Rust
builds can differ in linker UUID and signature bytes even with the same pinned
source and toolchain, so generate release checksums from the exact binaries
being published. Do not reuse a checksum from a local test build.

To test the CLI before a published release exists, give it the local archive
and its explicit SHA-256 digest. It should still apply the same archive checks
and install to the same private, versioned location. The SDKs then discover that
local installation through the CLI's shared configuration. Source installation
requires the published, pinned source asset; it does not combine with the
offline `--archive`, `--sha256`, or existing `--helper` options. Before release,
test the source archive's contents and a local locked Rust build separately.
