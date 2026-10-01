#!/usr/bin/env bash
# Reproducible local dependencies; no cloud resource changes.
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/prepare_tlsn.sh
# Rust 1.95.0 is required by the pinned mpz dependency. Install Rust with rustup
# if needed; scripts/cargo.sh also recognizes a local .toolchain install.
bash scripts/cargo.sh build --release --locked
