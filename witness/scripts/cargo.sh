#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -d .toolchain/rustup ]]; then
  export CARGO_HOME="$PWD/.toolchain/cargo"
  export RUSTUP_HOME="$PWD/.toolchain/rustup"
  export PATH="$CARGO_HOME/bin:$PATH"
fi
exec cargo "$@"
