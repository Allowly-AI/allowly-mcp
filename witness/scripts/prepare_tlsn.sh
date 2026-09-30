#!/usr/bin/env bash
# Fetch the exact TLSNotary source used by Cargo's local path dependencies.
set -euo pipefail
cd "$(dirname "$0")/.."

readonly TLSN_REV=47aee45b53e06648c1b2ad3689b367b8c923fdec
readonly TLSN_TAG=v0.1.0-alpha.15

if [[ ! -d vendor/tlsn/.git ]]; then
  if [[ -e vendor/tlsn ]]; then
    echo 'vendor/tlsn exists but is not a Git checkout' >&2
    exit 1
  fi
  mkdir -p vendor
  git clone --depth 1 --branch "$TLSN_TAG" https://github.com/tlsnotary/tlsn.git vendor/tlsn
fi

[[ "$(git -C vendor/tlsn rev-parse HEAD)" == "$TLSN_REV" ]] || {
  echo "TLSNotary checkout must be $TLSN_REV ($TLSN_TAG)" >&2
  exit 1
}
[[ -z "$(git -C vendor/tlsn status --porcelain)" ]] || {
  echo 'TLSNotary checkout must be unmodified' >&2
  exit 1
}
