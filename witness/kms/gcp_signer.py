#!/usr/bin/env python3
"""Witness-only Cloud KMS bridge; stdin is the exact TLSNotary signing message.

This is deliberately separate from Allowly's Ed25519 JSON receipt signer.
The KMS key must be a dedicated EC_SIGN_P256_SHA256 key version. KMS credentials
belong to the witness host. Never put them in a customer-side MCP process.
"""

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import time

import google_crc32c
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from google.cloud import kms_v1
from google.oauth2.credentials import Credentials

ALGORITHM = kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_P256_SHA256
ALGORITHM_NAME = "EC_SIGN_P256_SHA256"
KEY_VERSION = re.compile(
    r"projects/[a-zA-Z0-9._:-]+/locations/[a-zA-Z0-9_-]+/keyRings/"
    r"[a-zA-Z0-9_-]+/cryptoKeys/[a-zA-Z0-9_-]+/cryptoKeyVersions/[1-9][0-9]*"
)
MAX_MESSAGE_BYTES = 65_536
RPC_TIMEOUT_SECONDS = 12


class KmsIntegrityError(ValueError):
    """A KMS response did not match the requested operation."""


def create_client():
    """Select witness credentials explicitly; never switch identities on failure."""
    mode = os.environ.get("ALLOWLY_KMS_AUTH", "adc")
    if mode == "adc":
        return kms_v1.KeyManagementServiceClient()
    if mode == "token-file":
        path = pathlib.Path(os.environ.get("ALLOWLY_KMS_ACCESS_TOKEN_FILE", ""))
        if not path.is_absolute() or not path.is_file() or not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("ALLOWLY_KMS_ACCESS_TOKEN_FILE must be an existing regular file")
        with path.open("rb") as file:
            token_bytes = file.read(8193)
        if not 1 <= len(token_bytes) <= 8192:
            raise ValueError("invalid KMS access token file")
        try:
            def unique_object_pairs(items):
                value = {}
                for name, item in items:
                    if name in value:
                        raise ValueError("duplicate KMS token field")
                    value[name] = item
                return value

            pairs = json.loads(token_bytes, object_pairs_hook=unique_object_pairs)
            if not isinstance(pairs, dict) or set(pairs) != {"access_token", "expire_time"}:
                raise ValueError("invalid KMS access token file")
            token = pairs["access_token"]
            expires = pairs["expire_time"]
            if not isinstance(token, str) or not isinstance(expires, str):
                raise ValueError("invalid KMS access token file")
            deadline = dt.datetime.fromisoformat(expires.replace("Z", "+00:00"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid KMS access token file") from exc
        if (
            deadline.tzinfo is None
            or deadline.utcoffset() != dt.timedelta(0)
            or deadline <= dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=60)
        ):
            raise ValueError("KMS access token expired or too close to expiry")
        if not token or any(not 33 <= ord(character) <= 126 for character in token):
            raise ValueError("invalid KMS access token")
        return kms_v1.KeyManagementServiceClient(credentials=Credentials(token=token))
    if mode != "gcloud":
        raise ValueError("ALLOWLY_KMS_AUTH must be adc, token-file, or gcloud")
    # Local operator demo only: the already authenticated gcloud account. Capture
    # both streams; the access token must stay in memory and never reach logs.
    result = subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        capture_output=True,
        timeout=10,
        check=True,
    )
    if not 1 <= len(result.stdout) <= 8192:
        raise ValueError("gcloud returned an invalid access token")
    token = result.stdout.decode("ascii").strip()
    if not token or any(not 33 <= ord(character) <= 126 for character in token):
        raise ValueError("gcloud returned an invalid access token")
    # Explicit credentials have no quota project. Do not change the user's ADC,
    # gcloud configuration, quota project, or IAM to enable this local demo.
    return kms_v1.KeyManagementServiceClient(credentials=Credentials(token=token))


def validate_key_version(name):
    if not KEY_VERSION.fullmatch(name):
        raise ValueError("A complete, numeric KMS key-version resource is required")


def get_public_key(client, name):
    """Validate metadata/checksum and convert KMS SPKI PEM to P-256 SEC1."""
    validate_key_version(name)
    response = client.get_public_key(
        request={"name": name}, timeout=RPC_TIMEOUT_SECONDS, retry=None
    )
    if response.name != name:
        raise KmsIntegrityError("public key version mismatch")
    if response.algorithm != ALGORITHM:
        raise KmsIntegrityError("KMS key algorithm must be EC_SIGN_P256_SHA256")
    pem = response.pem.encode("utf-8")
    if response.pem_crc32c != google_crc32c.value(pem):
        raise KmsIntegrityError("public key checksum mismatch")
    public = serialization.load_pem_public_key(pem)
    if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(
        public.curve, ec.SECP256R1
    ):
        raise KmsIntegrityError("PEM key is not P-256")
    return public


def sec1_bytes(public):
    return public.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )


def sign_message(client, name, message, timing_ms=None):
    """Hash once, request KMS DER ECDSA, verify it, return fixed-width r||s."""
    if not message or len(message) > MAX_MESSAGE_BYTES:
        raise ValueError("TLSNotary signing message must contain 1..65536 bytes")
    started = time.perf_counter()
    public = get_public_key(client, name)
    if timing_ms is not None:
        timing_ms["public_key_rpc_and_validation_ms"] = (
            time.perf_counter() - started
        ) * 1000
    # TLSNotary's SECP256R1 verifier hashes its BCS header message with SHA-256.
    # KMS's digest field is already hashed; never pass this digest as `data`.
    digest = hashlib.sha256(message).digest()
    started = time.perf_counter()
    response = client.asymmetric_sign(
        request={
            "name": name,
            "digest": {"sha256": digest},
            "digest_crc32c": google_crc32c.value(digest),
        },
        timeout=RPC_TIMEOUT_SECONDS,
        retry=None,
    )
    if timing_ms is not None:
        timing_ms["sign_rpc_ms"] = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    if response.name != name:
        raise KmsIntegrityError("signature key version mismatch")
    if not response.verified_digest_crc32c:
        raise KmsIntegrityError("KMS did not verify the request checksum")
    der = bytes(response.signature)
    if response.signature_crc32c != google_crc32c.value(der):
        raise KmsIntegrityError("signature checksum mismatch")
    # Verify against the original message. This rejects accidental double hashing
    # and a wrong key even if metadata/checksums were otherwise valid.
    public.verify(der, message, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    if timing_ms is not None:
        timing_ms["signature_validation_ms"] = (time.perf_counter() - started) * 1000
    return signature


def _deadline(_signum, _frame):
    raise TimeoutError("KMS helper deadline exceeded")


def main():
    # These diagnostics contain durations only. The work total starts after
    # Python/module startup and ends before JSON serialization and process exit.
    work_started = time.perf_counter()
    timing_ms = {} if os.environ.get("ALLOWLY_TIMINGS") == "1" else None
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("public", "sign"))
    parser.add_argument("--key-version", required=True)
    args = parser.parse_args()
    # Whole-process bound includes credential refresh. The Rust caller also
    # enforces a deadline and kills the helper on platforms without SIGALRM.
    if hasattr(signal, "SIGALRM"):
        signal.signal(signal.SIGALRM, _deadline)
        signal.alarm(30)
    try:
        validate_key_version(args.key_version)
        started = time.perf_counter()
        client = create_client()
        if timing_ms is not None:
            timing_ms["client_auth_init_ms"] = (time.perf_counter() - started) * 1000
        result = {"key_version": args.key_version, "algorithm": ALGORITHM_NAME}
        if args.operation == "public":
            started = time.perf_counter()
            result["sec1_hex"] = sec1_bytes(
                get_public_key(client, args.key_version)
            ).hex()
            if timing_ms is not None:
                timing_ms["public_key_rpc_and_validation_ms"] = (
                    time.perf_counter() - started
                ) * 1000
        else:
            message = sys.stdin.buffer.read(MAX_MESSAGE_BYTES + 1)
            result["signature_hex"] = sign_message(
                client, args.key_version, message, timing_ms
            ).hex()
        if timing_ms is not None:
            timing_ms["helper_work_total_ms"] = (
                time.perf_counter() - work_started
            ) * 1000
            result["timing_ms"] = timing_ms
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except Exception as error:
        # Google API/auth exceptions can contain request details. Never print
        # their message, credentials, the header bytes, or a partial result.
        print(f"KMS operation failed ({type(error).__name__}).", file=sys.stderr)
        return 1
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
