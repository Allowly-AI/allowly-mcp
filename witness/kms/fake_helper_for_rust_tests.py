#!/usr/bin/env python3
"""TEST ONLY: subprocess fixture, never a Cloud KMS or real witness signer.

Uses a publicly known test scalar so separate helper processes share one key.
The real gcp_signer.py does not import or select this fixture.
"""

import argparse
import json
import sys

from cryptography.hazmat.primitives.asymmetric import ec

from gcp_signer import ALGORITHM_NAME, get_public_key, sec1_bytes, sign_message
from test_gcp_signer import FakeKms


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("public", "sign"))
    parser.add_argument("--key-version", required=True)
    args = parser.parse_args()
    key_name = args.key_version.split("/")[-3]
    client = FakeKms()
    client.private = ec.derive_private_key(1, ec.SECP256R1())
    result = {"key_version": args.key_version, "algorithm": ALGORITHM_NAME}
    if args.operation == "public":
        if key_name == "fail-public":
            return 1
        result["sec1_hex"] = sec1_bytes(get_public_key(client, args.key_version)).hex()
        if key_name == "wrong-public-version":
            result["key_version"] = args.key_version + "9"
        if key_name == "wrong-public-algorithm":
            result["algorithm"] = "EC_SIGN_ED25519"
        if key_name == "missing-public":
            del result["sec1_hex"]
    else:
        if key_name == "fail-sign":
            return 1
        message = sys.stdin.buffer.read()
        if key_name == "wrong-signing-key":
            client.private = ec.derive_private_key(2, ec.SECP256R1())
        fixed = sign_message(client, args.key_version, message)
        if key_name == "bad-signature":
            fixed = b"\x00" * 64
        result["signature_hex"] = fixed.hex()
        if key_name == "wrong-sign-version":
            result["key_version"] = args.key_version + "9"
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
