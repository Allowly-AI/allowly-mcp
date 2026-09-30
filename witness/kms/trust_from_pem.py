#!/usr/bin/env python3
"""Convert an independently obtained P-256 SPKI PEM to TLSNotary trust JSON.

This performs no authentication: obtain the PEM over a separately trusted path.
"""
import argparse
import hashlib
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('pem', type=Path)
parser.add_argument('output', type=Path)
args = parser.parse_args()
key = serialization.load_pem_public_key(args.pem.read_bytes())
if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
    raise SystemExit('Expected a P-256 public key')
sec1 = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
with args.output.open('x') as destination:
    json.dump({'alg': 2, 'data': list(sec1)}, destination, indent=2)
    destination.write('\n')
print('sha256(compressed SEC1): ' + hashlib.sha256(sec1).hexdigest())
