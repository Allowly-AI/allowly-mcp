"""Local adapter tests. FakeKms is not Google Cloud KMS or TLSNotary witnessing."""

import hashlib
import datetime as dt
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import google_crc32c
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from google.cloud import kms_v1

sys.path.insert(0, str(Path(__file__).parent))
from gcp_signer import (  # noqa: E402
    ALGORITHM,
    KmsIntegrityError,
    create_client,
    get_public_key,
    main,
    sec1_bytes,
    sign_message,
)

NAME = "projects/test-only/locations/global/keyRings/tests/cryptoKeys/witness-poc/cryptoKeyVersions/1"
MESSAGE = b"\x00TLSNotary BCS header adapter test\xff\x80\n"


class FakeKms:
    """Standards-based fake: consume a digest and return DER ECDSA like KMS."""

    def __init__(self):
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.public_fault = None
        self.sign_fault = None
        self.last_request = None
        self.double_hash = False

    def get_public_key(self, *, request, timeout, retry):
        assert timeout > 0 and retry is None
        pem = self.private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        response = kms_v1.PublicKey(
            name=request["name"], algorithm=ALGORITHM, pem=pem,
            pem_crc32c=google_crc32c.value(pem.encode()),
        )
        if self.public_fault:
            setattr(response, *self.public_fault)
        return response

    def asymmetric_sign(self, *, request, timeout, retry):
        assert timeout > 0 and retry is None
        self.last_request = request
        digest = request["digest"]["sha256"]
        assert google_crc32c.value(digest) == request["digest_crc32c"]
        if self.sign_fault == "unavailable":
            raise ConnectionError("fake KMS unavailable")
        # Prehashed is essential: ECDSA(SHA256()) here would hash twice.
        algorithm = hashes.SHA256() if self.double_hash else utils.Prehashed(hashes.SHA256())
        der = self.private.sign(digest, ec.ECDSA(algorithm))
        response = kms_v1.AsymmetricSignResponse(
            name=request["name"], signature=der,
            signature_crc32c=google_crc32c.value(der), verified_digest_crc32c=True,
        )
        if self.sign_fault:
            setattr(response, *self.sign_fault)
        return response


class KmsAdapterTests(unittest.TestCase):
    def setUp(self):
        self.client = FakeKms()

    def test_hash_once_and_convert_der_to_fixed_width(self):
        fixed = sign_message(self.client, NAME, MESSAGE)
        self.assertEqual(len(fixed), 64)
        self.assertEqual(self.client.last_request["digest"], {"sha256": hashlib.sha256(MESSAGE).digest()})
        self.assertNotIn("data", self.client.last_request)
        r, s = int.from_bytes(fixed[:32], "big"), int.from_bytes(fixed[32:], "big")
        self.client.private.public_key().verify(
            utils.encode_dss_signature(r, s), MESSAGE, ec.ECDSA(hashes.SHA256())
        )

    def test_double_hash_is_rejected(self):
        self.client.double_hash = True
        with self.assertRaises(InvalidSignature):
            sign_message(self.client, NAME, MESSAGE)

    def test_public_pem_converts_to_valid_sec1(self):
        public = get_public_key(self.client, NAME)
        encoded = sec1_bytes(public)
        self.assertEqual(len(encoded), 33)
        decoded = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), encoded)
        self.assertEqual(decoded.public_numbers(), public.public_numbers())

    def test_public_key_wrong_algorithm_is_rejected_before_signing(self):
        self.client.public_fault = ("algorithm", kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm.EC_SIGN_ED25519)
        with self.assertRaisesRegex(KmsIntegrityError, "algorithm"):
            sign_message(self.client, NAME, MESSAGE)
        self.assertIsNone(self.client.last_request)

    def test_public_key_wrong_curve_is_rejected(self):
        self.client.private = ec.generate_private_key(ec.SECP384R1())
        with self.assertRaisesRegex(KmsIntegrityError, "not P-256"):
            get_public_key(self.client, NAME)

    def test_public_key_corrupt_checksum_is_rejected(self):
        self.client.public_fault = ("pem_crc32c", -1)
        with self.assertRaisesRegex(KmsIntegrityError, "checksum"):
            get_public_key(self.client, NAME)

    def test_public_key_wrong_version_is_rejected(self):
        self.client.public_fault = ("name", NAME + "2")
        with self.assertRaisesRegex(KmsIntegrityError, "version"):
            get_public_key(self.client, NAME)

    def test_signature_wrong_version_is_rejected(self):
        self.client.sign_fault = ("name", NAME + "2")
        with self.assertRaisesRegex(KmsIntegrityError, "version"):
            sign_message(self.client, NAME, MESSAGE)

    def test_signature_corrupt_checksum_is_rejected(self):
        self.client.sign_fault = ("signature_crc32c", -1)
        with self.assertRaisesRegex(KmsIntegrityError, "checksum"):
            sign_message(self.client, NAME, MESSAGE)

    def test_kms_must_confirm_digest_checksum(self):
        self.client.sign_fault = ("verified_digest_crc32c", False)
        with self.assertRaisesRegex(KmsIntegrityError, "request checksum"):
            sign_message(self.client, NAME, MESSAGE)

    def test_signing_failure_propagates(self):
        self.client.sign_fault = "unavailable"
        with self.assertRaises(ConnectionError):
            sign_message(self.client, NAME, MESSAGE)

    def test_wrong_message_and_wrong_key_fail(self):
        fixed = sign_message(self.client, NAME, MESSAGE)
        der = utils.encode_dss_signature(
            int.from_bytes(fixed[:32], "big"), int.from_bytes(fixed[32:], "big")
        )
        with self.assertRaises(InvalidSignature):
            self.client.private.public_key().verify(der, MESSAGE + b"!", ec.ECDSA(hashes.SHA256()))
        with self.assertRaises(InvalidSignature):
            FakeKms().private.public_key().verify(der, MESSAGE, ec.ECDSA(hashes.SHA256()))

    def test_message_and_key_input_limits(self):
        for message in (b"", b"x" * 65_537):
            with self.subTest(length=len(message)), self.assertRaises(ValueError):
                sign_message(self.client, NAME, message)
        for name in ("", NAME.removesuffix("/1"), NAME.removesuffix("/1") + "/latest"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                get_public_key(self.client, name)
        self.assertIsNone(self.client.last_request)

    def test_cli_failure_outputs_no_message_or_partial_json(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("gcp_signer.py")), "sign", "--key-version", "invalid"],
            input=b"DO-NOT-LOG-THIS-HEADER", capture_output=True, timeout=5,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"DO-NOT-LOG", result.stderr)
        self.assertEqual(result.stderr, b"KMS operation failed (ValueError).\n")


class CredentialSelectionTests(unittest.TestCase):
    def test_adc_is_default_and_never_calls_gcloud(self):
        with patch.dict(os.environ, {}, clear=True), patch(
            "gcp_signer.kms_v1.KeyManagementServiceClient"
        ) as client, patch("gcp_signer.subprocess.run") as run:
            self.assertIs(create_client(), client.return_value)
            client.assert_called_once_with()
            run.assert_not_called()

    def test_adc_failure_has_no_gcloud_fallback(self):
        with patch.dict(os.environ, {"ALLOWLY_KMS_AUTH": "adc"}), patch(
            "gcp_signer.kms_v1.KeyManagementServiceClient", side_effect=RuntimeError("ADC unavailable")
        ), patch("gcp_signer.subprocess.run") as run:
            with self.assertRaises(RuntimeError):
                create_client()
            run.assert_not_called()

    def test_invalid_mode_fails_closed_before_any_authentication(self):
        for mode in ("", "ADC", "auto", "gcloud "):
            with self.subTest(mode=mode), patch.dict(os.environ, {"ALLOWLY_KMS_AUTH": mode}), patch(
                "gcp_signer.kms_v1.KeyManagementServiceClient"
            ) as client, patch("gcp_signer.subprocess.run") as run:
                with self.assertRaises(ValueError):
                    create_client()
                client.assert_not_called()
                run.assert_not_called()

    def test_explicit_gcloud_keeps_token_in_memory_without_quota_project(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"ALLOWLY_KMS_AUTH": "gcloud", "GOOGLE_CLOUD_QUOTA_PROJECT": "ignored-for-explicit-creds"}), patch(
            "gcp_signer.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"test-only-token\n", b"private diagnostic")
        ) as run, patch("gcp_signer.kms_v1.KeyManagementServiceClient") as client, redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertIs(create_client(), client.return_value)
            run.assert_called_once_with(["gcloud", "auth", "print-access-token"], capture_output=True, timeout=10, check=True)
            credentials = client.call_args.kwargs["credentials"]
            self.assertEqual(credentials.token, "test-only-token")
            self.assertIsNone(credentials.quota_project_id)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

    def test_token_file_is_read_for_each_kms_operation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kms-token.json"
            expires = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)).isoformat()
            path.write_text(json.dumps({"access_token": "first-impersonated-token", "expire_time": expires}))
            with patch.dict(os.environ, {
                "ALLOWLY_KMS_AUTH": "token-file",
                "ALLOWLY_KMS_ACCESS_TOKEN_FILE": str(path),
            }), patch("gcp_signer.kms_v1.KeyManagementServiceClient") as client, patch(
                "gcp_signer.subprocess.run"
            ) as run:
                create_client()
                self.assertEqual(client.call_args.kwargs["credentials"].token, "first-impersonated-token")
                path.write_text(json.dumps({"access_token": "rotated-impersonated-token", "expire_time": expires}))
                create_client()
                self.assertEqual(client.call_args.kwargs["credentials"].token, "rotated-impersonated-token")
                run.assert_not_called()

    def test_token_file_missing_or_invalid_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kms-token.json"
            future = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)).isoformat()
            past = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=1)).isoformat()
            near_expiry = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=30)).isoformat()
            for value in (
                None, "", "token with spaces", "bad\x00token",
                json.dumps({"access_token": "valid", "expire_time": past}),
                json.dumps({"access_token": "valid", "expire_time": near_expiry}),
                json.dumps({"access_token": "valid", "expire_time": future, "extra": "bad"}),
                '{"access_token":"valid","access_token":"duplicate","expire_time":"' + future + '"}',
            ):
                if value is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(value if value.startswith("{") else json.dumps({"access_token": value, "expire_time": future}))
                with self.subTest(value=value), patch.dict(os.environ, {
                    "ALLOWLY_KMS_AUTH": "token-file",
                    "ALLOWLY_KMS_ACCESS_TOKEN_FILE": str(path),
                }), patch("gcp_signer.kms_v1.KeyManagementServiceClient") as client:
                    with self.assertRaises(ValueError):
                        create_client()
                    client.assert_not_called()

    def test_invalid_gcloud_token_is_rejected_without_client(self):
        for token in (b"", b" \n", b"token with spaces", b"token\x00", b"\xff", b"x" * 8193):
            with self.subTest(token_size=len(token)), patch.dict(os.environ, {"ALLOWLY_KMS_AUTH": "gcloud"}), patch(
                "gcp_signer.subprocess.run", return_value=subprocess.CompletedProcess([], 0, token, b"")
            ), patch("gcp_signer.kms_v1.KeyManagementServiceClient") as client:
                with self.assertRaises(ValueError):
                    create_client()
                client.assert_not_called()

    def test_gcloud_failures_are_sanitized_without_partial_output(self):
        failures = (
            subprocess.CalledProcessError(1, ["gcloud"], output=b"private-token", stderr=b"private-auth-error"),
            subprocess.TimeoutExpired(["gcloud"], timeout=10, output=b"private-token"),
        )
        for failure in failures:
            stdout, stderr = io.StringIO(), io.StringIO()
            with self.subTest(error=type(failure).__name__), patch.dict(os.environ, {"ALLOWLY_KMS_AUTH": "gcloud"}), patch(
                "gcp_signer.subprocess.run", side_effect=failure
            ), patch("sys.argv", ["gcp_signer.py", "public", "--key-version", NAME]), redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(main(), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), f"KMS operation failed ({type(failure).__name__}).\n")


def write_test_vector():
    client = FakeKms()
    fixed = sign_message(client, NAME, MESSAGE)
    result = {
        "kind": "LOCAL_FAKE_KMS_ADAPTER_TEST_ONLY",
        "message_hex": MESSAGE.hex(),
        "sec1_hex": sec1_bytes(client.private.public_key()).hex(),
        "signature_hex": fixed.hex(),
        "wrong_sec1_hex": sec1_bytes(FakeKms().private.public_key()).hex(),
    }
    Path(__file__).with_name("adapter_test_vector.json").write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    if sys.argv[1:] == ["--write-test-vector"]:
        write_test_vector()
    else:
        unittest.main()
