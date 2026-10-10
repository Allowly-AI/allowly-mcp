"""Credential-free native identity checks for the existing-workspace HTML lab."""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

import existing_workspace
from native_runner import _fingerprint


class OwnerLookupFailure(RuntimeError):
    def __init__(self, status_code, error_code):
        super().__init__(status_code, error_code)
        self.status_code = status_code
        self.error_code = error_code


class NativeIdentityDemoTest(unittest.TestCase):
    WORKSPACE_ID = "ws_s001_native_test"
    AGENT_ID = "demo4"
    VERSION = (
        "projects/test-only/locations/global/keyRings/local-demo-witness/"
        "cryptoKeys/ws_s001_native_test-tlsnotary/cryptoKeyVersions/1"
    )

    @staticmethod
    def _write(path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def _files(self, state):
        raw_private = b"\x17" * 32
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_private)
        raw_public = private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        encode = lambda data: base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        credential = {
            "version": 1, "provider": "allowly", "workspace_id": self.WORKSPACE_ID,
            "agent_id": self.AGENT_ID, "binding_id": "aib_native_test", "key_id": "ack_native_test",
            "private_key_jwk": {
                "kty": "OKP", "crv": "Ed25519", "d": encode(raw_private), "x": encode(raw_public),
            },
        }
        credential_path = state / "agent.json"
        self._write(credential_path, credential)
        public = ec.derive_private_key(1, ec.SECP256R1()).public_key()
        key = {"alg": 2, "data": list(public.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint,
        ))}
        trust_path = state / "trusted.json"
        self._write(trust_path, key)
        private = {
            "workspace_id": self.WORKSPACE_ID, "api_base_url": "http://127.0.0.1:8085",
            "authorization_id": "auth_native_test", "enabled_executable_id": "exe_native_test",
            "agent_id": self.AGENT_ID, "identity_provider": "allowly", "policy_action": "github.read",
            "agent_credential_file": str(credential_path), "witness_kms_key_version": self.VERSION,
            "trusted_key_file": str(trust_path), "notary_fingerprint_sha256": _fingerprint(key),
            "local_test_signer": True, "api_key": "test-runtime-key", "internal_token": "test-internal-token",
        }
        config_path = state / "config.json"
        self._write(config_path, private)
        return config_path, private, credential, key

    def _responses(self, config, credential, key):
        return {
            "/v1/authorizations": {"items": [{
                "id": config["authorization_id"], "agent_id": self.AGENT_ID,
                "actions": [{
                    "name": "github.read", "constraints": {"resource_pattern": "github:octocat/Hello-World"},
                    "executable_operations": [{
                        "enabled_executable_id": config["enabled_executable_id"],
                        "operation_id": "github.issues.list", "minimum_evidence_mode": "witnessed",
                    }],
                }],
                "authorization_provenance": {"protected_item": {
                    "id": self.AGENT_ID,
                    "identity": {
                        "mode": "provider", "provider": "allowly", "credential_type": "ed25519_jwt",
                        "binding_id": credential["binding_id"], "issuer": "allowly-agent",
                        "audience": self.WORKSPACE_ID, "subject": self.AGENT_ID,
                    },
                    "owner": {"status": "customer_declared", "account_user_id": "owner_test"},
                }},
            }]},
            "identity-bindings": {
                "status": "configured", "agent_id": self.AGENT_ID, "provider": None,
                "owner_account_user_id": "owner_test", "binding_id": None,
            },
            "agent-credentials": {"agent_id": self.AGENT_ID, "credentials": [{
                "key_id": credential["key_id"], "binding_id": credential["binding_id"],
                "agent_id": self.AGENT_ID, "status": "active",
            }]},
            "witness-key": {
                "workspace_id": self.WORKSPACE_ID, "kms_key_version": self.VERSION,
                "fingerprint_sha256": "sha256:" + _fingerprint(key), "public_key": key,
            },
        }

    @staticmethod
    def _api(responses, calls):
        def api(path, *, internal=False):
            calls.append((path, internal))
            value = next(value for name, value in responses.items() if name in path)
            if isinstance(value, Exception):
                raise value
            return value
        return api

    def test_config_keeps_private_key_out_of_public_state_and_mints_native_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _private, source, key = self._files(Path(temporary))
            config, credentials, trusted = existing_workspace.load_config(path)
            self.assertEqual(config["identity_provider"], "allowly")
            self.assertEqual(config["policy_action"], "github.read")
            self.assertEqual(trusted, key)
            self.assertEqual(credentials["api_key"], "test-runtime-key")
            encoded = json.dumps(config)
            for secret in ("private_key_jwk", source["private_key_jwk"]["d"], "test-runtime-key", "test-internal-token"):
                self.assertNotIn(secret, encoded)
            credential = existing_workspace.load_native_credential(config)
            token = credential.token()
            header, claims, signature = token.split(".")
            self.assertTrue(header and signature)
            claim = json.loads(base64.urlsafe_b64decode(claims + "=" * (-len(claims) % 4)))
            self.assertEqual(claim["aud"], self.WORKSPACE_ID)
            self.assertEqual(claim["sub"], self.AGENT_ID)
            self.assertEqual(claim["exp"] - claim["iat"], 60)

    def test_native_credential_rejects_permissions_symlinks_and_identity_mismatches(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            path, private, credential, _key = self._files(state)
            credential_path = Path(private["agent_credential_file"])
            credential_path.chmod(0o644)
            with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                existing_workspace.load_config(path)
            credential_path.chmod(0o600)
            for field, value in (("workspace_id", "ws_wrong"), ("agent_id", "different-agent"), ("provider", "auth0")):
                with self.subTest(field=field):
                    changed = {**credential, field: value}
                    self._write(credential_path, changed)
                    with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                        existing_workspace.load_config(path)
            self._write(credential_path, credential)
            linked = state / "linked-agent.json"
            linked.symlink_to(credential_path)
            self._write(path, {**private, "agent_credential_file": str(linked)})
            with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                existing_workspace.load_config(path)
            self._write(path, {**private, "agent_credential_file": "agent.json"})
            with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                existing_workspace.load_config(path)

    def test_config_rejects_unsupported_provider_or_policy_action(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, private, _credential, _key = self._files(Path(temporary))
            for field, value in (("identity_provider", "other"), ("policy_action", "github.write"), ("policy_action", ["github.read"])):
                with self.subTest(field=field, value=value):
                    self._write(path, {**private, field: value})
                    with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                        existing_workspace.load_config(path)

    def test_live_preflight_requires_native_snapshot_active_key_owner_and_witness_pin(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _private, credential, key = self._files(Path(temporary))
            config, _credentials, _trusted = existing_workspace.load_config(path)
            responses = self._responses(config, credential, key)
            calls = []
            existing_workspace.verify_runtime_state(self._api(responses, calls), config, key)
            self.assertEqual(len(calls), 4)
            self.assertEqual([internal for _path, internal in calls], [False, True, True, True])
            self.assertTrue(any("agent-credentials?agent_id=demo4" in path for path, _ in calls))
            self.assertFalse(any("identity/auth0" in path for path, _ in calls))

            mutations = [
                ("authorization snapshot provider", lambda data: data["/v1/authorizations"]["items"][0]["authorization_provenance"]["protected_item"]["identity"].update(provider="auth0")),
                ("authorization snapshot mode", lambda data: data["/v1/authorizations"]["items"][0]["authorization_provenance"]["protected_item"]["identity"].update(mode="native")),
                ("authorization snapshot binding", lambda data: data["/v1/authorizations"]["items"][0]["authorization_provenance"]["protected_item"]["identity"].update(binding_id="other-binding")),
                ("authorization snapshot issuer", lambda data: data["/v1/authorizations"]["items"][0]["authorization_provenance"]["protected_item"]["identity"].update(issuer="other-issuer")),
                ("authorization snapshot audience", lambda data: data["/v1/authorizations"]["items"][0]["authorization_provenance"]["protected_item"]["identity"].update(audience="ws_other")),
                ("authorization snapshot subject", lambda data: data["/v1/authorizations"]["items"][0]["authorization_provenance"]["protected_item"]["identity"].update(subject="other-agent")),
                ("authorization snapshot credential type", lambda data: data["/v1/authorizations"]["items"][0]["authorization_provenance"]["protected_item"]["identity"].update(credential_type="oauth2_client_credentials")),
                ("revoked key", lambda data: data["agent-credentials"]["credentials"][0].update(status="revoked")),
                ("missing key", lambda data: data["agent-credentials"].update(credentials=[])),
                ("wrong key", lambda data: data["agent-credentials"]["credentials"][0].update(key_id="ack_other")),
                ("wrong current binding", lambda data: data["agent-credentials"]["credentials"][0].update(binding_id="aib_other")),
                ("wrong current agent", lambda data: data["agent-credentials"]["credentials"][0].update(agent_id="other-agent")),
                ("wrong owner", lambda data: data["identity-bindings"].update(owner_account_user_id="other-owner")),
                ("conflicting provider", lambda data: data["identity-bindings"].update(provider="auth0")),
                ("wrong action", lambda data: data["/v1/authorizations"]["items"][0]["actions"][0].update(name="github.issues.list")),
                ("wrong operation", lambda data: data["/v1/authorizations"]["items"][0]["actions"][0]["executable_operations"][0].update(operation_id="github.pull_requests.list")),
                ("wrong evidence mode", lambda data: data["/v1/authorizations"]["items"][0]["actions"][0]["executable_operations"][0].update(minimum_evidence_mode="receipt")),
                ("wrong resource", lambda data: data["/v1/authorizations"]["items"][0]["actions"][0].update(constraints={"resource_pattern": "*"})),
                ("extra action", lambda data: data["/v1/authorizations"]["items"][0]["actions"].append(copy.deepcopy(data["/v1/authorizations"]["items"][0]["actions"][0]))),
                ("extra operation", lambda data: data["/v1/authorizations"]["items"][0]["actions"][0]["executable_operations"].append(copy.deepcopy(data["/v1/authorizations"]["items"][0]["actions"][0]["executable_operations"][0]))),
                ("changed witness key", lambda data: data["witness-key"].update(fingerprint_sha256="sha256:" + "0" * 64)),
            ]
            for name, mutate in mutations:
                with self.subTest(name=name):
                    changed = copy.deepcopy(responses)
                    mutate(changed)
                    with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                        existing_workspace.verify_runtime_state(self._api(changed, []), config, key)


    def test_unassigned_owner_requires_exact_snapshot_and_live_missing_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _private, credential, key = self._files(Path(temporary))
            config, _credentials, _trusted = existing_workspace.load_config(path)
            responses = self._responses(config, credential, key)
            protected = responses["/v1/authorizations"]["items"][0]["authorization_provenance"]["protected_item"]
            protected["owner"] = dict(existing_workspace.UNVERIFIED_RUNTIME_OWNER)
            responses["identity-bindings"] = OwnerLookupFailure(404, "agent_identity_binding_not_found")
            calls = []
            existing_workspace.verify_runtime_state(self._api(responses, calls), config, key)
            self.assertEqual(len(calls), 4)
            self.assertTrue(any("agent-credentials" in path for path, _ in calls))
            self.assertTrue(any("witness-key" in path for path, _ in calls))

            for name, lookup in (
                ("wrong 404 code", OwnerLookupFailure(404, "authorization_not_found")),
                ("upstream unavailable", OwnerLookupFailure(503, "agent_identity_binding_not_found")),
                ("network failure", ConnectionError("Safe test connection failure")),
                ("newly assigned owner", {"status": "configured", "agent_id": self.AGENT_ID,
                                          "owner_account_user_id": "new-owner", "provider": None}),
                ("new provider binding", {"status": "configured", "agent_id": self.AGENT_ID,
                                         "owner_account_user_id": "new-owner", "provider": "auth0"}),
                ("successful null response", None),
            ):
                with self.subTest(name=name):
                    changed = copy.deepcopy(responses)
                    changed["identity-bindings"] = lookup
                    with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                        existing_workspace.verify_runtime_state(self._api(changed, []), config, key)

            for owner in (
                {**existing_workspace.UNVERIFIED_RUNTIME_OWNER, "account_user_id": "forged-owner"},
                {**existing_workspace.UNVERIFIED_RUNTIME_OWNER, "source": "human_verified"},
                {"status": "unverified"},
                {"kind": "unverified", "source": "runtime_api_key", "status": "customer_declared"},
            ):
                with self.subTest(owner=owner):
                    changed = copy.deepcopy(responses)
                    changed["/v1/authorizations"]["items"][0]["authorization_provenance"]["protected_item"]["owner"] = owner
                    with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                        existing_workspace.verify_runtime_state(self._api(changed, []), config, key)

    def test_configured_native_owner_cannot_become_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _private, credential, key = self._files(Path(temporary))
            config, _credentials, _trusted = existing_workspace.load_config(path)
            responses = self._responses(config, credential, key)
            responses["identity-bindings"] = OwnerLookupFailure(404, "agent_identity_binding_not_found")
            with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                existing_workspace.verify_runtime_state(self._api(responses, []), config, key)


if __name__ == "__main__":
    unittest.main()
