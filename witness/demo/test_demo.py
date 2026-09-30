"""Credential-free checks for the isolated local witness demo."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import existing_workspace
import local_api
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import ASGITransport, AsyncClient
from native_runner import _claimed_key_version, _fingerprint
from server import HEADERS, TARGET_PATH, TARGET_QUERY, Demo, digest, now, verify_outcome_receipt
from witness_config import TEST_KEY_VERSION, WORKSPACE_ID, workspace_key


class WitnessKeySelectionTest(unittest.TestCase):
    def test_claim_selects_only_a_version_of_the_demo_workspace_key(self):
        key_ref, *_ = workspace_key(TEST_KEY_VERSION)
        rotated = key_ref + "/cryptoKeyVersions/7"
        self.assertEqual(_claimed_key_version({"notary_kms_key_version": rotated}, key_ref), rotated)
        for bad in (None, "", key_ref + "/cryptoKeyVersions/0",
                    key_ref.replace(WORKSPACE_ID, "ws_other") + "/cryptoKeyVersions/7"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                _claimed_key_version({"notary_kms_key_version": bad}, key_ref)


class ExistingWorkspaceDemoTest(unittest.TestCase):
    WORKSPACE_ID = "ws_s001_test"
    VERSION = (
        "projects/test-only/locations/global/keyRings/local-demo-witness/"
        "cryptoKeys/ws_s001_test-tlsnotary/cryptoKeyVersions/1"
    )

    def _files(self, state):
        public = ec.derive_private_key(1, ec.SECP256R1()).public_key()
        point = public.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )
        key = {"alg": 2, "data": list(point)}
        trust_path = state / "trusted.json"
        trust_path.write_text(json.dumps(key))
        trust_path.chmod(0o600)
        config = {
            "workspace_id": self.WORKSPACE_ID,
            "api_base_url": "http://127.0.0.1:8085",
            "authorization_id": "auth_github_demo",
            "enabled_executable_id": "exe_github_demo",
            "agent_id": "demoagentidentity",
            "auth0_subject": "testmachine@clients",
            "auth0_issuer": "https://test.us.auth0.com/",
            "auth0_audience": "https://allowly.ai/agent-identity",
            "witness_kms_key_version": self.VERSION,
            "trusted_key_file": str(trust_path),
            "notary_fingerprint_sha256": _fingerprint(key),
            "local_test_signer": True,
            "api_key": "test-runtime-key",
            "internal_token": "test-internal-token",
        }
        config_path = state / "config.json"
        config_path.write_text(json.dumps(config))
        config_path.chmod(0o600)
        return config_path, config, key

    def test_private_config_pins_existing_workspace_without_exposing_secrets(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, private, trusted = self._files(Path(temporary))
            config, credentials, key = existing_workspace.load_config(path)
            self.assertEqual(config["workspace_id"], self.WORKSPACE_ID)
            self.assertEqual(config["policy_resource"], "github:octocat/Hello-World")
            self.assertEqual(config["witness_kms_key_version"], self.VERSION)
            self.assertTrue(config["local_test_signer"])
            self.assertEqual(key, trusted)
            self.assertEqual(credentials["api_key"], private["api_key"])
            self.assertNotIn("api_key", config)
            self.assertNotIn("internal_token", config)

    def test_existing_config_fails_closed_on_mode_trust_and_file_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, private, _key = self._files(Path(temporary))
            path.chmod(0o644)
            with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                existing_workspace.load_config(path)
            path.chmod(0o600)
            private["witness_kms_key_version"] = self.VERSION.replace(
                self.WORKSPACE_ID, "ws_other"
            )
            path.write_text(json.dumps(private))
            with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                existing_workspace.load_config(path)
            private["witness_kms_key_version"] = self.VERSION
            private["notary_fingerprint_sha256"] = "0" * 64
            path.write_text(json.dumps(private))
            with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                existing_workspace.load_config(path)
            private["notary_fingerprint_sha256"] = _fingerprint(_key)
            private["api_base_url"] = "https://not-local.example"
            path.write_text(json.dumps(private))
            with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                existing_workspace.load_config(path)

    def test_live_preflight_requires_matching_authorization_binding_and_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _private, key = self._files(Path(temporary))
            config, _credentials, _key = existing_workspace.load_config(path)
            identity = {
                "mode": "provider", "provider": "auth0", "binding_id": "binding_1",
                "subject": config["auth0_subject"], "issuer": config["auth0_issuer"],
                "audience": config["auth0_audience"],
            }
            binding = {
                "status": "configured", "provider": "auth0", "agent_id": config["agent_id"],
                "owner_account_user_id": "owner_1", **identity,
            }
            authorization = {
                "id": config["authorization_id"], "agent_id": config["agent_id"],
                "actions": [{"name": "github.issues.list", "constraints": {
                    "resource_pattern": "github:octocat/Hello-World"},
                    "executable_operations": [{
                        "enabled_executable_id": config["enabled_executable_id"],
                        "operation_id": "github.issues.list",
                        "minimum_evidence_mode": "witnessed",
                    }]}],
                "authorization_provenance": {"protected_item": {
                    "id": config["agent_id"], "identity": identity,
                    "owner": {"status": "customer_declared", "account_user_id": "owner_1"},
                }},
            }
            responses = {
                "/v1/authorizations": {"items": [authorization]},
                "identity-bindings": binding,
                "identity/auth0": {"status": "configured", "issuer": config["auth0_issuer"],
                                   "audience": config["auth0_audience"]},
                "witness-key": {"workspace_id": config["workspace_id"],
                                "kms_key_version": config["witness_kms_key_version"],
                                "fingerprint_sha256": "sha256:" + _fingerprint(key),
                                "public_key": key},
            }
            calls = []

            def api(path, *, internal=False):
                calls.append((path, internal))
                return next(value for name, value in responses.items() if name in path)

            existing_workspace.verify_runtime_state(api, config, key)
            self.assertEqual(len(calls), 4)
            self.assertEqual([flag for _path, flag in calls], [False, True, True, True])
            binding["subject"] = "other@clients"
            with self.assertRaises(existing_workspace.ExistingWorkspaceError):
                existing_workspace.verify_runtime_state(api, config, key)

    def test_auth0_token_is_minted_inside_app_container_only(self):
        config = {"workspace_id": self.WORKSPACE_ID, "auth0_subject": "testmachine@clients",
                  "auth0_audience": "https://allowly.ai/agent-identity",
                  "auth0_issuer": "https://test.us.auth0.com/"}
        with patch.object(existing_workspace.subprocess, "run", return_value=SimpleNamespace(
            returncode=0, stdout="short.lived.token", stderr=""
        )) as run:
            token = existing_workspace.fetch_auth0_token(config)
        self.assertEqual(token, "short.lived.token")
        command = run.call_args.args[0]
        self.assertEqual(command[:7], ["docker", "compose", "exec", "-T", "allowly-api",
                                       "/app/.venv/bin/python", "-c"])
        self.assertNotIn("short.lived.token", repr(run.call_args))
        with (patch.object(existing_workspace.subprocess, "run", return_value=SimpleNamespace(
            returncode=1, stdout="", stderr="sensitive diagnostic"
        )), self.assertRaises(existing_workspace.ExistingWorkspaceError) as error):
            existing_workspace.fetch_auth0_token(config)
        self.assertNotIn("sensitive diagnostic", str(error.exception))

    def test_existing_demo_requires_token_for_execute_without_exposing_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _private, key = self._files(Path(temporary))
            config, credentials, _key = existing_workspace.load_config(path)
            demo = Demo(Path(temporary), config, credentials, key, "gcloud", Path("unused"))
            opened = []

            def open_request(request, timeout):
                opened.append(request)
                return io.BytesIO(b"{}")

            demo.http.open = open_request
            with self.assertRaisesRegex(RuntimeError, "fresh Auth0 machine token"):
                demo.api("/v1/execute", {})
            self.assertEqual(opened, [])
            demo.api("/v1/execute", {}, agent_token="short.lived.token")
            self.assertEqual(opened[0].get_header("X-allowly-agent-token"), "short.lived.token")
            self.assertEqual(opened[0].full_url, "http://127.0.0.1:8085/v1/execute")

    def test_internal_preflight_signs_path_and_query_separately(self):
        with tempfile.TemporaryDirectory() as temporary:
            path, _private, key = self._files(Path(temporary))
            config, credentials, _key = existing_workspace.load_config(path)
            demo = Demo(Path(temporary), config, credentials, key, "gcloud", Path("unused"))
            opened = []

            def open_request(request, timeout):
                opened.append(request)
                return io.BytesIO(b"{}")

            demo.http.open = open_request
            api_path = f"/internal/workspaces/{self.WORKSPACE_ID}/identity-bindings?agent_id=demoagentidentity"
            demo.api(api_path, internal=True)
            request = opened[0]
            self.assertEqual(request.full_url, config["api_base_url"] + api_path)
            message = "\n".join([
                "GET", f"/internal/workspaces/{self.WORKSPACE_ID}/identity-bindings",
                "agent_id=demoagentidentity", self.WORKSPACE_ID,
                request.get_header("X-allowly-internal-timestamp"),
                request.get_header("X-allowly-internal-nonce"),
                hashlib.sha256(b"").hexdigest(),
            ]).encode()
            expected = hmac.new(credentials["internal_token"].encode(), message,
                                hashlib.sha256).hexdigest()
            self.assertEqual(request.get_header("X-allowly-internal-signature"), expected)

    def test_signed_after_receipt_must_link_to_decision_and_observed_response(self):
        with tempfile.TemporaryDirectory() as temporary:
            proof_dir = Path(temporary) / "witness"
            proof_dir.mkdir()
            (proof_dir / "presentation.json").write_bytes(b"proof")
            (proof_dir / "attestation.json").write_bytes(b"{}")
            record = {
                "type": "execution.outcome", "operation_id": "op_1",
                "authorization_id": "auth_1", "decision_receipt_id": "rcp_before",
                "approval_sha256": "sha256:approval", "destination_id": "exe_1",
                "action": "github.issues.list", "catalog_operation_id": "github.issues.list",
                "request_fingerprint": "sha256:request",
                "evidence_source": "independent_witness_customer_held_bundle",
                "target_state": "response_observed", "transport_status": "succeeded",
                "witness": {"status": "verified_reference", "evidence_bundle_sha256": digest(b"proof"),
                            "notary_attestation_sha256": digest(b"{}")},
                "downstream": {"http_status": 200, "response_fingerprint": "sha256:body"},
            }
            execution = SimpleNamespace(
                operation_id="op_1", request_descriptor=SimpleNamespace(authorization_id="auth_1"),
                approval_sha256="sha256:approval", destination_id="exe_1",
                action="github.issues.list", request_fingerprint="sha256:request",
                outcome_evidence=SimpleNamespace(record=record, record_sha256="a" * 64),
            )
            decision = {
                "approval": {"workspace_id": self.WORKSPACE_ID, "operation_id": "op_1",
                             "authorization_id": "auth_1", "action": "github.issues.list",
                             "executable": {"enabled_executable_id": "exe_1",
                                            "catalog_operation_id": "github.issues.list"}},
                "approval_sha256": "sha256:approval",
                "decision_receipt": {"receipt_id": "rcp_before"},
                "decision_receipt_verified": True,
            }
            receipt = {"receipt_id": "rcp_after",
                       "context": {"seal_origin": "allowly.execution.outcome.v1"}}
            response = {"status": 200, "body_sha256": "sha256:body"}
            verifier = ModuleType("allowly.verify")
            verifier.hash_seal_value = lambda _record: "a" * 64
            verifier.verify_seal_value = lambda *_args, **_kwargs: SimpleNamespace(
                signature_verified=True, record_matches=True,
            )

            def verify():
                verify_outcome_receipt(
                    execution, receipt, [], workspace_id=self.WORKSPACE_ID,
                    decision_package=decision, expected_receipt_id="rcp_after",
                    response=response, operation_dir=temporary,
                )

            with patch.dict(sys.modules, {"allowly": ModuleType("allowly"), "allowly.verify": verifier}):
                verify()
                execution.outcome_evidence.record_sha256 = "sha256:" + "a" * 64
                with self.assertRaisesRegex(ValueError, "does not bind"):
                    verify()
                execution.outcome_evidence.record_sha256 = "a" * 64
                decision["approval_sha256"] = "sha256:other"
                with self.assertRaisesRegex(ValueError, "do not identify"):
                    verify()
                decision["approval_sha256"] = "sha256:approval"
                decision["approval"]["action"] = "other.action"
                with self.assertRaisesRegex(ValueError, "do not identify"):
                    verify()
                decision["approval"]["action"] = "github.issues.list"
                decision["approval"]["executable"]["catalog_operation_id"] = "other.operation"
                with self.assertRaisesRegex(ValueError, "does not bind"):
                    verify()
                decision["approval"]["executable"]["catalog_operation_id"] = "github.issues.list"
                receipt["context"].pop("seal_origin")
                with self.assertRaisesRegex(ValueError, "do not identify"):
                    verify()
                receipt["context"]["seal_origin"] = "allowly.execution.outcome.v1"
                receipt["receipt_id"] = "rcp_other"
                with self.assertRaisesRegex(ValueError, "do not identify"):
                    verify()
                receipt["receipt_id"] = "rcp_after"
                record["witness"]["evidence_bundle_sha256"] = digest(b"other")
                with self.assertRaisesRegex(ValueError, "does not bind"):
                    verify()
                record["witness"]["evidence_bundle_sha256"] = digest(b"proof")
                verifier.verify_seal_value = lambda *_args, **_kwargs: SimpleNamespace(
                    signature_verified=False, record_matches=True,
                )
                with self.assertRaisesRegex(ValueError, "does not match"):
                    verify()


class LocalApiWitnessFlowTest(unittest.TestCase):
    def test_local_api_issues_workspace_key_claim_without_cloud_credentials(self):
        asyncio.run(self._check_local_api())

    async def _check_local_api(self):
        # API admission checks only that the verifier path is executable. The
        # smoke never dispatches or verifies, so the Python binary suffices.
        verifier = Path(sys.executable)
        public = ec.derive_private_key(1, ec.SECP256R1()).public_key()
        sec1 = public.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )
        trusted = {"alg": 2, "data": list(sec1)}
        fingerprint = _fingerprint(trusted)
        key_ref, project, location, ring = workspace_key(TEST_KEY_VERSION)
        self.assertEqual((project, location, ring), ("test-only", "global", "local-demo-witness"))

        with tempfile.TemporaryDirectory(prefix="allowly-witness-demo-") as temporary:
            state = Path(temporary)
            trust_path = state / "trusted-notary-key.json"
            trust_path.write_text(json.dumps(trusted))
            trust_path.chmod(0o600)
            args = argparse.Namespace(
                state_dir=state / "api", port=8811, repository="octocat/Hello-World",
                witness_url="wss://127.0.0.1:8810", notary_public_key=trust_path,
                notary_fingerprint=fingerprint, verifier_bin=verifier,
                witness_key_version=TEST_KEY_VERSION, witness_key_ref=key_ref,
                kms_project=project, kms_location=location, witness_key_ring=ring,
                local_test_signer=True,
            )
            for name in ("GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CONFIG", "ALLOWLY_KMS_AUTH"):
                os.environ.pop(name, None)
            credentials = local_api.configure(args)
            config = await local_api.seed(args, credentials)
            self.assertEqual(config["witness_kms_key_ref"], key_ref)
            with sqlite3.connect(state / "api/runtime.db") as database:
                saved = database.execute(
                    "SELECT witness_kms_key_ref FROM workspaces WHERE id = ?", (WORKSPACE_ID,)
                ).fetchone()
            self.assertEqual(saved, (key_ref,))

            from app.services import execution_witness
            original_active_key = execution_witness.active_key
            local_api.install_local_test_signer(args)
            try:
                from app.main import app

                async with AsyncClient(transport=ASGITransport(app=app), base_url="http://127.0.0.1:8811") as client:
                    request = {
                        "method": "GET", "origin": "https://api.github.com", "path": TARGET_PATH,
                        "query": TARGET_QUERY, "body_size": 0, "body_sha256": digest(b""),
                        "content_type": None, "headers": [
                            {"name": name, "value_sha256": digest(
                                b"allowly.execution.header.v1\0" + name.encode() + b"\0" + value.encode())}
                            for name, value in sorted(HEADERS.items())
                        ],
                    }
                    operation_id = str(uuid.uuid4())
                    body = {
                        "operation_id": operation_id,
                        "authorization_id": config["authorization_id"],
                        "enabled_executable_id": config["enabled_executable_id"],
                        "catalog_operation_id": "github.issues.list", "action": "github.issues.list",
                        "evidence_mode": "witnessed", "http_request": request,
                        "policy_input": {"resource": config["policy_resource"], "context": {}},
                        "client_timestamp": now(),
                    }
                    customer_headers = {"Authorization": "Bearer " + credentials["api_key"]}
                    response = await client.post("/v1/execute", json=body, headers={
                        **customer_headers, "Idempotency-Key": "prepare-" + operation_id,
                    })
                    self.assertEqual(response.status_code, 201, response.text)
                    approval = response.json()
                    self.assertEqual(approval["decision"], "allow")
                    response = await client.post(
                        f"/v1/executions/{operation_id}/witness-session-token",
                        json={"approval_sha256": approval["approval_sha256"]}, headers=customer_headers,
                    )
                    self.assertEqual(response.status_code, 200, response.text)
                    token = response.json()
                    path = f"/internal/execution-witness/sessions/{token['session_id']}/claim"
                    claim_body = {
                        "admission_token": token["admission_token"],
                        "bridge_instance_id": "localhost-demo-test",
                        "native_profile": token["native_profile"],
                    }
                    payload = json.dumps(claim_body, separators=(",", ":")).encode()
                    timestamp, nonce = str(int(time.time())), secrets.token_urlsafe(16)
                    message = "\n".join([
                        "POST", path, "", WORKSPACE_ID, timestamp, nonce,
                        hashlib.sha256(payload).hexdigest(),
                    ]).encode()
                    signature = hmac.new(credentials["internal_token"].encode(), message, hashlib.sha256).hexdigest()
                    response = await client.post(path, content=payload, headers={
                        "Content-Type": "application/json",
                        "X-Allowly-Internal-Timestamp": timestamp,
                        "X-Allowly-Internal-Nonce": nonce,
                        "X-Allowly-Internal-Workspace": WORKSPACE_ID,
                        "X-Allowly-Internal-Signature": signature,
                    })
                    self.assertEqual(response.status_code, 200, response.text)
                    claim = response.json()
                    self.assertEqual(_claimed_key_version(claim, key_ref), TEST_KEY_VERSION)
                    self.assertEqual(claim["trusted_notary_key_fingerprint_sha256"], fingerprint)
                    self.assertEqual(claim["workspace_id"], WORKSPACE_ID)
            finally:
                execution_witness.active_key = original_active_key
                from app.database import engine
                await engine.dispose()


if __name__ == "__main__":
    unittest.main()
