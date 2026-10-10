#!/usr/bin/env python3
"""Loopback-only GitHub execution demo using the real local Allowly runtime.

This small adapter calls the existing customer-execution API and native prover.
It is not a replacement SDK or a hosted witness service.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from existing_workspace import (
    ExistingWorkspaceError,
    fetch_auth0_token,
    load_native_credential,
    load_config,
    verify_runtime_state,
)
from native_runner import _fingerprint
from witness_config import TEST_KEY_VERSION, workspace_key

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent.parent
TARGET_PATH = "/repos/octocat/Hello-World/issues"
TARGET_QUERY = "per_page=1&state=all&sort=created&direction=asc"
TARGET_URL = "https://api.github.com" + TARGET_PATH + "?" + TARGET_QUERY
HEADERS = {"user-agent": "Allowly-Witness-Demo", "accept": "application/vnd.github+json"}


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def prefixed(value):
    return value if value.startswith("sha256:") else "sha256:" + value


def save(path, value):
    encoded = json.dumps(value, indent=2, ensure_ascii=False).encode()
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("wb") as handle:
        os.chmod(temporary, 0o600)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def check_existing_state(state, key_ref, fingerprint, local_test_signer):
    config_path = state / "api/runtime-config.json"
    if not config_path.exists():
        return
    config = json.loads(config_path.read_text())
    if (config.get("witness_kms_key_ref") != key_ref
            or config.get("trusted_notary_key_fingerprint_sha256") != fingerprint
            or config.get("local_test_signer") != local_test_signer):
        raise ValueError("Demo key or signer changed; choose a new private --state-dir")


def verify_outcome_receipt(execution, receipt, public_keys, *, workspace_id, decision_package,
                           expected_receipt_id, response, operation_dir):
    """Check the signed after record against this exact witnessed GitHub call."""
    from allowly.verify import hash_seal_value, verify_seal_value

    evidence = execution.outcome_evidence
    if evidence is None or not isinstance(evidence.record, dict):
        raise ValueError("The execution has no after record")
    record = evidence.record
    approval = decision_package.get("approval")
    decision_receipt = decision_package.get("decision_receipt")
    decision_hash = decision_package.get("approval_sha256")
    approved_executable = approval.get("executable") if isinstance(approval, dict) else None
    if (not isinstance(approval, dict) or not isinstance(decision_receipt, dict)
            or not isinstance(receipt, dict)
            or decision_package.get("decision_receipt_verified") is not True
            or not isinstance(decision_receipt.get("receipt_id"), str)
            or not decision_receipt["receipt_id"]
            or not isinstance(expected_receipt_id, str)
            or not expected_receipt_id
            or approval.get("workspace_id") != workspace_id
            or approval.get("operation_id") != execution.operation_id
            or approval.get("authorization_id") != execution.request_descriptor.authorization_id
            or approval.get("action") != execution.action
            or not isinstance(approved_executable, dict)
            or approved_executable.get("enabled_executable_id") != execution.destination_id
            or not isinstance(approved_executable.get("catalog_operation_id"), str)
            or not approved_executable["catalog_operation_id"]
            or decision_hash != execution.approval_sha256
            or receipt.get("receipt_id") != expected_receipt_id
            or not isinstance(receipt.get("context"), dict)
            or receipt["context"].get("seal_origin") != "allowly.execution.outcome.v1"):
        raise ValueError("The receipts do not identify this execution")

    proof_dir = Path(operation_dir) / "witness"
    with (proof_dir / "presentation.json").open("rb") as proof_file:
        presentation = proof_file.read(16 * 1024 * 1024 + 1)
    with (proof_dir / "attestation.json").open("rb") as attestation_file:
        attestation = attestation_file.read(1024 * 1024 + 1)
    if len(presentation) > 16 * 1024 * 1024 or len(attestation) > 1024 * 1024:
        raise ValueError("The local witness files exceed their limits")
    attestation_canonical = json.dumps(
        json.loads(attestation), ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode()
    verification = verify_seal_value(
        record, receipt, public_keys, expected_workspace_id=workspace_id,
    )
    if not verification.signature_verified or not verification.record_matches:
        raise ValueError("The signed after receipt does not match its record")
    if (evidence.record_sha256 != hash_seal_value(record)
            or record.get("type") != "execution.outcome"
            or record.get("operation_id") != execution.operation_id
            or record.get("authorization_id") != execution.request_descriptor.authorization_id
            or record.get("decision_receipt_id") != decision_receipt.get("receipt_id")
            or record.get("approval_sha256") != decision_hash
            or record.get("destination_id") != execution.destination_id
            or record.get("catalog_operation_id") != approved_executable.get("catalog_operation_id")
            or record.get("action") != execution.action
            or record.get("request_fingerprint") != execution.request_fingerprint
            or record.get("evidence_source") != "independent_witness_customer_held_bundle"
            or record.get("target_state") != "response_observed"
            or record.get("transport_status") != "succeeded"
            or not isinstance(record.get("witness"), dict)
            or record["witness"].get("status") != "verified_reference"
            or record["witness"].get("evidence_bundle_sha256") != digest(presentation)
            or record["witness"].get("notary_attestation_sha256") != digest(attestation_canonical)
            or not isinstance(record.get("downstream"), dict)
            or record["downstream"].get("http_status") != response.get("status")
            or record["downstream"].get("response_fingerprint") != response.get("body_sha256")):
        raise ValueError("The signed after record does not bind this execution")


class ApiFailure(RuntimeError):
    def __init__(self, message, *, status_code=None, error_code=None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


class Demo:
    def __init__(self, state, config, credentials, trusted_key, kms_auth, kms_helper, *, sdk_wss=False):
        self.state, self.config, self.credentials = state, config, credentials
        self.trusted_key, self.kms_auth, self.kms_helper = trusted_key, kms_auth, kms_helper
        self.sdk_wss = sdk_wss
        self.csrf_token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.running = False
        self.worker = None
        self.runs = {}
        self.http = build_opener(ProxyHandler({}))

    def api(self, path, body=None, *, internal=False, idempotency_key=None, agent_token=None):
        data = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
        method = "POST" if data is not None else "GET"
        headers = {"Content-Type": "application/json"}
        parsed_path = urlsplit(path)
        if parsed_path.scheme or parsed_path.netloc or not parsed_path.path.startswith("/"):
            raise ApiFailure("Invalid local API path")
        if internal:
            timestamp, nonce = str(int(time.time())), secrets.token_urlsafe(16)
            workspace = self.config["workspace_id"]
            message = "\n".join([method, parsed_path.path, parsed_path.query, workspace, timestamp, nonce,
                                 hashlib.sha256(data or b"").hexdigest()]).encode()
            signature = hmac.new(self.credentials["internal_token"].encode(), message,
                                 hashlib.sha256).hexdigest()
            headers.update({"X-Allowly-Internal-Timestamp": timestamp,
                            "X-Allowly-Internal-Nonce": nonce,
                            "X-Allowly-Internal-Workspace": workspace,
                            "X-Allowly-Internal-Signature": signature})
        else:
            headers["Authorization"] = "Bearer " + self.credentials["api_key"]
            if self.config.get("existing_workspace") and parsed_path.path.startswith(
                ("/v1/execute", "/v1/executions/")
            ):
                if not agent_token:
                    raise ApiFailure("A fresh Auth0 machine token is required")
                headers["X-Allowly-Agent-Token"] = agent_token
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        request = Request(self.config["api_base_url"] + path, data=data, headers=headers,
                          method=method)
        try:
            with self.http.open(request, timeout=30) as response:
                payload = response.read(2 * 1024 * 1024 + 1)
        except HTTPError as exc:
            # Do not copy full response bodies, tokens or traceback into the page.
            code = "request_failed"
            try:
                error = json.loads(exc.read(8192))
                detail = error.get("error", error.get("detail", error))
                if isinstance(detail, dict):
                    code = str(detail.get("code", code))[:128]
            except (ValueError, AttributeError):
                pass
            raise ApiFailure(f"Local Allowly returned HTTP {exc.code}: {code}",
                             status_code=exc.code, error_code=code) from None
        except (URLError, TimeoutError, OSError):
            raise ApiFailure("Local Allowly is unavailable. No automatic resend was made.") from None
        if len(payload) > 2 * 1024 * 1024:
            raise ApiFailure("Local Allowly response exceeded the demo limit")
        return json.loads(payload)

    def status(self):
        try:
            self.api("/healthz")
            signer = "local test signer" if self.config["local_test_signer"] else "Cloud KMS"
            ready, detail = True, f"Local API connected. {signer} access is checked when witnessing starts."
        except (ApiFailure, ValueError):
            ready, detail = False, "Local Allowly API is unavailable; execution will fail closed."
        return {"csrf_token": self.csrf_token, "ready": ready, "detail": detail,
                "api_base_url": self.config["api_base_url"], "target_url": TARGET_URL,
                "action": self.config.get("policy_action", "github.issues.list"),
                "identity_provider": self.config.get("identity_provider", "auth0")
                    if self.config.get("existing_workspace") else None,
                "identity": ("Allowly credential configured; token not checked yet"
                             if self.config.get("identity_provider") == "allowly"
                             else "Auth0 configured; token not checked yet"
                             if self.config.get("existing_workspace")
                             else "Unverified runtime key"),
                "existing_workspace": bool(self.config.get("existing_workspace")),
                "signer_mode": "local_test" if self.config["local_test_signer"] else "cloud_kms",
                "notary_fingerprint": self.config["trusted_notary_key_fingerprint_sha256"]}

    def start(self):
        with self.lock:
            if self.running:
                raise RuntimeError("A witnessed request is already running")
            self.running = True
            run_id = str(uuid.uuid4())
            self.runs[run_id] = {"run_id": run_id, "operation_id": run_id,
                                 "state": "running", "stage": "policy", "events": [],
                                 "witness_verified": False, "receipt_state": "not_requested",
                                 "report_state": "not_started", "timings_ms": {}}
        # Keep the API alive until an in-flight native run has closed its children
        # and recorded its outcome, even when the page server is stopped.
        self.worker = threading.Thread(target=self.run, args=(run_id,))
        self.worker.start()
        return run_id

    def snapshot(self, run_id):
        with self.lock:
            value = self.runs.get(run_id)
            return json.loads(json.dumps(value)) if value else None

    def run(self, run_id):
        if self.sdk_wss:
            return self.run_sdk_wss(run_id)
        from native_runner import run_witnessed_request
        started = time.monotonic()
        directory = self.state / "runs" / run_id
        directory.mkdir(parents=True, mode=0o700)
        outcome = None
        dispatch_started = None
        observed_response = None

        def update(**values):
            with self.lock:
                self.runs[run_id].update(values)
                snapshot = dict(self.runs[run_id])
            save(directory / "run.json", snapshot)

        def event(stage, message):
            with self.lock:
                self.runs[run_id]["stage"] = stage
                self.runs[run_id]["events"].append(
                    {"stage": stage, "message": message,
                     "elapsed_ms": round((time.monotonic() - started) * 1000)})

        try:
            agent_token = None
            if self.config.get("existing_workspace"):
                event("policy", "Checking this workspace's authorization, Auth0 binding and witness key")
                verify_runtime_state(self.api, self.config, json.loads(self.trusted_key.read_text()))
                agent_token = fetch_auth0_token(self.config)
            event("policy", "Requesting approval from the real local Allowly evaluator")
            request = {"method": "GET", "origin": "https://api.github.com", "path": TARGET_PATH,
                       "query": TARGET_QUERY, "body_size": 0, "body_sha256": digest(b""),
                       "content_type": None, "headers": [
                           {"name": name, "value_sha256": digest(
                               b"allowly.execution.header.v1\0" + name.encode() + b"\0" + value.encode())}
                           for name, value in sorted(HEADERS.items())]}
            body = {"operation_id": run_id,
                    "authorization_id": self.config["authorization_id"],
                    "enabled_executable_id": self.config["enabled_executable_id"],
                    "catalog_operation_id": "github.issues.list", "action": "github.issues.list",
                    "evidence_mode": "witnessed", "http_request": request,
                    "policy_input": {"resource": self.config["policy_resource"], "context": {}},
                    "client_timestamp": now()}
            save(directory / "prepare-request.json", body)
            approval = self.api("/v1/execute", body, idempotency_key="prepare-" + run_id,
                                agent_token=agent_token)
            descriptor = approval.get("request_descriptor") if isinstance(approval, dict) else None
            decision_receipt = approval.get("decision_receipt") if isinstance(approval, dict) else None
            if (not isinstance(approval, dict) or approval.get("operation_id") != run_id
                    or approval.get("effective_evidence_mode") != "witnessed"
                    or not isinstance(descriptor, dict)
                    or descriptor.get("authorization_id") != self.config["authorization_id"]
                    or not isinstance(decision_receipt, dict)
                    or not isinstance(decision_receipt.get("receipt_id"), str)
                    or approval.get("decision") not in {"allow", "deny", "confirm", "escalate"}):
                raise RuntimeError("Local Allowly did not return a matching witnessed decision")
            save(directory / "approval-response.json", approval)
            update(policy_decision=approval.get("decision"), receipt_state="pending",
                   approval_sha256=approval.get("approval_sha256"),
                   **({"identity_verification": "accepted_by_runtime"}
                      if self.config.get("existing_workspace") else {}),
                   timings_ms={"policy": round((time.monotonic() - started) * 1000)})
            if approval.get("decision") != "allow":
                update(state="complete", stage="not_allowed", report_state="not_started",
                       detail="Policy did not allow this request. GitHub was not called.")
                return

            def claim_witness():
                event("witness", "Claiming the one-use witness session with local Allowly")
                token = self.api(f"/v1/executions/{run_id}/witness-session-token",
                                 {"approval_sha256": approval["approval_sha256"]},
                                 agent_token=agent_token)
                claim = self.api(f"/internal/execution-witness/sessions/{token['session_id']}/claim",
                                 {"admission_token": token["admission_token"],
                                  "bridge_instance_id": "localhost-html-demo",
                                  "native_profile": token["native_profile"]}, internal=True)
                event("witness", "Starting the native witness and TLS protocol; target send is still gated")
                return claim

            def claim_dispatch():
                nonlocal dispatch_started
                event("dispatch", "Witness ready. Asking local Allowly for the one-use send permission")
                # Durable marker precedes the dispatch call, including ambiguous network failures.
                dispatch_started = now()
                save(directory / "dispatch-attempt.json", {"started_at": dispatch_started})
                claim = self.api(f"/v1/executions/{run_id}/dispatch",
                                 {"approval_sha256": approval["approval_sha256"]},
                                 agent_token=agent_token)
                save(directory / "dispatch-response.json", claim)
                event("target", "Dispatch approved. Sending the GitHub request through witnessed HTTPS")
                return claim

            witness_start = time.monotonic()
            result = run_witnessed_request(
                approval, {"headers": HEADERS, "body": ""}, self.trusted_key,
                directory / "native", claim_witness, claim_dispatch,
                witness_key_ref=self.config["witness_kms_key_ref"],
                kms_auth=self.kms_auth, kms_helper_path=self.kms_helper,
                local_test_signer=self.config["local_test_signer"])
            save(directory / "native-result.json", result)
            observed_response = result.get("response")
            update(timings_ms={**self.snapshot(run_id)["timings_ms"],
                               "witness": round((time.monotonic() - witness_start) * 1000)})
            if not result.get("verified"):
                error = result.get("error", {})
                raise RuntimeError(f"TLS witnessing failed during {error.get('phase', 'verification')} "
                                   f"({error.get('category', 'unknown')})")
            response = result["response"]
            update(witness_verified=True, http_status=response["status"],
                   response_body=response["body"], response_sha256=prefixed(response["body_sha256"]))
            outcome = {"approval_sha256": approval["approval_sha256"],
                       "target_state": "response_observed", "dispatch_started_at": dispatch_started,
                       "completed_at": now(), "http_status": response["status"],
                       "response_sha256": prefixed(response["body_sha256"]),
                       "response_size": response["body_bytes"],
                       "evidence_bundle_sha256": prefixed(result["evidence_bundle_sha256"]),
                       "notary_attestation": result["notary_attestation"]}
            save(directory / "outcome-request.json", outcome)
            event("report", "Uploading the compact attestation and fingerprints to local Allowly")
            report = self.api(f"/v1/executions/{run_id}/outcome", outcome,
                              idempotency_key="outcome-" + run_id, agent_token=agent_token)
            save(directory / "outcome-response.json", report)
            if report.get("evidence_state") != "customer_held_witness_bundle":
                raise RuntimeError("Local Allowly did not accept the witness attestation")
            detail = ("TLS proof verified and reported locally. Allowly receipt signing "
                      "has not been checked by this page." if self.config.get("existing_workspace")
                      else "TLS proof verified and reported locally. Allowly receipt signing "
                      "is not configured in this isolated demo.")
            update(state="complete", stage="complete", report_state="accepted",
                   receipt_state="unverified" if self.config.get("existing_workspace") else "pending",
                   detail=detail,
                   evidence_url=f"/api/run/{run_id}/evidence")
            event("complete", "Proof verified and outcome accepted by local Allowly")
        except Exception as exc:  # noqa: BLE001 - retain any execution failure for reconciliation
            # After a send claim, report uncertainty rather than retrying the target.
            if dispatch_started and outcome is None:
                try:
                    uncertain = {"approval_sha256": approval["approval_sha256"],
                                 "target_state": "unknown", "dispatch_started_at": dispatch_started,
                                 "completed_at": now()}
                    if observed_response:
                        uncertain.update(target_state="response_observed",
                                         http_status=observed_response["status"],
                                         response_sha256=prefixed(observed_response["body_sha256"]),
                                         response_size=observed_response["body_bytes"])
                        update(http_status=observed_response["status"],
                               response_body=observed_response["body"],
                               detail="Response observed, but TLS proof verification failed.")
                    save(directory / "outcome-request.json", uncertain)
                    report = self.api(f"/v1/executions/{run_id}/outcome", uncertain,
                                      idempotency_key="outcome-" + run_id,
                                      agent_token=agent_token)
                    save(directory / "outcome-response.json", report)
                    update(report_state="uncertainty_reported")
                except Exception:  # noqa: BLE001 - reporting must not erase the original failure
                    update(report_state="pending_reconciliation")
            elif outcome is not None:
                update(report_state="pending_reconciliation")
            message = str(exc)[:400] if isinstance(exc, (ApiFailure, RuntimeError)) else type(exc).__name__
            update(state="failed", stage="failed", error=message,
                   detail="No target retry was made. Private evidence and report state remain on disk.")
            event("failed", message)
        finally:
            update(timings_ms={**self.snapshot(run_id)["timings_ms"],
                               "total": round((time.monotonic() - started) * 1000)})
            with self.lock:
                self.running = False

    def run_sdk_wss(self, run_id):
        """Drive the real local WSS bridge with the installed Python SDK."""
        started = time.monotonic()
        directory = self.state / "runs" / run_id
        directory.mkdir(parents=True, mode=0o700)

        def update(**values):
            with self.lock:
                self.runs[run_id].update(values)
                snapshot = dict(self.runs[run_id])
            save(directory / "run.json", snapshot)

        def event(stage, message):
            with self.lock:
                self.runs[run_id]["stage"] = stage
                self.runs[run_id]["events"].append({
                    "stage": stage, "message": message,
                    "elapsed_ms": round((time.monotonic() - started) * 1000),
                })

        try:
            event("policy", "Checking this workspace's authorization, agent identity and witness key")
            verify_runtime_state(self.api, self.config, json.loads(self.trusted_key.read_text()))
            sdk_root = WORKSPACE / "allowly-sdk-python"
            if str(sdk_root) not in sys.path:
                sys.path.insert(0, str(sdk_root))
            from allowly import Allowly
            native_identity = self.config.get("identity_provider") == "allowly"
            credential = load_native_credential(self.config) if native_identity else None
            agent_token = None if native_identity else fetch_auth0_token(self.config)
            identity_options = {"agent_token_supplier": credential.token} if credential else {}

            async def execute():
                async with Allowly(
                    self.credentials["api_key"], base_url=self.config["api_base_url"],
                    dangerously_allow_insecure_base_url=self.config["api_base_url"].startswith("http://127.0.0.1:"),
                    **identity_options,
                ) as client:
                    return await client.execute_http(
                        TARGET_URL, operation_id=run_id,
                        authorization_id=self.config["authorization_id"],
                        enabled_executable_id=self.config["enabled_executable_id"],
                        catalog_operation_id="github.issues.list",
                        action=self.config.get("policy_action", "github.issues.list"),
                        method="GET", headers=HEADERS, body="", evidence_mode="witnessed",
                        policy_input={"resource": self.config["policy_resource"], "context": {}},
                        storage_dir=str(directory / "sdk"), agent_token=agent_token,
                        timeout=150,
                    )

            event("witness", "The SDK is requesting permission and opening the trusted witness socket")
            result = asyncio.run(execute())
            save(directory / "sdk-result.json", {
                "execution": asdict(result.execution),
                "operation_dir": result.operation_dir,
                "response": result.response,
                "outcome_pending": result.outcome_pending,
            })
            update(policy_decision=result.execution.decision,
                   approval_sha256=result.execution.approval_sha256,
                   identity_provider=self.config.get("identity_provider", "auth0"),
                   identity_verification="accepted_by_runtime")
            if result.execution.decision != "allow":
                update(state="complete", stage="not_allowed", report_state="not_started",
                       detail="Policy did not allow this request. GitHub was not called.")
                return
            if result.outcome_pending:
                update(state="failed", stage="report", report_state="pending_reconciliation",
                       detail="The local outcome is saved for reconciliation. GitHub was not retried.")
                return
            if (result.response is None or result.execution.evidence_state != "customer_held_witness_bundle"):
                update(state="failed", stage="witness", report_state="uncertainty_reported",
                       detail="No verified witness result was accepted. GitHub was not retried.")
                return
            response = result.response
            update(receipt_state="pending")
            event("receipts", "Checking the signed decision and after-outcome receipts")
            receipt_verified = False
            try:
                from allowly.execution import complete_execution_evidence
                from allowly.verify import load_keys_from_json

                keys_doc = self.api(f"/v1/workspaces/{self.config['workspace_id']}/keys")
                public_keys = load_keys_from_json(keys_doc)
                if not public_keys:
                    raise ValueError("The workspace has no receipt verification keys")

                async def check_receipts():
                    async with Allowly(
                        self.credentials["api_key"], base_url=self.config["api_base_url"],
                        dangerously_allow_insecure_base_url=True,
                    ) as client:
                        evidence = result.execution.outcome_evidence
                        if evidence is None or evidence.receipt is None:
                            raise ValueError("The after receipt was not issued")

                        async def signed_outcome():
                            envelope = evidence.receipt
                            if envelope.status == "signed":
                                return envelope.receipt
                            return await client.receipts.fetch_signed(envelope.receipt_id)

                        decision_package, outcome_receipt = await asyncio.gather(
                            complete_execution_evidence(
                                client, result.operation_dir, public_keys=public_keys,
                                expected_workspace_id=self.config["workspace_id"],
                            ),
                            signed_outcome(),
                        )
                        envelope = result.execution.outcome_evidence.receipt
                        expected_outcome_id = (envelope.receipt_id if envelope.status == "pending"
                                               else envelope.receipt.get("receipt_id"))
                        verify_outcome_receipt(
                            result.execution, outcome_receipt, public_keys,
                            workspace_id=self.config["workspace_id"],
                            decision_package=decision_package,
                            expected_receipt_id=expected_outcome_id,
                            response=response, operation_dir=result.operation_dir,
                        )
                        return decision_package, outcome_receipt

                decision_package, outcome_receipt = asyncio.run(check_receipts())
                save(directory / "receipt-keys.json", keys_doc)
                save(directory / "decision-receipt.json", decision_package["decision_receipt"])
                save(directory / "outcome-receipt.json", outcome_receipt)
                receipt_verified = True
            except Exception as exc:  # noqa: BLE001 - the provider call is already complete
                event("receipts", f"Receipt verification incomplete: {type(exc).__name__}")
            update(state="complete", stage="complete", witness_verified=True,
                   report_state="accepted", receipt_state="verified" if receipt_verified else "unverified",
                   http_status=response["status"], response_body=response["body"],
                   response_sha256=response["body_sha256"],
                   detail=("The live witness proof and both linked Allowly receipts were verified."
                           if receipt_verified else
                           "The live witness proof was accepted, but its Allowly receipts remain unverified."),
                   evidence_url=f"/api/run/{run_id}/evidence")
            event("complete", "Witnessed GitHub response and Allowly outcome accepted")
        except Exception as exc:  # noqa: BLE001 - keep the operation state for recovery, never resend
            update(state="failed", stage="failed", report_state="pending_reconciliation",
                   error=type(exc).__name__,
                   detail="The witnessed action failed. Check the private local journal; no automatic retry was made.")
            event("failed", type(exc).__name__)
        finally:
            update(timings_ms={"total": round((time.monotonic() - started) * 1000)})
            with self.lock:
                self.running = False



def serve(demo, args, state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def send(self, status, value, content_type="application/json"):
            body = value if isinstance(value, bytes) else json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def valid_host(self):
            return self.headers.get("Host") == f"127.0.0.1:{args.port}"

        def do_GET(self):
            if not self.valid_host():
                return self.send(403, {"error": "Use the printed loopback URL"})
            if self.path == "/":
                return self.send(200, (ROOT / "demo/index.html").read_bytes(), "text/html; charset=utf-8")
            if self.path == "/api/status":
                return self.send(200, demo.status())
            if self.path.startswith("/api/run/"):
                tail = self.path.removeprefix("/api/run/")
                run_id = tail.split("/")[0]
                run = demo.snapshot(run_id)
                if run and tail == run_id:
                    return self.send(200, run)
                if run and tail == run_id + "/evidence" and run.get("witness_verified"):
                    # A small index only; raw proof stays on the customer's disk.
                    note = ("Signed decision and after-outcome receipts were verified and saved locally."
                            if run.get("receipt_state") == "verified" else
                            "Full evidence remains local. Allowly receipt signatures have not been verified by this page.")
                    return self.send(200, {"run": run, "local_directory": str(state / "runs" / run_id),
                                           "note": note})
            return self.send(404, {"error": "Not found"})

        def do_POST(self):
            origin = f"http://127.0.0.1:{args.port}"
            if (not self.valid_host() or self.headers.get("Origin") not in (None, origin)
                    or not hmac.compare_digest(self.headers.get("X-Demo-Token", ""), demo.csrf_token)):
                return self.send(403, {"error": "Invalid local demo request"})
            if self.path != "/api/run":
                return self.send(404, {"error": "Not found"})
            if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length") != "2":
                return self.send(400, {"error": "Send an empty JSON object"})
            if self.rfile.read(2) != b"{}":
                return self.send(400, {"error": "The demo accepts only its fixed GitHub request"})
            try:
                return self.send(202, {"run_id": demo.start()})
            except RuntimeError as exc:
                return self.send(409, {"error": str(exc)})

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Allowly GitHub demo: http://127.0.0.1:{args.port}", flush=True)
    print(f"Local Allowly API: {demo.config['api_base_url']}; private state: {state}", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def main_existing(args):
    if args.kms_key_version or args.trusted_key:
        raise SystemExit("--existing-config supplies the witness key settings")
    try:
        config, credentials, trusted_key = load_config(args.existing_config)
    except ExistingWorkspaceError as exc:
        raise SystemExit(str(exc)) from None
    if args.local_test_signer != config["local_test_signer"]:
        raise SystemExit("Explicit --local-test-signer must match the private config")
    if config.get("identity_provider") == "allowly" and not args.sdk_wss:
        raise SystemExit("Allowly native identity requires --sdk-wss so each request gets a fresh agent token")
    if not config["local_test_signer"] and config["witness_kms_key_version"].startswith(
        "projects/test-only/"
    ):
        raise SystemExit("A test-only witness key cannot be used in Cloud KMS mode")
    os.umask(0o077)
    state = (args.state_dir or ROOT / "artifacts/github-html-existing-workspace").expanduser().resolve()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state, 0o700)
    pin_path = state / "workspace-binding.json"
    pin = {"workspace_id": config["workspace_id"],
           "api_base_url": config["api_base_url"],
           "witness_kms_key_version": config["witness_kms_key_version"],
           "notary_fingerprint_sha256": config["trusted_notary_key_fingerprint_sha256"],
           "local_test_signer": config["local_test_signer"]}
    if pin_path.exists() and json.loads(pin_path.read_text()) != pin:
        raise SystemExit("Existing demo state belongs to a different workspace or witness key")
    save(pin_path, pin)
    trusted_copy = state / "trusted-notary-key.json"
    if trusted_copy.exists() and json.loads(trusted_copy.read_text()) != trusted_key:
        raise SystemExit("Existing demo state has a different trusted witness key")
    save(trusted_copy, trusted_key)
    kms_helper = ROOT / "kms" / (
        "fake_helper_for_rust_tests.py" if config["local_test_signer"] else "gcp_signer.py"
    )
    demo = Demo(state, config, credentials, trusted_copy, args.kms_auth, kms_helper, sdk_wss=args.sdk_wss)
    if not demo.status()["ready"]:
        raise SystemExit("The existing local runtime API is unavailable")
    if args.preflight:
        try:
            verify_runtime_state(demo.api, config, trusted_key)
            if config.get("identity_provider") != "allowly":
                fetch_auth0_token(config)
            if args.sdk_wss:
                sdk_root = WORKSPACE / "allowly-sdk-python"
                if str(sdk_root) not in sys.path:
                    sys.path.insert(0, str(sdk_root))
                from allowly.execution import _witness_files
                _native, _public_key, fingerprint, ca = _witness_files(config["workspace_id"], None, None)
                if fingerprint != config["trusted_notary_key_fingerprint_sha256"] or ca is None:
                    raise ExistingWorkspaceError("Installed SDK witness key or local bridge CA is missing")
        except (ApiFailure, ExistingWorkspaceError, ValueError) as exc:
            raise SystemExit(str(exc)) from None
        print("Existing workspace, agent identity and witness key checked. No GitHub request was sent.")
        return
    try:
        serve(demo, args, state)
    except KeyboardInterrupt:
        pass
    finally:
        if demo.worker and demo.worker.is_alive():
            print("Waiting for the in-flight request to finish and record its outcome...", flush=True)
            demo.worker.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--port", type=int, default=8810)
    parser.add_argument("--api-port", type=int, default=8811)
    parser.add_argument("--kms-auth", choices=("gcloud", "adc"), default="gcloud")
    parser.add_argument("--kms-key-version", help="dedicated key version for ws_local_witness_demo")
    parser.add_argument("--trusted-key", type=Path, help="independently obtained public key JSON for the KMS version")
    parser.add_argument("--local-test-signer", action="store_true", help="use the repository's public test scalar without Cloud KMS")
    parser.add_argument("--existing-config", type=Path,
                        help="owner-only JSON for a configured local Allowly workspace")
    parser.add_argument("--preflight", action="store_true",
                        help="check existing workspace and agent identity without contacting GitHub")
    parser.add_argument("--sdk-wss", action="store_true",
                        help="run the existing workspace through the Python SDK and local WSS bridge")
    args = parser.parse_args()
    if args.preflight and not args.existing_config:
        parser.error("--preflight requires --existing-config")
    if args.sdk_wss and not args.existing_config:
        parser.error("--sdk-wss requires --existing-config")
    if args.existing_config:
        return main_existing(args)
    if args.local_test_signer:
        if args.kms_key_version or args.trusted_key:
            parser.error("--local-test-signer cannot be combined with KMS key options")
        key_version = TEST_KEY_VERSION
        kms_helper = ROOT / "kms/fake_helper_for_rust_tests.py"
    else:
        if not args.kms_key_version or not args.trusted_key:
            parser.error("real KMS mode requires --kms-key-version and --trusted-key")
        key_version = args.kms_key_version
        kms_helper = ROOT / "kms/gcp_signer.py"
    try:
        key_ref, *_ = workspace_key(key_version)
    except ValueError as exc:
        parser.error(str(exc))
    os.umask(0o077)
    default_state = ROOT / "artifacts" / ("github-html-demo-test" if args.local_test_signer else "github-html-demo")
    state = (args.state_dir or default_state).expanduser().resolve()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(state, 0o700)
    trusted_key = state / "trusted-notary-key.json"
    if args.local_test_signer:
        output = subprocess.run(
            [str(ROOT / ".venv/bin/python"), str(kms_helper), "public", "--key-version", key_version],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        key = {"alg": 2, "data": list(bytes.fromhex(json.loads(output.stdout)["sec1_hex"]))}
    else:
        key = json.loads(args.trusted_key.expanduser().resolve(strict=True).read_text())
    fingerprint = _fingerprint(key)
    check_existing_state(state, key_ref, fingerprint, args.local_test_signer)
    save(trusted_key, key)
    api_python = WORKSPACE / "allowly-api" / ".venv" / "bin" / "python"
    api_log = (state / "local-api.log").open("ab")
    command = [str(api_python), str(ROOT / "demo" / "local_api.py"),
               "--state-dir", str(state / "api"), "--port", str(args.api_port),
               "--witness-url", f"wss://127.0.0.1:{args.port}",
               "--notary-public-key", str(trusted_key), "--notary-fingerprint", fingerprint,
               "--witness-key-version", key_version,
               "--verifier-bin", str(ROOT / "target/release/allowly-witness-poc")]
    if args.local_test_signer:
        command.append("--local-test-signer")
    api_env = os.environ.copy()
    if args.local_test_signer:
        for name in ("GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CONFIG", "ALLOWLY_KMS_AUTH"):
            api_env.pop(name, None)
    api_process = subprocess.Popen(command, stdout=api_log, stderr=api_log, env=api_env)
    demo = None
    try:
        deadline = time.monotonic() + 40
        config_file, secrets_file = state / "api/runtime-config.json", state / "api/runtime-secrets.json"
        while not (config_file.exists() and secrets_file.exists()):
            if api_process.poll() is not None or time.monotonic() >= deadline:
                raise SystemExit(f"Local API bootstrap failed; inspect {state / 'local-api.log'}")
            time.sleep(0.1)
        demo = Demo(state, json.loads(config_file.read_text()), json.loads(secrets_file.read_text()),
                    trusted_key, args.kms_auth, kms_helper)
        while not demo.status()["ready"]:
            if api_process.poll() is not None or time.monotonic() >= deadline:
                raise SystemExit(f"Local API unavailable; inspect {state / 'local-api.log'}")
            time.sleep(0.1)

        serve(demo, args, state)
    except KeyboardInterrupt:
        pass
    finally:
        if demo and demo.worker and demo.worker.is_alive():
            print("Waiting for the in-flight request to finish and record its outcome...", flush=True)
            demo.worker.join()
        api_process.terminate()
        try:
            api_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            api_process.kill()
            api_process.wait()
        api_log.close()


if __name__ == "__main__":
    main()
