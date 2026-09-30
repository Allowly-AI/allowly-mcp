#!/usr/bin/env python3
"""Focused tests for the authenticated remote witness bridge."""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import datetime as dt
import hashlib
import hmac
import http.client
import http.server
import json
import os
import pathlib
import stat
import sys
import tempfile
import threading
import time
import unittest

from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import execute_service as bridge  # noqa: E402


INTERNAL_TOKEN = "test-internal-token-that-is-long-enough"
SESSION_ID = "wit_fixture_session_123"
WORKSPACE_ID = "workspace-fixture-1"
ADMISSION_TOKEN = "A" * 43
FINGERPRINT = "b" * 64
KMS_KEY_VERSION = (
    "projects/test/locations/global/keyRings/test/cryptoKeys/workspace-fixture-1-tlsnotary/"
    "cryptoKeyVersions/1"
)


def _timestamp(delta: dt.timedelta = dt.timedelta()) -> str:
    return (dt.datetime.now(dt.timezone.utc) + delta).isoformat().replace("+00:00", "Z")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _header_digest(name: str, value: str) -> str:
    return _digest(
        b"allowly.execution.header.v1\0"
        + name.encode()
        + b"\0"
        + value.encode()
    )


def claim_response(
    *,
    fingerprint: str = FINGERPRINT,
    kms_key_version: str = KMS_KEY_VERSION,
    workspace_id: str = WORKSPACE_ID,
) -> dict:
    expires = _timestamp(dt.timedelta(minutes=5))
    approval = {
        "profile": "allowly.execution.approval.v1",
        "evidence_mode": "witnessed",
        "operation_id": "customer operation ! 42",
        "issued_at": _timestamp(dt.timedelta(seconds=-1)),
        "expires_at": expires,
        "request": {
            "origin": "https://example.com",
            "method": "POST",
            "path": "/formats/json",
            "query": "",
            "headers": [],
            "body_sha256": "sha256:" + "0" * 64,
            "body_size": 0,
            "content_type": None,
        },
    }
    return {
        "session_id": SESSION_ID,
        "operation_id": "customer operation ! 42",
        "workspace_id": workspace_id,
        "approval_sha256": "sha256:" + "a" * 64,
        "approval": approval,
        "expires_at": expires,
        "expected_server_name": "example.com",
        "notary_kms_key_version": kms_key_version,
        "trusted_notary_key_fingerprint_sha256": fingerprint,
        "native_profile": bridge.NATIVE_PROFILE,
        "request_binding_verification": bridge.REQUEST_BINDING_VERIFICATION,
    }


class RuntimeStub:
    def __init__(self, response: dict | None = None, *, status: int = 200):
        self.response = response or claim_response()
        self.status = status
        self.requests: list[dict] = []
        self.hmac_valid = False
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                timestamp = self.headers.get("X-Allowly-Internal-Timestamp", "")
                nonce = self.headers.get("X-Allowly-Internal-Nonce", "")
                workspace = self.headers.get("X-Allowly-Internal-Workspace", "")
                signature = self.headers.get("X-Allowly-Internal-Signature", "")
                canonical = "\n".join(
                    [
                        "POST",
                        self.path,
                        "",
                        workspace,
                        timestamp,
                        nonce,
                        hashlib.sha256(body).hexdigest(),
                    ]
                ).encode()
                expected = hmac.new(INTERNAL_TOKEN.encode(), canonical, hashlib.sha256).hexdigest()
                owner.hmac_valid = (
                    hmac.compare_digest(expected, signature)
                    and workspace == owner.response["workspace_id"]
                    and len(nonce) == 22
                    and timestamp.isdigit()
                    and abs(int(timestamp) - int(time.time())) <= 5
                )
                parsed = json.loads(body)
                owner.requests.append(
                    {"path": self.path, "body": parsed, "raw_body": body}
                )
                encoded = json.dumps(owner.response, separators=(",", ":")).encode()
                self.send_response(owner.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError):
                    self.wfile.write(encoded)

            def log_message(self, format, *args):  # noqa: A002
                return

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


FAKE_NATIVE = r'''#!/usr/bin/env python3
import json
import os
import pathlib
import socket
import stat
import sys

if "ALLOWLY_INTERNAL_TOKEN" in os.environ:
    raise SystemExit(51)
if len(sys.argv) < 2 or sys.argv[1] != "witness":
    raise SystemExit(52)

def arg(name):
    index = sys.argv.index(name)
    return pathlib.Path(sys.argv[index + 1])

approval_path = arg("--execution-approval")
public_key_path = arg("--public-key")
ready_path = arg("--ready-file")
if stat.S_IMODE(approval_path.parent.stat().st_mode) != 0o700:
    raise SystemExit(53)
if stat.S_IMODE(approval_path.stat().st_mode) != 0o600:
    raise SystemExit(54)
approval = json.loads(approval_path.read_text())
if set(approval) != {"approval_sha256", "approval"}:
    raise SystemExit(55)

marker = pathlib.Path(os.environ["ALLOWLY_FAKE_NATIVE_MARKER"])
marker.write_text(json.dumps({"temporary_directory": str(approval_path.parent), "argv": sys.argv[1:]}))

def write_new(path, contents):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(contents)
        output.flush()
        os.fsync(output.fileno())

listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(1)
write_new(public_key_path, b'{"alg":2,"data":[1]}')
fingerprint = os.environ.get("ALLOWLY_FAKE_NATIVE_FINGERPRINT", "b" * 64)
write_new(ready_path, json.dumps({"listen": "127.0.0.1:%d" % listener.getsockname()[1], "signer_fingerprint_sha256": fingerprint}, separators=(",", ":")).encode())
listener.settimeout(10)
connection, _ = listener.accept()
connection.settimeout(10)
data = connection.recv(1024 * 1024)
if data:
    connection.sendall(b"native:" + data)
connection.shutdown(socket.SHUT_WR)
connection.close()
listener.close()
'''


class BridgeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="allowly-bridge-test-")
        self.temp = pathlib.Path(self.temporary.name)
        self.fake_native = self.temp / "fake-native.py"
        self.fake_native.write_text(FAKE_NATIVE)
        self.fake_native.chmod(0o700)
        self.marker = self.temp / "native-started.json"
        self.previous_env = {
            key: os.environ.get(key)
            for key in (
                "ALLOWLY_INTERNAL_TOKEN",
                "ALLOWLY_FAKE_NATIVE_MARKER",
                "ALLOWLY_FAKE_NATIVE_FINGERPRINT",
            )
        }
        os.environ["ALLOWLY_INTERNAL_TOKEN"] = "must-not-enter-child"
        os.environ["ALLOWLY_FAKE_NATIVE_MARKER"] = str(self.marker)
        os.environ["ALLOWLY_FAKE_NATIVE_FINGERPRINT"] = FINGERPRINT
        self.services: list[bridge.WitnessBridgeService] = []
        self.stubs: list[RuntimeStub] = []

    async def asyncTearDown(self) -> None:
        for service in self.services:
            await service.begin_drain(timeout=0.5)
        for stub in self.stubs:
            await asyncio.to_thread(stub.stop)
        for key, value in self.previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.temporary.cleanup()

    async def start_service(
        self,
        *,
        response: dict | None = None,
        status: int = 200,
        max_concurrent: int = 4,
    ) -> tuple[bridge.WitnessBridgeService, RuntimeStub]:
        stub = RuntimeStub(response, status=status)
        stub.start()
        self.stubs.append(stub)
        config = bridge.BridgeConfig(
            api_base_url=stub.base_url,
            internal_token=INTERNAL_TOKEN,
            bridge_instance_id="bridge.test:1",
            listen_host="127.0.0.1",
            listen_port=0,
            native_bin=self.fake_native,
            kms_key_version=None,
            witness_kms_key_ring="test",
            kms_python=pathlib.Path(sys.executable),
            kms_helper=ROOT / "kms/gcp_signer.py",
            tls_cert_file=None,
            tls_key_file=None,
            preflight_timeout_seconds=1,
            claim_timeout_seconds=2,
            native_ready_timeout_seconds=2,
            session_timeout_seconds=8,
            drain_timeout_seconds=1,
            max_concurrent_sessions=max_concurrent,
            test_fixture=False,
        )
        service = bridge.WitnessBridgeService(config)
        await service.start()
        self.services.append(service)
        return service, stub

    @staticmethod
    def preflight(**changes) -> str:
        value = {
            "session_id": SESSION_ID,
            "workspace_id": WORKSPACE_ID,
            "admission_token": ADMISSION_TOKEN,
        }
        value.update(changes)
        return json.dumps(value, separators=(",", ":"))

    @staticmethod
    def url(service: bridge.WitnessBridgeService) -> str:
        return f"ws://127.0.0.1:{service.bound_port}/sessions/{SESSION_ID}"

    async def wait_done(self, service: bridge.WitnessBridgeService) -> None:
        await asyncio.wait_for(service._all_done.wait(), timeout=3)

    async def assert_rejected_without_child(
        self,
        *,
        message: str,
        response: dict | None = None,
        status: int = 200,
        expected_claims: int,
    ) -> None:
        if self.marker.exists():
            self.marker.unlink()
        service, stub = await self.start_service(
            response=response,
            status=status,
        )
        async with connect(self.url(service), compression=None) as websocket:
            await websocket.send(message)
            with self.assertRaises(ConnectionClosed):
                await websocket.recv()
        await self.wait_done(service)
        self.assertEqual(len(stub.requests), expected_claims)
        self.assertFalse(self.marker.exists())

    async def test_missing_or_invalid_token_profile_key_and_conflict_start_no_child(self):
        missing = json.dumps(
            {"session_id": SESSION_ID, "workspace_id": WORKSPACE_ID},
            separators=(",", ":"),
        )
        await self.assert_rejected_without_child(
            message=missing, expected_claims=0
        )
        await self.assert_rejected_without_child(
            message=self.preflight(), status=401, expected_claims=1
        )
        wrong_profile = claim_response()
        wrong_profile["native_profile"] = "wrong"
        await self.assert_rejected_without_child(
            message=self.preflight(), response=wrong_profile, expected_claims=1
        )
        wrong_key = claim_response(kms_key_version="invalid/version")
        await self.assert_rejected_without_child(
            message=self.preflight(), response=wrong_key, expected_claims=1
        )
        other_workspace_key = claim_response(
            kms_key_version=(
                "projects/test/locations/global/keyRings/test/"
                "cryptoKeys/workspace-fixture-2-tlsnotary/cryptoKeyVersions/1"
            )
        )
        await self.assert_rejected_without_child(
            message=self.preflight(), response=other_workspace_key, expected_claims=1
        )
        other_ring_key = claim_response(
            kms_key_version=(
                "projects/test/locations/global/keyRings/receipt-ring/"
                "cryptoKeys/workspace-fixture-1-tlsnotary/cryptoKeyVersions/1"
            )
        )
        await self.assert_rejected_without_child(
            message=self.preflight(), response=other_ring_key, expected_claims=1
        )
        missing_key = claim_response()
        del missing_key["notary_kms_key_version"]
        await self.assert_rejected_without_child(
            message=self.preflight(), response=missing_key, expected_claims=1
        )
        await self.assert_rejected_without_child(
            message=self.preflight(notary_kms_key_version=KMS_KEY_VERSION),
            expected_claims=0,
        )
        await self.assert_rejected_without_child(
            message=self.preflight(), status=409, expected_claims=1
        )

    async def test_binary_relay_hmac_private_files_and_cleanup(self):
        service, stub = await self.start_service()
        async with connect(self.url(service), compression=None) as websocket:
            await websocket.send(self.preflight())
            ready = json.loads(await websocket.recv())
            self.assertEqual(ready, {"ready": True})
            marker = json.loads(self.marker.read_text())
            private_dir = pathlib.Path(marker["temporary_directory"])
            self.assertEqual(stat.S_IMODE(private_dir.stat().st_mode), 0o700)
            self.assertIn("--kms-key-version", marker["argv"])
            self.assertEqual(
                marker["argv"][marker["argv"].index("--kms-key-version") + 1],
                KMS_KEY_VERSION,
            )
            await websocket.send(b"\x00\x01private-mpc-bytes")
            self.assertEqual(await websocket.recv(), b"native:\x00\x01private-mpc-bytes")
            with self.assertRaises(ConnectionClosed):
                await websocket.recv()
        await self.wait_done(service)
        self.assertTrue(stub.hmac_valid)
        self.assertEqual(len(stub.requests), 1)
        self.assertEqual(
            stub.requests[0]["path"],
            f"/internal/execution-witness/sessions/{SESSION_ID}/claim",
        )
        self.assertEqual(
            stub.requests[0]["body"],
            {
                "admission_token": ADMISSION_TOKEN,
                "bridge_instance_id": "bridge.test:1",
                "native_profile": bridge.NATIVE_PROFILE,
            },
        )
        self.assertFalse(private_dir.exists())

    async def test_native_ready_key_mismatch_closes_and_cleans_up(self):
        os.environ["ALLOWLY_FAKE_NATIVE_FINGERPRINT"] = "c" * 64
        service, _ = await self.start_service()
        async with connect(self.url(service), compression=None) as websocket:
            await websocket.send(self.preflight())
            with self.assertRaises(ConnectionClosed):
                await websocket.recv()
        await self.wait_done(service)
        marker = json.loads(self.marker.read_text())
        self.assertFalse(pathlib.Path(marker["temporary_directory"]).exists())

    async def test_each_workspace_claim_selects_its_own_kms_key(self):
        other_workspace = "workspace-fixture-2"
        other_key_version = (
            "projects/test/locations/global/keyRings/test/"
            "cryptoKeys/workspace-fixture-2-tlsnotary/cryptoKeyVersions/3"
        )
        for workspace_id, key_version in (
            (WORKSPACE_ID, KMS_KEY_VERSION),
            (other_workspace, other_key_version),
        ):
            with self.subTest(workspace_id=workspace_id):
                service, stub = await self.start_service(
                    response=claim_response(
                        workspace_id=workspace_id,
                        kms_key_version=key_version,
                    )
                )
                async with connect(self.url(service), compression=None) as websocket:
                    await websocket.send(self.preflight(workspace_id=workspace_id))
                    self.assertEqual(json.loads(await websocket.recv()), {"ready": True})
                    marker = json.loads(self.marker.read_text())
                    args = marker["argv"]
                    self.assertEqual(args[args.index("--kms-key-version") + 1], key_version)
                    await websocket.send(b"ok")
                    self.assertEqual(await websocket.recv(), b"native:ok")
                await self.wait_done(service)
                self.assertTrue(stub.hmac_valid)

    @unittest.skipUnless(
        os.environ.get("ALLOWLY_RUN_NATIVE_BRIDGE_FIXTURE") == "1",
        "set ALLOWLY_RUN_NATIVE_BRIDGE_FIXTURE=1 for the real TLS/MPC fixture",
    )
    async def test_real_native_wss_fixture_and_two_phase_dispatch_gate(self):
        """Real native prover + witness through WS; synthetic local fixture only."""
        native = ROOT / "target/release/allowly-witness-poc"
        kms_python = ROOT / ".venv/bin/python"
        kms_helper = ROOT / "kms/fake_helper_for_rust_tests.py"
        for required in (native, kms_python, kms_helper):
            self.assertTrue(required.exists(), f"missing fixture dependency: {required.name}")

        kms_key_version = (
            "projects/test-only/locations/global/keyRings/tests/"
            "cryptoKeys/workspace-fixture-1-tlsnotary/"
            "cryptoKeyVersions/1"
        )
        key_process = await asyncio.create_subprocess_exec(
            str(kms_python),
            str(kms_helper),
            "public",
            "--key-version",
            kms_key_version,
            cwd=ROOT,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        key_output, key_errors = await key_process.communicate()
        self.assertEqual(
            key_process.returncode, 0, key_errors.decode(errors="replace")[:1000]
        )
        sec1 = bytes.fromhex(json.loads(key_output)["sec1_hex"])
        fingerprint = hashlib.sha256(sec1).hexdigest()
        artifacts_root = ROOT / "artifacts"
        artifacts_root.mkdir(exist_ok=True)
        artifact_dir = pathlib.Path(
            tempfile.mkdtemp(prefix="execute-service-integration-", dir=artifacts_root)
        )
        trusted_key = artifact_dir / "trusted-notary-key.json"
        trusted_key.write_text(json.dumps({"alg": 2, "data": list(sec1)}))
        trusted_key.chmod(0o600)

        secret = "Bearer bridge-fixture-only"
        body = '{"bridge":"fixture"}'
        expires = _timestamp(dt.timedelta(minutes=5))
        approval = {
            "profile": "allowly.execution.approval.v1",
            "evidence_mode": "witnessed",
            "operation_id": "bridge-real-native-fixture",
            "issued_at": _timestamp(dt.timedelta(seconds=-1)),
            "expires_at": expires,
            "request": {
                "method": "POST",
                "origin": "https://test-server.io",
                "path": "/formats/json",
                "query": "",
                "body_size": len(body.encode()),
                "body_sha256": _digest(body.encode()),
                "content_type": "application/json",
                "headers": [
                    {
                        "name": "authorization",
                        "value_sha256": _header_digest("authorization", secret),
                    },
                    {
                        "name": "content-type",
                        "value_sha256": _header_digest(
                            "content-type", "application/json"
                        ),
                    },
                ],
            },
        }
        approval_sha = _digest(
            json.dumps(approval, sort_keys=True, separators=(",", ":")).encode()
        )
        response = {
            "session_id": SESSION_ID,
            "operation_id": approval["operation_id"],
            "workspace_id": WORKSPACE_ID,
            "approval_sha256": approval_sha,
            "approval": approval,
            "expires_at": expires,
            "expected_server_name": "test-server.io",
            "notary_kms_key_version": kms_key_version,
            "trusted_notary_key_fingerprint_sha256": fingerprint,
            "native_profile": bridge.NATIVE_PROFILE,
            "request_binding_verification": bridge.REQUEST_BINDING_VERIFICATION,
        }
        stub = RuntimeStub(response)
        stub.start()
        self.stubs.append(stub)
        config = bridge.BridgeConfig(
            api_base_url=stub.base_url,
            internal_token=INTERNAL_TOKEN,
            bridge_instance_id="bridge.real-fixture:1",
            listen_host="127.0.0.1",
            listen_port=0,
            native_bin=native,
            kms_key_version=kms_key_version,
            witness_kms_key_ring="tests",
            kms_python=kms_python,
            kms_helper=kms_helper,
            tls_cert_file=None,
            tls_key_file=None,
            preflight_timeout_seconds=5,
            claim_timeout_seconds=5,
            native_ready_timeout_seconds=30,
            session_timeout_seconds=180,
            drain_timeout_seconds=10,
            max_concurrent_sessions=2,
            test_fixture=True,
            # The deterministic repository fake-KMS helper makes the trust key
            # pre-provisionable, so this real integration keeps equality strict.
            allow_random_test_signer=False,
        )
        service = bridge.WitnessBridgeService(config)
        await service.start()
        self.services.append(service)

        fixture = await asyncio.create_subprocess_exec(
            str(native),
            "fixture",
            cwd=ROOT,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
        prover = None
        try:
            deadline = asyncio.get_running_loop().time() + 10
            while True:
                if fixture.returncode is not None:
                    self.fail("native HTTPS fixture exited before readiness")
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", 3000)
                    writer.close()
                    await writer.wait_closed()
                    del reader
                    break
                except OSError:
                    if asyncio.get_running_loop().time() >= deadline:
                        self.fail("native HTTPS fixture readiness timeout")
                    await asyncio.sleep(0.02)

            evidence = artifact_dir / "evidence"
            payload = {
                "approval_sha256": approval_sha,
                "approval": approval,
                "request": {
                    "headers": {
                        "authorization": secret,
                        "content-type": "application/json",
                    },
                    "body": body,
                },
                "witness": {
                    "url": f"ws://127.0.0.1:{service.bound_port}/sessions/{SESSION_ID}",
                    "session_id": SESSION_ID,
                    "admission_token": ADMISSION_TOKEN,
                    "workspace_id": WORKSPACE_ID,
                },
                "require_dispatch_ack": True,
            }
            prover = await asyncio.create_subprocess_exec(
                str(native),
                "prove-execute",
                "--output",
                str(evidence),
                "--trusted-key",
                str(trusted_key),
                "--fixture",
                cwd=ROOT,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            communication = asyncio.create_task(
                prover.communicate(json.dumps(payload, separators=(",", ":")).encode())
            )
            ready_file = evidence / "witness.ready.json"
            deadline = asyncio.get_running_loop().time() + 90
            while not ready_file.exists():
                if communication.done():
                    stdout, stderr = await communication
                    self.fail(
                        "native prover failed before dispatch gate: "
                        + stderr.decode(errors="replace")[:1000]
                        + stdout.decode(errors="replace")[:1000]
                    )
                if asyncio.get_running_loop().time() >= deadline:
                    prover.kill()
                    await prover.wait()
                    self.fail("native prover did not reach dispatch gate")
                await asyncio.sleep(0.02)
            self.assertFalse((evidence / "dispatch.started.json").exists())
            gate_temp = evidence / "dispatch.approved.tmp"
            gate_temp.write_text(json.dumps({"approval_sha256": approval_sha}))
            gate_temp.chmod(0o600)
            gate_temp.replace(evidence / "dispatch.approved.json")
            stdout, stderr = await asyncio.wait_for(communication, timeout=180)
            self.assertEqual(prover.returncode, 0, stderr.decode(errors="replace")[:2000])
            result = json.loads(stdout)
            self.assertEqual(result["response"]["status"], 405)
            self.assertTrue((evidence / "dispatch.started.json").exists())
            self.assertTrue((evidence / "response.json").exists())

            async def verify(*arguments: str) -> dict:
                process = await asyncio.create_subprocess_exec(
                    str(native),
                    *arguments,
                    cwd=ROOT,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                output, errors = await asyncio.wait_for(process.communicate(), timeout=30)
                self.assertEqual(process.returncode, 0, errors.decode(errors="replace")[:2000])
                return json.loads(output)

            approval_path = artifact_dir / "approval.json"
            approval_path.write_text(
                json.dumps({"approval_sha256": approval_sha, "approval": approval})
            )
            approval_path.chmod(0o600)
            full = await verify(
                "verify-execute",
                "--presentation",
                str(evidence / "presentation.json"),
                "--trusted-key",
                str(trusted_key),
                "--approval",
                str(approval_path),
                "--fixture",
            )
            compact = await verify(
                "verify-execute-attestation",
                "--attestation",
                str(evidence / "attestation.json"),
                "--trusted-key",
                str(trusted_key),
                "--approval",
                str(approval_path),
                "--fixture",
            )
            self.assertTrue(full["verified"])
            self.assertEqual(full["response"]["status"], 405)
            self.assertEqual(
                compact["request_binding_verification"], "customer_held_bundle"
            )
            self.assertNotIn("response", compact)
            self.assertNotIn(secret, (evidence / "attestation.json").read_text())
            self.assertTrue(stub.hmac_valid)
            self.assertEqual(len(stub.requests), 1)
            await self.wait_done(service)
            report = {
                "status": "pass",
                "fixture_only": True,
                "real_tlsnotary": True,
                "bridge_transport": "ws_loopback_fixture",
                "observed_http_status": 405,
                "dispatch_gate_exercised": True,
                "full_presentation_verified": True,
                "compact_attestation_verified": True,
                "runtime_claim_count": len(stub.requests),
            }
            (artifact_dir / "execute-service-report.json").write_text(
                json.dumps(report, indent=2)
            )
            print(f"real bridge fixture artifacts: {artifact_dir}")
        finally:
            if prover is not None and prover.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(prover.pid, 15)
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(prover.wait(), timeout=5)
            if fixture.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(fixture.pid, 15)
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(fixture.wait(), timeout=5)

    async def test_health_and_drain_close_unclaimed_connection(self):
        service, stub = await self.start_service()

        def health() -> tuple[int, bytes]:
            client = http.client.HTTPConnection("127.0.0.1", service.bound_port, timeout=2)
            client.request("GET", "/healthz")
            response = client.getresponse()
            result = response.status, response.read()
            client.close()
            return result

        self.assertEqual(await asyncio.to_thread(health), (200, b"ok\n"))
        websocket = await connect(self.url(service), compression=None)
        drain = asyncio.create_task(service.begin_drain(timeout=1))
        with self.assertRaises(ConnectionClosed):
            await websocket.recv()
        await drain
        self.assertTrue(service.draining)
        self.assertEqual(stub.requests, [])
        self.assertFalse(self.marker.exists())

    async def test_capacity_rejection_happens_before_claim(self):
        service, stub = await self.start_service(max_concurrent=1)
        first = await connect(self.url(service), compression=None)
        second = await connect(self.url(service), compression=None)
        with self.assertRaises(ConnectionClosed):
            await second.recv()
        await first.close()
        await self.wait_done(service)
        self.assertEqual(stub.requests, [])
        self.assertFalse(self.marker.exists())


class ConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="allowly-bridge-config-")
        self.temp = pathlib.Path(self.temporary.name)
        self.binary = self.temp / "native"
        self.binary.write_text("#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o700)
        self.python = pathlib.Path(sys.executable).resolve()
        self.helper = self.temp / "helper.py"
        self.helper.write_text("# fixture\n")
        self.base = {
            "ALLOWLY_API_BASE_URL": "https://api.example.test",
            "ALLOWLY_INTERNAL_TOKEN": INTERNAL_TOKEN,
            "ALLOWLY_WITNESS_BRIDGE_INSTANCE_ID": "bridge-1",
            "ALLOWLY_WITNESS_NATIVE_BIN": str(self.binary),
            "ALLOWLY_WITNESS_KMS_PYTHON": str(self.python),
            "ALLOWLY_WITNESS_KMS_HELPER": str(self.helper),
            "WITNESS_KMS_KEY_RING": "witness-ring",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_production_rejects_http_api_and_public_cleartext_listener(self):
        values = dict(self.base, ALLOWLY_API_BASE_URL="http://127.0.0.1:8000")
        with self.assertRaises(bridge.ConfigurationError):
            bridge.BridgeConfig.from_env(values)
        values = dict(self.base, ALLOWLY_WITNESS_LISTEN_ADDR="0.0.0.0:8765")
        with self.assertRaises(bridge.ConfigurationError):
            bridge.BridgeConfig.from_env(values)

    def test_fixture_is_explicit_and_rejects_production_signer_mix(self):
        values = dict(
            self.base,
            ALLOWLY_API_BASE_URL="http://127.0.0.1:8000",
            ALLOWLY_WITNESS_LISTEN_ADDR="127.0.0.1:0",
        )
        configured = bridge.BridgeConfig.from_env(values, test_fixture=True)
        self.assertTrue(configured.test_fixture)
        self.assertIsNone(configured.kms_key_version)
        values["ALLOWLY_WITNESS_NOTARY_SIGNING_KEY"] = KMS_KEY_VERSION
        with self.assertRaises(bridge.ConfigurationError):
            bridge.BridgeConfig.from_env(values, test_fixture=True)

    def test_production_rejects_global_signer_settings(self):
        configured = bridge.BridgeConfig.from_env(self.base)
        with self.assertRaises(bridge.ConfigurationError):
            dataclasses.replace(configured, kms_key_version=KMS_KEY_VERSION)
        for name, value in (
            ("ALLOWLY_WITNESS_NOTARY_SIGNING_KEY", KMS_KEY_VERSION),
            ("ALLOWLY_WITNESS_NOTARY_KEY_FINGERPRINT_SHA256", FINGERPRINT),
        ):
            with self.subTest(name=name), self.assertRaises(bridge.ConfigurationError):
                bridge.BridgeConfig.from_env(dict(self.base, **{name: value}))

    def test_production_requires_valid_dedicated_ring_name(self):
        configured = bridge.BridgeConfig.from_env(self.base)
        with self.assertRaises(bridge.ConfigurationError):
            dataclasses.replace(configured, witness_kms_key_ring=None)
        for ring in ("", "projects/p/locations/global/keyRings/r", "invalid ring"):
            with self.subTest(ring=ring), self.assertRaises(bridge.ConfigurationError):
                bridge.BridgeConfig.from_env(
                    dict(self.base, WITNESS_KMS_KEY_RING=ring)
                )

    def test_local_api_ca_must_be_a_readable_valid_ca(self):
        missing = self.temp / "missing-ca.pem"
        with self.assertRaises(bridge.ConfigurationError):
            bridge.BridgeConfig.from_env(
                dict(self.base, ALLOWLY_API_CA_CERT_FILE=str(missing))
            )
        invalid = self.temp / "invalid-ca.pem"
        invalid.write_text("not a CA certificate")
        configured = bridge.BridgeConfig.from_env(
            dict(self.base, ALLOWLY_API_CA_CERT_FILE=str(invalid))
        )
        with self.assertRaises(bridge.ConfigurationError):
            bridge.RuntimeClaimClient(configured)


if __name__ == "__main__":
    unittest.main(verbosity=2)
