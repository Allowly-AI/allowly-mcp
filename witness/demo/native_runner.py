"""Local demo supervisor for a real, public-root TLSNotary execution.

The caller owns the real Allowly API calls and receipt verification. The two
callbacks must have bounded HTTP timeouts and must never retry: claim_witness
returns the authenticated internal witness-session claim response; claim_dispatch
returns the customer dispatch claim response. Neither callback is a mock hook in
the running demo. Provider plaintext stays in this private local run directory.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import signal
import stat
import subprocess
import time
from collections.abc import Callable
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "customer_held_tlsn_bundle_v1"


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


def _write_private(path: Path, data: bytes) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _read_json(path: Path, maximum: int = 256 * 1024) -> Any:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("invalid artifact")
        return json.loads(stream.read(maximum + 1))


def _fingerprint(key: Any) -> str:
    if (not isinstance(key, dict) or type(key.get("alg")) is not int
            or key["alg"] != 2 or not isinstance(key.get("data"), list)):
        raise ValueError("invalid public trust key")
    if any(type(value) is not int or not 0 <= value <= 255 for value in key["data"]):
        raise ValueError("invalid public trust key")
    encoded = bytes(key["data"])
    if len(encoded) == 65 and encoded[0] == 4:
        encoded = bytes([2 | (encoded[-1] & 1)]) + encoded[1:33]
    if len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ValueError("invalid public trust key")
    return hashlib.sha256(encoded).hexdigest()


def _claimed_key_version(claim: dict[str, Any], witness_key_ref: str) -> str:
    version = claim.get("notary_kms_key_version")
    if (not isinstance(version, str)
            or not re.fullmatch(re.escape(witness_key_ref) + r"/cryptoKeyVersions/[1-9][0-9]*", version)):
        raise ValueError("witness claim selected a different workspace key")
    return version


def _live(approval: dict[str, Any]) -> None:
    issued = datetime.fromisoformat(approval["issued_at"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(approval["expires_at"].replace("Z", "+00:00"))
    if issued.tzinfo is None or expires.tzinfo is None or not issued <= datetime.now(timezone.utc) < expires:
        raise ValueError("approval expired or invalid")


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)
        except ProcessLookupError:
            process.wait(timeout=3)


def run_witnessed_request(
    approval_envelope: dict[str, Any],
    request: dict[str, Any],
    trusted_key_path: str | Path,
    run_dir: str | Path,
    claim_witness: Callable[[], dict[str, Any]],
    claim_dispatch: Callable[[], dict[str, Any]],
    *,
    witness_key_ref: str,
    kms_auth: str = "gcloud",
    local_test_signer: bool = False,
    binary_path: str | Path | None = None,
    kms_python_path: str | Path | None = None,
    kms_helper_path: str | Path | None = None,
    timeout_seconds: int = 180,
) -> dict[str, Any]:
    """Run once in a NEW directory; return sanitized failure or verified evidence.

    A failure never grants permission to retry the provider request. If a claim
    was attempted, the caller must reconcile the same operation with Allowly.
    This supervisor deliberately uses private loopback native transport rather
    than pretending a local WebSocket bridge is a deployed witness service.
    """
    run_dir = Path(run_dir).absolute()
    evidence = run_dir / "evidence"
    deadline = time.monotonic() + timeout_seconds
    processes: list[subprocess.Popen[bytes]] = []
    phase = "configuration"
    claim_attempted = False
    dispatch_attempted = False
    started_at: str | None = None
    result: dict[str, Any] = {
        "verified": False,
        "target_state": "not_started",
        "evidence_state": "evidence_gap",
        "retry_business_request": False,
        "reconcile_required": False,
        "artifact_directory": str(run_dir),
    }
    env = {name: os.environ[name] for name in ("PATH", "HOME", "USER", "TMPDIR", "LANG", "LC_ALL") if name in os.environ}

    def remaining() -> float:
        seconds = deadline - time.monotonic()
        if seconds <= 0:
            raise TimeoutError("native run deadline")
        return seconds

    with ExitStack() as stack:
        try:
            if not 1 <= timeout_seconds <= 300 or kms_auth not in {"gcloud", "adc"}:
                raise ValueError("invalid native settings")
            if not re.fullmatch(r"projects/[^/\s]+/locations/[^/\s]+/keyRings/[^/\s]+/cryptoKeys/[^/\s]+", witness_key_ref):
                raise ValueError("invalid workspace witness key")
            binary = Path(binary_path or ROOT / "target/release/allowly-witness-poc").resolve(strict=True)
            python = Path(kms_python_path or ROOT / ".venv/bin/python").absolute()
            helper = Path(kms_helper_path or ROOT / "kms/gcp_signer.py").resolve(strict=True)
            if not binary.is_file() or not os.access(binary, os.X_OK) or not python.is_file() or not os.access(python, os.X_OK):
                raise ValueError("native runtime unavailable")
            # Copy public trust before any claim; never trust the key in evidence.
            trusted = _read_json(Path(trusted_key_path), 4096)
            trusted_fingerprint = _fingerprint(trusted)
            binding = {name: approval_envelope[name] for name in ("approval", "approval_sha256")}
            binding = json.loads(_json_bytes(binding))
            approval = binding["approval"]
            if approval["profile"] != "allowly.execution.approval.v1" or approval["evidence_mode"] != "witnessed":
                raise ValueError("wrong approval profile")
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", binding["approval_sha256"]):
                raise ValueError("invalid approval fingerprint")
            _live(approval)
            if set(request) != {"headers", "body"} or not isinstance(request["headers"], dict) or not isinstance(request["body"], str):
                raise ValueError("invalid native request")
            native_input = _json_bytes({**binding, "request": request, "require_dispatch_ack": True})
            if len(native_input) > 128 * 1024:
                raise ValueError("oversized native input")
            run_dir.mkdir(mode=0o700)
            os.chmod(run_dir, 0o700)
            approval_path = run_dir / "approval.json"
            trust_path = run_dir / "trusted-notary-key.json"
            _write_private(approval_path, _json_bytes(binding))
            _write_private(trust_path, _json_bytes(trusted))

            def start(arguments: list[str], name: str, child_env: dict[str, str], *, piped: bool = False) -> subprocess.Popen[bytes]:
                stdout = stack.enter_context(os.fdopen(os.open(run_dir / f"{name}.stdout.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"))
                stderr = stack.enter_context(os.fdopen(os.open(run_dir / f"{name}.stderr.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"))
                process = subprocess.Popen([str(binary), *arguments], cwd=ROOT, env=child_env, stdin=subprocess.PIPE if piped else subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
                processes.append(process)
                return process

            def wait_file(path: Path, process: subprocess.Popen[bytes]) -> Any:
                while not path.exists():
                    remaining()
                    _live(approval)
                    if process.poll() is not None:
                        raise RuntimeError("native process stopped before readiness")
                    time.sleep(0.025)
                return _read_json(path, 4096)

            phase = "witness_admission"
            claim_attempted = True
            claim = claim_witness()
            remaining()
            if (
                claim["approval"] != approval
                or claim["approval_sha256"] != binding["approval_sha256"]
                or claim["operation_id"] != approval["operation_id"]
                or claim["workspace_id"] != approval["workspace_id"]
                or claim["expires_at"] != approval["expires_at"]
                or claim["expected_server_name"] != approval["request"]["origin"].removeprefix("https://")
                or claim["trusted_notary_key_fingerprint_sha256"] != trusted_fingerprint
                or claim["native_profile"] != PROFILE
                or claim["request_binding_verification"] != "customer_held_bundle"
            ):
                raise ValueError("witness claim mismatch")
            session = approval_envelope.get("witness_session")
            if session is not None and claim["session_id"] != session["session_id"]:
                raise ValueError("witness session mismatch")
            kms_key_version = _claimed_key_version(claim, witness_key_ref)
            _live(approval)
            phase = "witness_start"
            witness_env = {**env, "ALLOWLY_KMS_AUTH": kms_auth}
            cloud_names = () if local_test_signer else ("CLOUDSDK_CONFIG", "GOOGLE_APPLICATION_CREDENTIALS")
            for name in (*cloud_names, "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE"):
                if name in os.environ:
                    witness_env[name] = os.environ[name]
            witness = start([
                "witness", "--execution-approval", str(approval_path), "--listen", "127.0.0.1:0",
                "--public-key", str(run_dir / "witness-public-key.json"),
                "--ready-file", str(run_dir / "witness-ready.json"),
                "--kms-key-version", kms_key_version, "--kms-python", str(python), "--kms-helper", str(helper),
            ], "witness", witness_env)
            ready = wait_file(run_dir / "witness-ready.json", witness)
            host, port = ready["listen"].rsplit(":", 1)
            if not ipaddress.ip_address(host).is_loopback or not 0 < int(port) < 65536 or ready["signer_fingerprint_sha256"] != trusted_fingerprint:
                raise ValueError("native witness trust mismatch")
            phase = "mpc_setup"
            prover = start([
                "prove-execute", "--witness", ready["listen"], "--trusted-key", str(trust_path), "--output", str(evidence),
            ], "prover", env, piped=True)
            assert prover.stdin is not None
            prover.stdin.write(native_input)
            prover.stdin.close()
            if wait_file(evidence / "witness.ready.json", prover) != {"approval_sha256": binding["approval_sha256"]}:
                raise ValueError("native prover approval mismatch")
            phase = "dispatch_claim"
            dispatch_attempted = True
            dispatch = claim_dispatch()
            remaining()
            if (
                dispatch["dispatch_state"] != "claimed"
                or dispatch["operation_id"] != approval["operation_id"]
                or dispatch["approval"] != approval
                or dispatch["approval_sha256"] != binding["approval_sha256"]
                or dispatch["approval_expires_at"] != approval["expires_at"]
                or dispatch["effective_evidence_mode"] != "witnessed"
            ):
                raise ValueError("dispatch claim mismatch")
            _live(approval)
            started_at = datetime.now(timezone.utc).isoformat()
            gate = evidence / "dispatch.approved.tmp"
            _write_private(gate, _json_bytes({"approval_sha256": binding["approval_sha256"]}))
            os.rename(gate, evidence / "dispatch.approved.json")
            directory_fd = os.open(evidence, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            phase = "provider_exchange_and_proof"
            if prover.wait(timeout=remaining()) != 0:
                raise RuntimeError("native prover failed")
            if witness.wait(timeout=remaining()) != 0:
                raise RuntimeError("native witness failed")

            def verify(command: str, flag: str, filename: str, name: str) -> dict[str, Any]:
                process = start([command, flag, str(evidence / filename), "--trusted-key", str(trust_path), "--approval", str(approval_path)], name, env)
                if process.wait(timeout=remaining()) != 0:
                    raise RuntimeError("independent evidence verification failed")
                value = _read_json(run_dir / f"{name}.stdout.json")
                if value.get("verified") is not True or value.get("trust_mode") != "mozilla_public_roots" or value.get("approval_sha256") != binding["approval_sha256"] or value.get("signer_fingerprint_sha256") != trusted_fingerprint:
                    raise ValueError("verification output mismatch")
                return value

            phase = "evidence_verification"
            full = verify("verify-execute", "--presentation", "presentation.json", "verify-full")
            compact = verify("verify-execute-attestation", "--attestation", "attestation.json", "verify-compact")
            if full.get("request_binding_verification") != "verified_from_full_presentation" or compact.get("request_binding_verification") != "customer_held_bundle":
                raise ValueError("wrong verification profile")
            result.update(
                verified=True, target_state="response_observed", evidence_state="customer_held_witness_bundle",
                response=full["response"], full_verification=full, compact_verification=compact,
                evidence_bundle_sha256=full["artifact_sha256"],
                notary_attestation=_read_json(evidence / "attestation.json", 1024 * 1024),
                evidence_paths={"presentation": str(evidence / "presentation.json"), "attestation": str(evidence / "attestation.json"), "approval": str(approval_path), "trusted_key": str(trust_path)},
            )
        except Exception as error:  # noqa: BLE001 - contain callback failures without leaking secrets
            # Native/HTTP exception text may contain private request data. Keep it local.
            result.update(error={"phase": phase, "category": type(error).__name__}, reconcile_required=claim_attempted)
        finally:
            for process in reversed(processes):
                _stop(process)
            if not result["verified"] and evidence.is_dir():
                result["target_state"] = "unknown" if (evidence / "dispatch.started.json").exists() else "not_started"
                try:
                    if (evidence / "response.json").exists():
                        result.update(response=_read_json(evidence / "response.json"), target_state="response_observed")
                except (OSError, ValueError):
                    pass
            result.update(dispatch_claim_attempted=dispatch_attempted, dispatch_started_at=started_at, completed_at=datetime.now(timezone.utc).isoformat())
    return result
