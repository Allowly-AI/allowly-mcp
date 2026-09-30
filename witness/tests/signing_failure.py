#!/usr/bin/env python3
"""TEST ONLY: real native TLSNotary exchange with a fake KMS signing failure.

Uses the upstream loopback HTTPS fixture and a publicly known test key.
No Cloud KMS request or cloud signature is made. Run from witness/:
    python3 tests/signing_failure.py
"""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target/release/allowly-witness-poc"
KEY_VERSION = (
    "projects/test-only/locations/global/keyRings/tests/cryptoKeys/"
    "fail-sign/cryptoKeyVersions/1"
)
WITNESS_ADDRESS = "127.0.0.1:7048"


def wait_for_free_ports():
    deadline = time.monotonic() + 60
    while True:
        available = True
        for port in (3000, 7048):
            with socket.socket() as probe:
                try:
                    probe.bind(("127.0.0.1", port))
                except OSError:
                    available = False
        if available:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("Test ports are in use; existing processes were left alone")
        time.sleep(0.5)


def main():
    base = ROOT / "artifacts"
    base.mkdir(exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="failure-fake-signing-", dir=base))
    trusted = out / "trusted-test-key.json"
    evidence = out / "evidence"
    env = {name: os.environ[name] for name in
           ("PATH", "TMPDIR", "TMP", "TEMP", "SystemRoot", "WINDIR")
           if name in os.environ}
    processes, logs = [], []
    report = {
        "test": "fake_signing_failure_after_real_tlsnotary_exchange",
        "cloud_kms": False,
        "signing_backend": "test-only fake helper configured to refuse signing",
        "real_tlsnotary": False,
        "actual_native_invocation": False,
        "status": "failed",
        "checks": {},
        "artifact_directory": str(out),
    }

    def start(command, name):
        log = open(out / name, "w", encoding="utf-8")
        log.write("TEST ONLY: fake KMS signing failure; no Cloud KMS calls or signatures.\n")
        log.flush()
        logs.append(log)
        process = subprocess.Popen([str(arg) for arg in command], cwd=ROOT,
                                   env=env, stdout=log, stderr=log)
        processes.append(process)
        return process

    try:
        wait_for_free_ports()
        fixture = start([BIN, "fixture"], "fixture.log")
        time.sleep(0.3)
        if fixture.poll() is not None:
            raise RuntimeError("Test fixture did not start")
        witness = start([
            BIN, "witness", "--listen", WITNESS_ADDRESS,
            "--kms-key-version", KEY_VERSION,
            "--kms-helper", ROOT / "kms/fake_helper_for_rust_tests.py",
            "--kms-python", sys.executable,
            "--fixture", "--public-key", trusted,
        ], "witness.log")
        deadline = time.monotonic() + 40
        while not trusted.exists():
            if witness.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Fake-signing witness did not become ready")
            time.sleep(0.05)
        result = subprocess.run([
            str(BIN), "prove", "--witness", WITNESS_ADDRESS, "--trusted-key", str(trusted),
            "--fixture", "--output", str(evidence),
        ], cwd=ROOT, env=env, capture_output=True, text=True, timeout=200)
        if result.returncode == 0:
            raise RuntimeError("Native prover did not observe the expected signing failure")
        assert not result.stdout.strip(), "failed prover must not return successful evidence"
        report["actual_native_invocation"] = True
        report["checks"]["signing_failure_is_native_error"] = "pass"

        witness_log = (out / "witness.log").read_text()
        # This branch is reached only after the native verifier completes the
        # real MPC exchange and checks the allowed server identity.
        assert "Witness session failed:" in witness_log
        assert "witness KMS helper failed" in witness_log
        assert "TLSNotary attestation issued" not in witness_log
        report["real_tlsnotary"] = True
        report["checks"]["real_exchange_reached_failing_signer"] = "pass"
        for filename in ("presentation.json", "attestation.json", "verified.json"):
            assert not list(evidence.rglob(filename)), f"Unexpected evidence file: {filename}"
        report["checks"]["no_evidence_artifact_emitted"] = "pass"
        report["status"] = "pass"
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
        for log in logs:
            log.close()
        report["processes_stopped"] = all(p.poll() is not None for p in processes)
        (out / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
