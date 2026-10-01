#!/usr/bin/env python3
"""Real local TLS/MPC execution proof. Synthetic approval and TEST CA only.

No Allowly API or vendor write is made by this test. The synthetic approval is
not an Allowly receipt; API/SDK integration tests cover remote authorization.
"""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target/release/allowly-witness-poc"


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def run(*args, input=None, succeeds=True):
    result = subprocess.run([str(BIN), *map(str, args)], input=input, text=True,
                            capture_output=True, timeout=180, cwd=ROOT)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(result.stderr[:2000])
    return json.loads(result.stdout) if succeeds else None


def main():
    (ROOT / "artifacts").mkdir(exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="execute-", dir=ROOT / "artifacts"))
    rejected_key = out / "rejected-production-test-key.json"
    run("witness", "--local-test-key", "--public-key", rejected_key, succeeds=False)
    assert not rejected_key.exists(), "test key must not configure a production notary"
    now = datetime.now(timezone.utc)
    secret = "Bearer local-fixture-only"
    approval = {"profile": "allowly.execution.approval.v1", "evidence_mode": "witnessed",
                "operation_id": "fixture-stable-operation", "issued_at": (now-timedelta(seconds=1)).isoformat(),
                "expires_at": (now+timedelta(minutes=5)).isoformat(),
                "request": {"method": "GET", "origin": "https://test-server.io",
                            "path": "/formats/json", "query": "", "body_size": 0,
                            "body_sha256": digest(b""), "content_type": None,
                            "headers": [{"name": "authorization", "value_sha256": digest(
                                b"allowly.execution.header.v1\0authorization\0" + secret.encode())}]}}
    binding = {"approval": approval, "approval_sha256": digest(json.dumps(approval,sort_keys=True,separators=(",", ":")).encode())}
    approval_path = out / "approval.json"
    approval_path.write_text(json.dumps(binding))
    key = out / "notary-key.json"
    processes, logs = [], []
    def start(args, filename):
        log = open(out / filename, "w")
        logs.append(log)
        p = subprocess.Popen([str(BIN), *map(str,args)], cwd=ROOT, stdout=log, stderr=log)
        processes.append(p)
        return p
    report = {"status": "failed", "fixture_only": True, "real_tlsnotary": False}
    try:
        fixture = start(["fixture"], "fixture.log")
        witness = start(["witness", "--listen", "127.0.0.1:7051", "--public-key", key,
                         "--local-test-key", "--fixture", "--execution-approval", approval_path], "witness.log")
        deadline = time.monotonic()+30
        while not key.exists():
            assert witness.poll() is None, "witness failed before readiness"
            assert time.monotonic() < deadline, "witness readiness timeout"
            time.sleep(.05)
        assert fixture.poll() is None
        payload = {**binding, "request":{"headers":{"authorization":secret}, "body":""}, "require_dispatch_ack":True}
        # Bad request must fail before consuming the single admitted witness session.
        bad = copy.deepcopy(payload)
        bad["request"]["headers"]["authorization"] = "Bearer wrong"
        run("prove-execute", "--witness", "127.0.0.1:7051", "--trusted-key", key,
            "--output", out/"rejected", "--fixture", input=json.dumps(bad), succeeds=False)
        assert witness.poll() is None
        prover = subprocess.Popen([str(BIN),"prove-execute","--witness","127.0.0.1:7051",
            "--trusted-key",str(key),"--output",str(out/"evidence"),"--fixture"],cwd=ROOT,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        processes.append(prover)
        prover.stdin.write(json.dumps(payload)); prover.stdin.close(); prover.stdin = None
        deadline = time.monotonic()+120
        while not (out/"evidence/witness.ready.json").exists():
            if prover.poll() is not None: raise AssertionError(prover.stderr.read()[:2000])
            assert time.monotonic() < deadline, "witness readiness timeout"
            time.sleep(.02)
        assert not (out/"evidence/dispatch.started.json").exists(), "must wait before provider send"
        # This is the controlled test equivalent of the SDK receiving /dispatch.
        gate = out/"evidence/dispatch.approved.tmp"
        gate.write_text(json.dumps({"approval_sha256":binding["approval_sha256"]}))
        gate.rename(out/"evidence/dispatch.approved.json")
        stdout, stderr = prover.communicate(timeout=180)
        assert prover.returncode == 0, stderr[:2000]
        result = json.loads(stdout)
        assert result["request_binding_verification"] == "verified_from_full_presentation"
        assert result["response"]["status"] == 200
        presentation = out/"evidence/presentation.json"
        attestation = out/"evidence/attestation.json"
        checked = run("verify-execute", "--presentation", presentation, "--trusted-key", key,
                      "--approval", approval_path, "--fixture")
        assert checked["verified"] is True
        compact = run("verify-execute-attestation", "--attestation", attestation, "--trusted-key", key,
                      "--approval", approval_path, "--fixture")
        assert compact["request_binding_verification"] == "customer_held_bundle"
        assert "response" not in compact
        assert secret not in attestation.read_text()
        assert secret not in (out/"witness.log").read_text()
        changed = copy.deepcopy(binding)
        changed["approval"]["request"]["path"] = "/wrong"
        changed_path = out/"wrong-request.json"
        changed_path.write_text(json.dumps(changed))
        run("verify-execute", "--presentation", presentation, "--trusted-key", key,
            "--approval", changed_path, "--fixture", succeeds=False)
        changed["approval_sha256"] = "sha256:"+"b"*64
        changed_path.write_text(json.dumps(changed))
        run("verify-execute-attestation", "--attestation", attestation, "--trusted-key", key,
            "--approval", changed_path, "--fixture", succeeds=False)
        tampered = json.loads(presentation.read_text())
        tampered["transcript"]["transcript"]["received_authed"][-1] ^= 1
        tampered_path = out/"tampered.json"
        tampered_path.write_text(json.dumps(tampered))
        run("verify-execute", "--presentation", tampered_path, "--trusted-key", key,
            "--approval", approval_path, "--fixture", succeeds=False)
        run("verify-execute", "--presentation", presentation, "--trusted-key", key,
            "--approval", approval_path, succeeds=False)
        # Existing marker/output prevents a new send even if the old result is lost.
        run("prove-execute", "--witness", "127.0.0.1:7051", "--trusted-key", key,
            "--output", out/"evidence", "--fixture", input=json.dumps(payload), succeeds=False)
        assert (out/"evidence/dispatch.started.json").exists()
        assert (out/"evidence/response.json").exists()
        witness.wait(timeout=10)
        report.update(status="pass", real_tlsnotary=True, checks=["changed_private_header_rejected_before_send",
            "real_mpc_exchange", "full_presentation_request_binding", "compact_reference_only",
            "credential_absent_from_notary_record", "wrong_request_rejected", "wrong_approval_reference_rejected",
            "tampered_transcript_rejected", "fixture_trust_explicit", "remote_dispatch_gate_before_send", "durable_dispatch_and_response", "output_reuse_rejected"])
    finally:
        for p in processes:
            if p.poll() is None:
                p.terminate()
                try: p.wait(timeout=10)
                except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=10)
        for log in logs: log.close()
        report["artifact_directory"] = str(out)
        (out/"report.json").write_text(json.dumps(report,indent=2))
        print(json.dumps(report,indent=2))


if __name__ == "__main__":
    main()
