"""Measure the sibling runtime's real /v1/check over local HTTP.

Requires its existing .venv and locally cached Docker Desktop images. Creates
only disposable benchmark containers/data; never reads .env or cloud credentials.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import secrets
import socket
import statistics
import subprocess
import tempfile
import time

import httpx

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent.parent / "allowly-api"
PYTHON = str(REPO / ".venv/bin/python")
DOCKER = ["docker", "--context", "desktop-linux"]
OUT = Path(tempfile.mkdtemp(prefix="allowly-check-bench-", dir="/tmp"))
RUN = OUT.name
containers = []
server = None
report = {"status": "failed", "directory": str(OUT), "samples": []}


def docker(*args):
    return subprocess.check_output([*DOCKER, *args], text=True).strip()


def service(suffix, image, port, *args):
    name = f"{RUN}-{suffix}"
    docker("run", "--pull", "never", "-d", "--name", name,
           "--label", f"allowly.local-benchmark={RUN}",
           "-p", f"127.0.0.1::{port}", *args, image)
    containers.append(name)
    address = docker("port", name, f"{port}/tcp")
    assert address.startswith("127.0.0.1:")
    return name, int(address.rsplit(":", 1)[1])


def run_python(*args):
    with (OUT / "setup.log").open("a") as log:
        subprocess.run([PYTHON, *args], cwd=REPO, env=env,
                       stdout=log, stderr=log, check=True, timeout=90)


try:
    pg, pg_port = service("pg", "postgres:18.4-bookworm", 5432,
                          "-e", "POSTGRES_PASSWORD=local-benchmark-only",
                          "-e", "POSTGRES_USER=bench", "-e", "POSTGRES_DB=bench")
    redis, redis_port = service("redis", "redis:8.8.1-alpine", 6379)
    deadline = time.monotonic() + 30
    while subprocess.run([*DOCKER, "exec", pg, "pg_isready", "-U", "bench"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        if time.monotonic() > deadline:
            raise TimeoutError("Benchmark Postgres did not start")
        time.sleep(.2)
    assert docker("exec", redis, "redis-cli", "ping") == "PONG"
    db = f"postgresql+asyncpg://bench:local-benchmark-only@127.0.0.1:{pg_port}/bench"
    env = {key: os.environ[key] for key in ("PATH", "TMPDIR", "LANG") if key in os.environ}
    env.update({
        "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
        "APP_ENV": "dev", "ALLOWLY_RUNTIME_ROLE": "api",
        "DATABASE_URL": db, "MIGRATION_DATABASE_URL": db,
        "REDIS_URL": f"redis://127.0.0.1:{redis_port}/0",
        "ALLOWLY_HMAC_SECRET": secrets.token_hex(32),
        "API_KEY_LOOKUP_SECRET": secrets.token_hex(32),
        "GCP_SECRETS_ENABLED": "false", "ENABLE_CRON": "false",
        "ENABLE_KMS_SIGNING": "false", "ENABLE_RECEIPT_EVIDENCE_WRITE": "false",
        "ENABLE_BIGQUERY_WRITE": "false",
        "CHECK_TIMING_PROFILE_ENABLED": "true", "CHECK_TIMING_PROFILE_SAMPLE_RATE": "1",
        "HOT_PATH_SUCCESS_LOG_SAMPLE_RATE": "1",
    })
    run_python("-m", "alembic", "upgrade", "head")
    seed_path = OUT / "seed.json"
    run_python("-m", "scripts.stresstest.mint_stress_material", "--run-id", RUN,
               "--key-count", "1", "--authorization-count", "1", "--action", "stress.local",
               "--key-env", "test", "--tier", "enterprise", "--kms-key-ref", "stress:none",
               "--expires-hours", "0.25", "--output", str(seed_path))
    seed = json.loads(seed_path.read_text())
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        api_port = sock.getsockname()[1]
    with (OUT / "api.log").open("w") as log:
        server = subprocess.Popen([PYTHON, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
                                   "--port", str(api_port), "--workers", "1", "--no-access-log"],
                                  cwd=REPO, env=env, stdout=log, stderr=log)
    base = f"http://127.0.0.1:{api_port}"
    deadline = time.monotonic() + 30
    with httpx.Client(base_url=base, timeout=15, trust_env=False) as client:
        while True:
            try:
                if client.get("/readyz").status_code == 200:
                    break
            except httpx.ConnectError:
                pass
            if server.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("Benchmark API failed startup; inspect api.log")
            time.sleep(.1)
        for index in range(110):
            request_id = f"{RUN}-{index}"
            payload = {"authorization_id": seed["authorizations"][0]["id"],
                       "actions": [seed["action"]], "estimated_cost_micros": 0,
                       "session_id": request_id}
            started = time.perf_counter()
            response = client.post("/v1/check?wait=false", json=payload,
                                   headers={"Authorization": f"Bearer {seed['api_keys'][0]}",
                                            "X-Request-Id": request_id})
            elapsed = (time.perf_counter() - started) * 1000
            if response.status_code != 200:
                raise RuntimeError(f"Unexpected benchmark HTTP status {response.status_code}: {response.text}")
            result = response.json()["results"][seed["action"]]
            assert result["decision"] == "allow", result["decision"]
            assert result["receipt"]["status"] == "pending"
            report["samples"].append({"request_id": request_id, "client_ms": elapsed,
                                      "warmup": index < 10, "decision": "allow", "receipt_status": "pending"})
            if index in (0, 9, 59, 109):
                print(json.dumps({"completed": index + 1, "latest_ms": round(elapsed, 3)}), flush=True)
            time.sleep(max(0, .2 - (time.perf_counter() - started)))
    # Verify actual durable rows before removing the disposable database.
    run_python("-c", """
import asyncio, json
from pathlib import Path
from sqlalchemy import select, func, text
from app.database import AsyncSessionLocal
from app.models import ReceiptRecent
async def main():
    async with AsyncSessionLocal() as db:
        count = await db.scalar(select(func.count()).select_from(ReceiptRecent))
        durability = {key: await db.scalar(text('SHOW ' + key)) for key in ('fsync','synchronous_commit')}
        Path('""" + str(OUT / "database-check.json") + """').write_text(json.dumps({'receipts':count, **durability}))
asyncio.run(main())
""")
    report["database"] = json.loads((OUT / "database-check.json").read_text())
    assert report["database"]["receipts"] == len(report["samples"])
    profiles = {}
    observations = {}
    for line in (OUT / "api.log").read_text().splitlines():
        if not line.startswith("{"):
            continue
        entry = json.loads(line)
        if entry.get("event") == "check_timing_profile":
            profiles[entry["request_id"]] = entry
        elif entry.get("event") == "http_request":
            observations[entry["request_id"]] = entry
    for sample in report["samples"]:
        profile = profiles[sample["request_id"]]
        sample["profile_ms"] = profile["total_ms"]
        sample["http_handler_ms"] = observations[sample["request_id"]]["duration_ms"]
        sample["stages_ms"] = {name: stage["total_ms"] for name, stage in profile["stages"].items()}
    measured = sorted((x for x in report["samples"] if not x["warmup"]), key=lambda x: x["client_ms"])
    durations = [x["client_ms"] for x in measured]
    report.update({
        "status": "pass", "route": "POST /v1/check?wait=false", "count": len(measured),
        "first_request_ms": report["samples"][0]["client_ms"],
        "summary_ms": {"min": min(durations), "median": statistics.median(durations),
                       "p95_nearest_rank": durations[math.ceil(.95 * len(durations)) - 1],
                       "max": max(durations)},
        "representative": measured[len(measured) // 2],
        "under_30ms": sum(x < 30 for x in durations),
        "runtime_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "setup": "Host Python 3.12/Uvicorn, one worker; real Docker Postgres18.4 and Redis8.8.1; 5RPS, sequential keep-alive HTTP; ten warmups; one unrestricted action; Enterprise synthetic workspace; no budget, external identity, or idempotency replay; normal origin rate limiter enabled.",
        "excluded": ["Service startup", "MCP", "TLSNotary", "Public network/TLS/edge proxy", "GCS registration", "KMS final signing"],
    })
finally:
    if server is not None:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()
    for name in reversed(containers):
        docker("rm", "-f", "-v", name)
    (OUT / "seed.json").unlink(missing_ok=True)
    report["cleanup"] = "Owned containers and their volumes removed; API stopped; temporary API-key seed file removed."
    (OUT / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "summary_ms": report.get("summary_ms"),
                      "report": str(OUT / "report.json")}), flush=True)
