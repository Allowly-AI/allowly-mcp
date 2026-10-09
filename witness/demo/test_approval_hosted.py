"""Hosted auth/review tests with no production/API/provider traffic."""
import base64
import json
import threading
import time

import httpx
import pytest

from approval_lab import ApprovalLab, LabError, load_config, make_server, save_private
from test_approval_lab import Runtime, config, wait

PASSWORD = "fixture-secret-" + "a" * 40
PUBLIC_ORIGIN = "https://approval-lab.example.test"


def hosted_config(tmp_path):
    auth = tmp_path / "browser-auth.json"
    save_private(auth, {"username": "lab-user", "password": PASSWORD})
    value = {**config(), "api_base_url": "https://api.example.test", "external_review": True,
             "public_origin": PUBLIC_ORIGIN, "browser_auth_file": str(auth)}
    path = tmp_path / "config.json"
    save_private(path, value)
    return path, value


@pytest.mark.parametrize("changed", [{"api_base_url": "http://127.0.0.1:8085"}, {"public_origin": "http://example.test"},
                                     {"external_review": "true"}, {"edge_token": "not-for-public-routing"},
                                     {"browser_auth_file": "relative.json"}])
def test_hosted_configuration_requires_explicit_https_private_auth(tmp_path, changed):
    path, value = hosted_config(tmp_path)
    save_private(path, {**value, **changed})
    with pytest.raises(ValueError):
        load_config(path)


def test_hosted_auth_never_reuses_runtime_key_or_weak_password(tmp_path):
    path, value = hosted_config(tmp_path)
    auth = tmp_path / "browser-auth.json"
    for password in ("short", value["api_key"]):
        save_private(auth, {"username": "lab-user", "password": password})
        with pytest.raises(ValueError):
            load_config(path)


@pytest.mark.parametrize("kind", ["confirm", "escalate"])
@pytest.mark.parametrize("outcome", ["approved", "rejected"])
def test_external_poll_wakes_same_operation_without_local_resolver(tmp_path, kind, outcome):
    path, _ = hosted_config(tmp_path)
    runtime = Runtime()
    lab = ApprovalLab(load_config(path), tmp_path / "state", client_factory=runtime.client)
    try:
        operation_id = lab.start(kind)["operation_id"]
        initial = wait(lab, operation_id, {"waiting_for_review"})
        assert initial["external_review"] is True and runtime.continued == []
        with pytest.raises(LabError, match="external_review_required"):
            lab.resolve(operation_id, "approve")
        runtime.runs[operation_id].update(status=outcome, authority="available" if outcome == "approved" else "none")
        lab.snapshot(operation_id)
        value = wait(lab, operation_id, {"succeeded", "rejected"})
        assert value["choice_source"] == "status_poll"
        assert runtime.continued == ([operation_id] if outcome == "approved" else [])
        assert runtime.resolved == []
    finally:
        lab.close()


def test_background_monitor_wakes_without_browser(tmp_path):
    path, _ = hosted_config(tmp_path)
    runtime = Runtime()
    lab = ApprovalLab(load_config(path), tmp_path / "state", client_factory=runtime.client)
    try:
        operation_id = lab.start("escalate")["operation_id"]
        wait(lab, operation_id, {"waiting_for_review"})
        runtime.runs[operation_id].update(status="approved", authority="available")
        lab.start_monitor()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not runtime.continued:
            time.sleep(0.01)
        assert runtime.continued == [operation_id]
        wait(lab, operation_id, {"succeeded"})
    finally:
        lab.close()


def test_poll_transport_outage_stays_waiting_without_send(tmp_path):
    runtime = Runtime()
    lab = ApprovalLab(config(), tmp_path, client_factory=runtime.client)
    try:
        operation_id = lab.start("confirm")["operation_id"]
        wait(lab, operation_id, {"waiting_for_review"})
        original = lab.client_factory
        def broken(state):
            client = original(state)
            async def unavailable(_):
                raise httpx.ConnectError("private provider details should not appear")
            client.get_status = unavailable
            return client
        lab.client_factory = broken
        lab.snapshot(operation_id)
        value = wait(lab, operation_id, {"waiting_for_review"})
        assert value["poll_error"] == "status_temporarily_unavailable"
        assert "private provider details" not in json.dumps(value)
        assert runtime.continued == []
    finally:
        lab.close()


def test_hosted_http_auth_host_origin_csrf_and_body_bounds(tmp_path, monkeypatch):
    path, _ = hosted_config(tmp_path)
    runtime = Runtime()
    lab = ApprovalLab(load_config(path), tmp_path / "state", client_factory=runtime.client)
    async def ready(_):
        return True
    monkeypatch.setattr("approval_lab.Allowly.readiness", ready)
    server = make_server(lab, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}"
    token = base64.b64encode(("lab-user:" + PASSWORD).encode()).decode()
    auth = {"Host": "approval-lab.example.test", "Authorization": "Basic " + token}
    try:
        assert server.server_address[0] == "127.0.0.1"
        with httpx.Client(base_url=url, trust_env=False) as browser:
            for endpoint in ("/", "/api/status", "/api/approval-lab/status"):
                response = browser.get(endpoint, headers={"Host": "approval-lab.example.test"})
                assert response.status_code == 401 and "WWW-Authenticate" in response.headers
            assert browser.get("/api/approval-lab/status", headers={**auth, "Authorization": "Basic !!!"}).status_code == 401
            assert browser.get("/api/approval-lab/status", headers={**auth, "Host": "attacker.test", "X-Forwarded-Host": "approval-lab.example.test"}).status_code == 403
            assert browser.get("/api/approval-lab/status", headers={**auth, "Origin": "https://attacker.test"}).status_code == 403
            response = browser.get("/api/approval-lab/status", headers=auth)
            assert response.status_code == 200 and response.json()["external_review"] is True
            assert PASSWORD not in response.text and "private-api-key" not in response.text
            headers = {**auth, "Origin": PUBLIC_ORIGIN, "X-Demo-Token": response.json()["csrf_token"]}
            assert browser.post("/api/approval-lab/jobs", headers=auth, json={"scenario": "confirm"}).status_code == 403
            assert browser.post("/api/approval-lab/jobs", headers=headers, content="{}").status_code == 400
            assert browser.post("/api/approval-lab/jobs", headers=headers, json={"scenario": "confirm", "url": "https://attacker.test"}).status_code == 400
            assert browser.post("/api/approval-lab/jobs", headers=headers, json={"scenario": "x" * 4096}).status_code == 400
            job = browser.post("/api/approval-lab/jobs", headers=headers, json={"scenario": "confirm"})
            assert job.status_code == 202
            operation_id = job.json()["operation_id"]
            wait(lab, operation_id, {"waiting_for_review"})
            assert browser.post(f"/api/approval-lab/jobs/{operation_id}/resolve", headers=headers, json={"choice": "approve"}).status_code == 403
            assert runtime.resolved == [] and runtime.continued == []
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        lab.close()
