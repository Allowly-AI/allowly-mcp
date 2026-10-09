"""Credential-free adapter tests; the provider is never contacted."""
import asyncio
import json
import threading
import time
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest
from allowly import Allowly
from allowly.error import AllowlyProtocolError
from allowly.types import (
    ConfirmationStatusResponse,
    EscalationStatusResponse,
    ExecutionRequestDescriptor,
    ExecutionResponse,
    ExecutionReview,
    OutcomeEvidence,
    ReceiptEnvelopePending,
)
from approval_lab import (
    TARGET_URL,
    ApprovalLab,
    ReviewOnlyClient,
    save_private,
)


def config():
    return {"api_key": "private-api-key", "workspace_id": "ws_local", "api_base_url": "http://127.0.0.1:8085",
            "enabled_executable_id": "exe_github", "action": "github.read",
            "scenarios": {kind: {"authorization_id": "auth_" + kind, "context": {"review": kind}}
                          for kind in ("confirm", "escalate")}}


def execution(operation_id, kind, status="waiting_for_review"):
    waiting = status == "waiting_for_review"
    descriptor = ExecutionRequestDescriptor(operation_id, "auth_" + kind, "exe_github", "github.read", "GET",
                                             "https://api.github.com", "/repos/octocat/Hello-World/issues", "", [],
                                             "sha256:" + "0" * 64, 0, None)
    receipt = ReceiptEnvelopePending("pending", "rcp_" + operation_id, None, "/receipt")
    result = ExecutionResponse(operation_id, status, kind if waiting else "allow", "test", "exe_github", "github.read",
                               "allowly.execution.request.v1", "sha256:" + "1" * 64, descriptor, receipt,
                               confirm_nonce="private-bearer-nonce" if kind == "confirm" and waiting else None,
                               review=ExecutionReview(kind, ("cnf_" if kind == "confirm" else "esc_") + operation_id,
                                                     receipt.receipt_id, "2099-01-01T00:00:00Z"),
                               decision_state="not_allowed" if waiting else "allowed",
                               target_state="not_started" if waiting else "response_observed", evidence_state="pending")
    if not waiting:
        result.outcome_evidence = OutcomeEvidence("allowly.seal.jcs-sha256.v1", {}, "0" * 64,
                                                  ReceiptEnvelopePending("pending", "rcp_outcome", None, "/outcome"))
    return result


class Runtime:
    def __init__(self):
        self.runs, self.continued, self.resolved = {}, [], []
        self.wrong_binding = False

    def client(self, state):
        runtime = self
        class Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_):
                pass

            async def execute_http(self, **arguments):
                operation_id, kind = arguments["operation_id"], state["scenario"]
                result = execution(operation_id, kind)
                runtime.runs[operation_id] = {"execution": result, "arguments": arguments, "status": "pending", "authority": "none"}
                folder = Path(arguments["storage_dir"]) / __import__("hashlib").sha256(operation_id.encode()).hexdigest()
                folder.mkdir(parents=True)
                private = asdict(result)
                private["confirm_nonce"] = None
                save_private(folder / "journal.json", {"phase": "waiting_for_review", "authorization": private})
                return SimpleNamespace(execution=result)

            async def get_execution(self, operation_id):
                return runtime.runs[operation_id]["execution"]

            async def _request(self, method, path):
                run = runtime.runs[state["operation_id"]]
                result = run["execution"]
                review = result.review
                return {"confirmation_id" if review.kind == "confirm" else "escalation_id": review.id,
                        "authorization_id": "auth_" + state["scenario"], "action": "github.read",
                        "resource": "github:octocat/Hello-World", "status": run["status"],
                        "authority_status": run["authority"], "source_receipt_id": "wrong" if runtime.wrong_binding else review.source_receipt_id,
                        "resolution_receipt_id": "rcp_resolution" if run["status"] != "pending" else None}

            async def get_status(self, review_id):
                value = await self._request("GET", review_id)
                value.update(expires_at="2099-01-01T00:00:00Z", resolved_at=None)
                if review_id.startswith("cnf_"):
                    return ConfirmationStatusResponse(**value, child_authorization_id=None, authority_expires_at=None)
                return EscalationStatusResponse(**value, consumed_at=None)

            async def continue_http_execution(self, **arguments):
                operation_id = state["operation_id"]
                run = runtime.runs[operation_id]
                assert arguments == run["arguments"]
                runtime.continued.append(operation_id)
                result = execution(operation_id, state["scenario"], "succeeded")
                run.update(execution=result, authority="consumed")
                folder = Path(arguments["storage_dir"]) / __import__("hashlib").sha256(operation_id.encode()).hexdigest()
                save_private(folder / "journal.json", {"phase": "complete", "outcome": {}, "dispatch_attempted_at": "test"})
                return SimpleNamespace(execution=result, response={"status": 200, "body": '[{"id": 1}]'}, outcome_pending=False)

            async def approve(self, nonce, *, approved, **_):
                assert nonce == "private-bearer-nonce"
                run = runtime.runs[state["operation_id"]]
                runtime.resolved.append(state["operation_id"])
                run.update(status="approved" if approved else "rejected", authority="available" if approved else "none")

            async def resolve(self, review_id, *, resolution, **_):
                run = runtime.runs[state["operation_id"]]
                assert review_id == run["execution"].review.id
                runtime.resolved.append(state["operation_id"])
                run.update(status=resolution, authority="available" if resolution == "approved" else "none")

            @property
            def confirmations(self):
                return self

            @property
            def escalations(self):
                return self
        return Client()


def wait(lab, operation_id, statuses):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        value = lab.snapshot(operation_id, poll=False)
        if value["status"] in statuses and operation_id not in lab.inflight:
            return value
        time.sleep(0.01)
    raise AssertionError(lab.snapshot(operation_id, poll=False))


@pytest.mark.parametrize("kind", ["confirm", "escalate"])
@pytest.mark.parametrize("choice", ["approve", "reject"])
def test_roundtrip_same_operation_no_duplicate_dispatch(tmp_path, kind, choice):
    runtime = Runtime()
    lab = ApprovalLab(config(), tmp_path, client_factory=runtime.client)
    try:
        operation_id = lab.start(kind)["operation_id"]
        waiting = wait(lab, operation_id, {"waiting_for_review"})
        assert waiting["provider_attempts"] == 0
        assert runtime.continued == []
        assert "private-api-key" not in json.dumps(waiting)
        assert "private-bearer-nonce" not in json.dumps(waiting)
        lab.resolve(operation_id, choice)
        finished = wait(lab, operation_id, {"succeeded", "rejected"})
        assert finished["choice_recorded"] is True
        assert finished["provider_attempts"] == (choice == "approve")
        assert finished["outcome_receipt_state"] == ("pending" if choice == "approve" else "unavailable")
        lab.resolve(operation_id, choice)
        assert runtime.continued == ([operation_id] if choice == "approve" else [])
    finally:
        lab.close()


def test_reject_cannot_dispatch_if_someone_already_approved(tmp_path):
    runtime = Runtime()
    lab = ApprovalLab(config(), tmp_path, client_factory=runtime.client)
    try:
        operation_id = lab.start("confirm")["operation_id"]
        wait(lab, operation_id, {"waiting_for_review"})
        runtime.runs[operation_id].update(status="approved", authority="available")
        lab.resolve(operation_id, "reject")
        value = wait(lab, operation_id, {"blocked"})
        assert value["error"] == "choice_already_recorded"
        assert value["choice_recorded"] is False
        assert runtime.continued == []
    finally:
        lab.close()


def test_restart_waiting_and_configuration_mismatch_fail_closed(tmp_path):
    runtime = Runtime()
    original = config()
    lab = ApprovalLab(original, tmp_path, client_factory=runtime.client)
    operation_id = lab.start("confirm")["operation_id"]
    wait(lab, operation_id, {"waiting_for_review"})
    lab.close()
    changed = config()
    changed["scenarios"]["confirm"]["context"] = {"changed": True}
    lab = ApprovalLab(changed, tmp_path, client_factory=runtime.client)
    try:
        assert lab.snapshot(operation_id, poll=False)["status"] == "waiting_for_review"
        lab.resolve(operation_id, "approve")
        assert wait(lab, operation_id, {"blocked"})["error"] == "original_request_changed"
        assert runtime.continued == []
        assert runtime.resolved == []
    finally:
        lab.close()


def test_status_poll_wakes_saved_operation_without_new_check(tmp_path):
    runtime = Runtime()
    lab = ApprovalLab(config(), tmp_path, client_factory=runtime.client)
    operation_id = lab.start("escalate")["operation_id"]
    wait(lab, operation_id, {"waiting_for_review"})
    lab.close()
    runtime.runs[operation_id].update(status="approved", authority="available")
    lab = ApprovalLab(config(), tmp_path, client_factory=runtime.client)
    try:
        lab.snapshot(operation_id)
        result = wait(lab, operation_id, {"succeeded"})
        assert result["choice_source"] == "status_poll"
        assert runtime.continued == [operation_id]
        assert runtime.resolved == []
    finally:
        lab.close()


def test_wrong_status_binding_never_continues(tmp_path):
    runtime = Runtime()
    lab = ApprovalLab(config(), tmp_path, client_factory=runtime.client)
    try:
        operation_id = lab.start("confirm")["operation_id"]
        wait(lab, operation_id, {"waiting_for_review"})
        runtime.wrong_binding = True
        lab.resolve(operation_id, "approve")
        assert wait(lab, operation_id, {"blocked"})["error"] == "review_status_binding_mismatch"
        assert runtime.continued == []
    finally:
        lab.close()


def test_queued_reject_fences_inflight_approved_status_poll(tmp_path):
    runtime = Runtime()
    entered, release = threading.Event(), threading.Event()
    first = [True]
    def gated(state):
        client = runtime.client(state)
        read = client._request
        async def request(method, path):
            if first[0]:
                first[0] = False
                entered.set()
                assert release.wait(3)
            return await read(method, path)
        client._request = request
        return client
    lab = ApprovalLab(config(), tmp_path, client_factory=gated)
    try:
        operation_id = lab.start("confirm")["operation_id"]
        wait(lab, operation_id, {"waiting_for_review"})
        runtime.runs[operation_id].update(status="approved", authority="available")
        lab.snapshot(operation_id)
        assert entered.wait(3)
        lab.resolve(operation_id, "reject")
        release.set()
        value = wait(lab, operation_id, {"blocked"})
        assert value["choice"] == "reject"
        assert value["choice_recorded"] is False
        assert runtime.continued == []
    finally:
        release.set()
        lab.close()


def test_restart_after_sdk_completion_recovers_without_resend(tmp_path):
    runtime = Runtime()
    lab = ApprovalLab(config(), tmp_path, client_factory=runtime.client)
    operation_id = lab.start("escalate")["operation_id"]
    wait(lab, operation_id, {"waiting_for_review"})
    state = {**lab._state(operation_id), "status": "continuing", "choice": "approve", "choice_source": "local_html"}
    lab.graph.update_state(lab._cfg(operation_id), state, as_node="review")
    runtime.runs[operation_id]["execution"] = execution(operation_id, "escalate", "succeeded")
    save_private(lab._folder(state) / "journal.json", {"phase": "complete", "dispatch_attempted_at": "test"})
    lab.close()
    lab = ApprovalLab(config(), tmp_path, client_factory=runtime.client)
    try:
        lab.snapshot(operation_id)
        value = wait(lab, operation_id, {"succeeded"})
        assert value["operation_id"] == operation_id
        assert value["provider_attempts"] == 1
        lab.resolve(operation_id, "approve")
        assert runtime.continued == []
        assert runtime.resolved == []
    finally:
        lab.close()


def test_missing_journal_never_claims_zero_prior_attempts(tmp_path):
    runtime = Runtime()
    lab = ApprovalLab(config(), tmp_path, client_factory=runtime.client)
    try:
        operation_id = lab.start("confirm")["operation_id"]
        wait(lab, operation_id, {"waiting_for_review"})
        lab._folder(lab._state(operation_id)).joinpath("journal.json").unlink()
        assert lab.snapshot(operation_id, poll=False)["provider_attempts"] is None
        lab.resolve(operation_id, "approve")
        # A real SDK refuses missing journals; the adapter should refuse even
        # before a resolver/API effect, including with a permissive test client.
        assert wait(lab, operation_id, {"blocked"})["error"] == "sdk_journal_unavailable"
        assert runtime.continued == []
        assert runtime.resolved == []
    finally:
        lab.close()


def test_unexpected_initial_allow_is_refused_before_provider(tmp_path, monkeypatch):
    result = execution("html-review-" + "0" * 32, "confirm", "approved")
    called = []
    async def unexpected_allow(self, **kwargs):
        return result
    monkeypatch.setattr(Allowly, "prepare_execution", unexpected_allow)
    monkeypatch.setattr("allowly.execution._provider_send", lambda *_: called.append("provider"))
    async def run():
        async with ReviewOnlyClient("test", base_url="http://127.0.0.1:1", dangerously_allow_insecure_base_url=True,
                                    expected_kind="confirm", capture_review=lambda _: called.append("capture")) as client:
            await client.execute_http(TARGET_URL, operation_id=result.operation_id, authorization_id="auth_confirm",
                                      enabled_executable_id="exe_github", catalog_operation_id="github.issues.list",
                                      action="github.read", storage_dir=str(tmp_path))
    with pytest.raises(AllowlyProtocolError, match="configured review"):
        asyncio.run(run())
    assert called == []
