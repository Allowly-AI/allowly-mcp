"""Loopback listener for local or TLS-hosted approval continuation.

Run with Python SDK 0.7.0 and a runtime supporting native continuation.
Local review is customer-declared; hosted mode waits for configured external
review behind an authenticated HTTPS reverse proxy. Receipt mode has no TLS witness.
LangGraph checkpoints are private; the SDK journal remains the no-resend gate.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from allowly import Allowly, NativeAgentCredential
from allowly.error import AllowlyAPIError, AllowlyProtocolError
from allowly.execution import ExecutionRecoveryRequired
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command, interrupt

TARGET_URL = "https://api.github.com/repos/octocat/Hello-World/issues?per_page=1&state=all&sort=created&direction=asc"
HEADERS = {"accept": "application/vnd.github+json", "user-agent": "Allowly-Approval-HTML-Lab"}
REVIEWER_NOTE = "Customer-declared local HTML reviewer; not a verified human identity."
OPERATION_RE = re.compile(r"html-review-[0-9a-f]{32}")
TERMINAL = {"succeeded", "failed", "rejected", "unknown", "blocked"}


class LabError(RuntimeError):
    def __init__(self, code, status=409):
        self.code, self.status = code, status
        super().__init__(code)


def private_json(path):
    """Do not follow a credential/config symlink or accept group-readable files."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Private files must belong to this user and have mode 0600")
        value = json.loads(source.read(128 * 1024 + 1))
    if not isinstance(value, dict):
        raise TypeError("Private configuration must be an object")
    return value


def save_private(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".approval-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as target:
            json.dump(value, target, allow_nan=False)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load_config(path):
    config = private_json(path)
    parsed = urlsplit(config.get("api_base_url", ""))
    external = config.get("external_review", False)
    if not isinstance(external, bool):
        raise ValueError("external_review must be a boolean")
    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or not parsed.hostname:
        raise ValueError("Use a runtime origin without credentials, path, query or fragment")
    if external:
        if parsed.scheme != "https":
            raise ValueError("External review requires an HTTPS Allowly runtime")
        origin = urlsplit(config.get("public_origin", ""))
        if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password
                or origin.path or origin.query or origin.fragment):
            raise ValueError("External review requires an exact HTTPS public_origin")
        if config.get("edge_token"):
            raise ValueError("External review uses public runtime routing, not an origin edge token")
        auth_path = config.get("browser_auth_file", "")
        if not isinstance(auth_path, str) or not Path(auth_path).is_absolute():
            raise ValueError("External review requires an absolute browser_auth_file")
        auth = private_json(auth_path)
        username, password = auth.get("username"), auth.get("password")
        if (set(auth) != {"username", "password"} or not isinstance(username, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username)
                or not isinstance(password, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", password)
                or password == config.get("api_key")):
            raise ValueError("Use a dedicated browser user and fresh random URL-safe password of at least 32 characters")
        config["browser_auth"] = auth
    elif parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port:
        raise ValueError("Local review only uses an explicit loopback HTTP Allowly API")
    for key in ("api_key", "workspace_id", "enabled_executable_id", "action"):
        if not isinstance(config.get(key), str) or not config[key]:
            raise ValueError(f"Private configuration requires {key}")
    if set(config.get("scenarios", {})) != {"confirm", "escalate"}:
        raise ValueError("Configure exactly confirm and escalate scenarios")
    for scenario in config["scenarios"].values():
        if not isinstance(scenario.get("authorization_id"), str) or not scenario["authorization_id"]:
            raise ValueError("Each scenario needs its existing authorization_id")
        if not isinstance(scenario.get("context", {}), dict):
            raise TypeError("Each scenario context must be an object")
    return config


class ReviewOnlyClient(Allowly):
    """Reject an unexpected initial allow before execute_http can dispatch."""
    def __init__(self, *args, expected_kind, capture_review, **kwargs):
        super().__init__(*args, **kwargs)
        self.expected_kind, self.capture_review = expected_kind, capture_review

    async def prepare_execution(self, **kwargs):
        response = await super().prepare_execution(**kwargs)
        if (response.status != "waiting_for_review" or response.decision != self.expected_kind
                or response.review is None or response.review.kind != self.expected_kind):
            raise AllowlyProtocolError("The lab requires its configured review before any dispatch")
        self.capture_review(response)
        return response

    async def continue_execution(self, *args, **kwargs):
        response = await super().continue_execution(*args, **kwargs)
        if response.status == "waiting_for_review":
            self.capture_review(response)
        return response


class ApprovalLab:
    def __init__(self, config, state_dir, *, client_factory=None):
        self.config = config
        self.external_review = config.get("external_review", False)
        self.stop_monitor = threading.Event()
        self.monitor_thread = None
        self.state_dir = Path(state_dir).absolute()
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("Use an owner-only state directory, mode 0700")
        self.guard = os.open(self.state_dir / "adapter.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        database = self.state_dir / "checkpoints.sqlite"
        if database.is_symlink():
            raise ValueError("The checkpoint database cannot be a symlink")
        self.db = sqlite3.connect(database, check_same_thread=False)
        database.chmod(0o600)
        self.saver = SqliteSaver(self.db)
        self.csrf_token = secrets.token_urlsafe(32)
        self.lock = threading.RLock()
        self.inflight, self.pending, self.live, self.last_poll = {}, {}, {}, {}
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.client_factory = client_factory or self._client
        self.health_checked_at, self.ready = 0, False
        # This local graph must never export private request/nonce checkpoints.
        os.environ["LANGSMITH_TRACING"] = "false"
        os.environ["LANGCHAIN_TRACING_V2"] = "false"
        graph = StateGraph(dict)
        graph.add_node("prepare", self._prepare)
        graph.add_node("review", self._review)
        graph.add_node("finish", self._finish)
        graph.add_edge(START, "prepare")
        graph.add_conditional_edges("prepare", lambda value: "review" if value["status"] == "waiting_for_review" else END)
        graph.add_edge("review", "finish")
        graph.add_conditional_edges("finish", lambda value: "review" if value["status"] == "waiting_for_review" else END)
        self.graph = graph.compile(checkpointer=self.saver)

    def close(self):
        self.stop_monitor.set()
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        self.executor.shutdown(wait=True)
        self.db.close()
        os.close(self.guard)

    def start_monitor(self):
        """External approvals wake saved jobs even when no browser is open."""
        if not self.external_review or self.monitor_thread:
            return
        def monitor():
            while not self.stop_monitor.wait(5):
                for operation_id in self._job_ids():
                    if self.stop_monitor.is_set():
                        return
                    try:
                        self.snapshot(operation_id)
                    except (LabError, ValueError, TypeError):
                        pass  # Corrupt state is never permission to replace/send a job.
        self.monitor_thread = threading.Thread(target=monitor, daemon=True, name="approval-status")
        self.monitor_thread.start()

    def _cfg(self, operation_id):
        if not OPERATION_RE.fullmatch(operation_id):
            raise LabError("job_not_found", 404)
        return {"configurable": {"thread_id": operation_id}, "callbacks": []}

    def _state(self, operation_id):
        value = self.graph.get_state(self._cfg(operation_id)).values
        if not value:
            raise LabError("job_not_found", 404)
        return value

    def _folder(self, state):
        return self.state_dir / "sdk" / hashlib.sha256(state["operation_id"].encode()).hexdigest()

    def _journal(self, state):
        path = self._folder(state) / "journal.json"
        return json.loads(path.read_text()) if path.exists() else None

    def _client(self, state):
        def capture(response):
            # Capture before the SDK removes the bearer nonce from its journal.
            save_private(self.state_dir / (state["operation_id"] + ".review.json"), {
                "confirm_nonce": response.confirm_nonce, "review": asdict(response.review),
            })
        identity = {}
        if self.config.get("agent_credential_file"):
            credential = NativeAgentCredential(private_json(self.config["agent_credential_file"]))
            if (credential.workspace_id != self.config["workspace_id"]
                    or credential.agent_id != self.config.get("agent_id")):
                raise LabError("agent_identity_mismatch")
            identity["agent_token_supplier"] = credential.token
        elif self.config.get("agent_token"):
            identity["agent_token"] = self.config["agent_token"]
        return ReviewOnlyClient(self.config["api_key"], base_url=self.config["api_base_url"],
                                dangerously_allow_insecure_base_url=not self.external_review,
                                edge_token=self.config.get("edge_token"), expected_kind=state["scenario"],
                                capture_review=capture, **identity)

    def _original(self, scenario, operation_id):
        selected = self.config["scenarios"][scenario]
        return {"url": TARGET_URL, "operation_id": operation_id,
                "authorization_id": selected["authorization_id"],
                "enabled_executable_id": self.config["enabled_executable_id"],
                "catalog_operation_id": self.config.get("catalog_operation_id", "github.issues.list"),
                "action": self.config["action"], "method": "GET", "headers": HEADERS.copy(),
                "body": "", "evidence_mode": "receipt",
                "policy_input": {"resource": self.config.get("resource", "github:octocat/Hello-World"),
                                 "context": selected.get("context", {}).copy()}}

    def _arguments(self, state):
        # Refuse configuration/request changes on restart, before SDK/API effects.
        if state["request"] != self._original(state["scenario"], state["operation_id"]):
            raise LabError("original_request_changed")
        return {**state["request"], "storage_dir": str(self.state_dir / "sdk"), "timeout": 30.0}

    def _result(self, state, execution, response=None, outcome_pending=False):
        value = asdict(execution)
        value.pop("confirm_nonce", None)
        waiting = execution.status == "waiting_for_review"
        status = "waiting_for_review" if waiting else execution.status
        if status not in TERMINAL and not waiting:
            status = "unknown" if execution.target_state == "unknown" or outcome_pending else "blocked"
        old_review = state.get("execution", {}).get("review") or {}
        if waiting and old_review.get("id") != execution.review.id:
            self.live.pop(state["operation_id"], None)
        nonce = execution.confirm_nonce or (state.get("nonce") if not waiting or old_review.get("id") == execution.review.id else None)
        return {**state, "status": status, "execution": value,
                "nonce": nonce,
                "response_body": response["body"].encode()[:65536].decode(errors="replace") if response else state.get("response_body"),
                "response_truncated": bool(response and len(response["body"].encode()) > 65536),
                "provider_http_status": response["status"] if response else state.get("provider_http_status"),
                "outcome_pending": outcome_pending,
                "choice": None if waiting else state.get("choice"), "error": None}

    def _prepare(self, state):
        self._arguments(state)
        async def run():
            async with self.client_factory(state) as client:
                journal = self._journal(state)
                if journal:
                    if journal["phase"] not in {"waiting_for_review", "continuing"}:
                        return await self._recover(client, state, journal)
                    execution = await client.get_execution(state["operation_id"])
                    secret = self.state_dir / (state["operation_id"] + ".review.json")
                    saved_secret = private_json(secret) if secret.exists() else {}
                    nonce = saved_secret.get("confirm_nonce") if saved_secret.get("review", {}).get("id") == execution.review.id else execution.confirm_nonce
                    value = self._result(state, execution)
                    return {**value, "status": "waiting_for_review", "nonce": nonce}
                result = await client.execute_http(**self._arguments(state))
                if result.execution.status != "waiting_for_review":
                    raise LabError("expected_review_missing")
                return self._result(state, result.execution)
        return asyncio.run(run())

    def _review(self, state):
        choice = interrupt({"operation_id": state["operation_id"], "scenario": state["scenario"]})
        if not isinstance(choice, dict) or choice.get("choice") not in {"approve", "reject"}:
            raise LabError("invalid_review_choice", 400)
        return {**state, "choice": choice["choice"], "choice_source": choice.get("source", "local_html"),
                "status": "continuing"}

    async def _prompt_status(self, client, state):
        review = state["execution"]["review"]
        kind, review_id = review["kind"], review["id"]
        resource = client.confirmations if kind == "confirm" else client.escalations
        value = asdict(await resource.get_status(review_id))
        request = state["request"]
        if (value.get("confirmation_id" if kind == "confirm" else "escalation_id") != review_id
                or value.get("authorization_id") != request["authorization_id"]
                or value.get("action") != request["action"]
                or value.get("resource") != request["policy_input"]["resource"]
                or value.get("source_receipt_id") != review["source_receipt_id"]
                or value.get("status") not in {"pending", "approved", "rejected", "expired", "unknown"}):
            raise LabError("review_status_binding_mismatch")
        return value

    def _finish(self, state):
        self._arguments(state)
        async def run():
            async with self.client_factory(state) as client:
                journal = self._journal(state)
                if not journal:
                    raise LabError("sdk_journal_unavailable")
                if journal and journal["phase"] not in {"waiting_for_review", "continuing"}:
                    return await self._recover(client, state, journal)
                saved_review = (journal or {}).get("authorization", {}).get("review")
                if saved_review and saved_review["id"] != state["execution"]["review"]["id"]:
                    execution = await client.get_execution(state["operation_id"])
                    return self._result(state, execution)
                status = await self._prompt_status(client, state)
                expected = "approved" if state["choice"] == "approve" else "rejected"
                if state["choice_source"] == "local_html" and status["status"] == "pending":
                    if self.external_review:
                        raise LabError("external_review_required", 403)
                    review = state["execution"]["review"]
                    if review["kind"] == "confirm":
                        if not state.get("nonce"):
                            raise LabError("confirmation_nonce_unavailable")
                        await client.confirmations.approve(state["nonce"], approved=state["choice"] == "approve",
                                                          ttl_seconds=300, idempotency_key="resolve:" + state["operation_id"])
                    else:
                        await client.escalations.resolve(review["id"], resolution=expected,
                                                         resolved_by="local-html-reviewer", note=REVIEWER_NOTE)
                    status = await self._prompt_status(client, state)
                recorded = status["status"] == expected
                self.live[state["operation_id"]] = {
                    "approval_status": status["status"], "authority_status": status.get("authority_status"),
                    "resolution_receipt_id": status.get("resolution_receipt_id"), "choice_recorded": recorded,
                }
                result_state = {**state, "approval_status": status["status"],
                                "authority_status": status.get("authority_status"),
                                "resolution_receipt_id": status.get("resolution_receipt_id"), "choice_recorded": recorded}
                if state["choice"] == "reject" and status["status"] != "rejected":
                    return {**result_state, "status": "blocked", "error": "choice_already_recorded"}
                if status["status"] == "rejected":
                    return {**result_state, "status": "rejected", "error": None}
                review = state["execution"]["review"]
                intent = (journal or {}).get("continuation", {})
                own_consumed = (journal and journal["phase"] == "continuing"
                                and intent.get("review_id") == review["id"]
                                and intent.get("source_receipt_id") == review["source_receipt_id"]
                                and status.get("authority_status") == "consumed")
                if status["status"] != "approved" or not (status.get("authority_status") == "available" or own_consumed):
                    return {**result_state, "status": "blocked", "error": "review_not_available"}
                result = await client.continue_http_execution(**self._arguments(state))
                return self._result(result_state, result.execution, result.response, result.outcome_pending)
        return asyncio.run(run())

    async def _recover(self, client, state, journal):
        # Read-only reconciliation; never retry a provider send or dispatch claim.
        execution = await client.get_execution(state["operation_id"])
        value = self._result(state, execution, outcome_pending=journal["phase"] == "outcome_pending")
        if journal["phase"] in {"prepared", "authorized"}:
            return {**value, "status": "blocked", "error": "initial_prepare_recovery_required"}
        if journal["phase"] in {"dispatch_attempted", "outcome_pending"}:
            return {**value, "status": "unknown", "error": "outcome_recovery_required"}
        return value

    def _schedule(self, operation_id, action, choice=None):
        with self.lock:
            if operation_id in self.inflight:
                previous = self.inflight[operation_id] or self.pending.get(operation_id, (None, None))[1]
                if choice and previous not in {None, choice}:
                    raise LabError("choice_already_recorded")
                if choice and self.inflight[operation_id] is None:
                    self.pending[operation_id] = (action, choice)
                return
            self.inflight[operation_id] = choice
        def work():
            try:
                action()
            except Exception as exc:  # noqa: BLE001 - preserve private recovery state and never resend
                code = getattr(exc, "code", None)
                if not isinstance(code, str) or not re.fullmatch(r"[a-zA-Z0-9_]{1,128}", code):
                    code = "execution_recovery_required" if isinstance(exc, ExecutionRecoveryRequired) else "runtime_or_sdk_refused"
                state = self._state(operation_id)
                self.graph.update_state(self._cfg(operation_id), {**state, "status": "blocked", "error": code}, as_node="finish")
            finally:
                with self.lock:
                    self.inflight.pop(operation_id, None)
                    pending = self.pending.pop(operation_id, None)
                if pending:
                    self._schedule(operation_id, pending[0], pending[1])
        self.executor.submit(work)

    def start(self, scenario):
        with self.lock:
            return self._start(scenario)

    def _start(self, scenario):
        if scenario not in {"confirm", "escalate"}:
            raise LabError("invalid_scenario", 400)
        if len(self._job_ids()) >= 50:
            raise LabError("lab_capacity_reached", 429)
        operation_id = "html-review-" + uuid.uuid4().hex
        state = {"operation_id": operation_id, "scenario": scenario, "status": "starting",
                 "request": self._original(scenario, operation_id), "choice": None, "error": None,
                 "created_at": time.time(), "original_decision": scenario}
        self.graph.invoke(state, self._cfg(operation_id), interrupt_before=["prepare"])
        self._schedule(operation_id, lambda: self.graph.invoke(None, self._cfg(operation_id)))
        return self.snapshot(operation_id, poll=False)

    def resolve(self, operation_id, choice):
        if self.external_review:
            raise LabError("external_review_required", 403)
        if choice not in {"approve", "reject"}:
            raise LabError("invalid_review_choice", 400)
        state = self._state(operation_id)
        if state.get("choice") and state["choice"] != choice:
            raise LabError("choice_already_recorded")
        if state["status"] in TERMINAL:
            return self.snapshot(operation_id, poll=False)
        if state["status"] not in {"waiting_for_review", "continuing"}:
            raise LabError("review_not_ready")
        self._schedule(operation_id, lambda: self.graph.invoke(Command(resume={"choice": choice, "source": "local_html"}),
                                                               self._cfg(operation_id)), choice)
        return self.snapshot(operation_id, poll=False)

    def _poll(self, operation_id):
        state = self._state(operation_id)
        if state["status"] != "waiting_for_review":
            return
        async def read():
            async with self.client_factory(state) as client:
                return await self._prompt_status(client, state)
        try:
            status = asyncio.run(read())
        except (httpx.TransportError, AllowlyAPIError) as exc:
            if isinstance(exc, AllowlyAPIError) and exc.status not in {408, 429} and exc.status < 500:
                raise
            self.live[operation_id] = {"poll_error": "status_temporarily_unavailable"}
            return  # No permission or provider send; retry only this read later.
        self.live[operation_id] = {"approval_status": status["status"], "authority_status": status.get("authority_status"),
                                   "resolution_receipt_id": status.get("resolution_receipt_id")}
        if status["status"] in {"approved", "rejected"}:
            # A local choice admitted while this status read was in flight wins
            # this adapter's ordering. Do not auto-approve past a queued Reject.
            with self.lock:
                if operation_id in self.pending:
                    return
                self.inflight[operation_id] = "approve" if status["status"] == "approved" else "reject"
            self.graph.invoke(Command(resume={"choice": "approve" if status["status"] == "approved" else "reject",
                                               "source": "status_poll"}), self._cfg(operation_id))
        elif status["status"] in {"expired", "unknown"} or status.get("authority_status") in {"revoked", "expired", "unknown"}:
            self.graph.update_state(self._cfg(operation_id), {**state, "status": "blocked", "error": "review_not_available"}, as_node="finish")

    def snapshot(self, operation_id, *, poll=True):
        state = self._state(operation_id)
        if poll and state["status"] == "waiting_for_review" and time.monotonic() - self.last_poll.get(operation_id, 0) > 5:
            self.last_poll[operation_id] = time.monotonic()
            self._schedule(operation_id, lambda: self._poll(operation_id))
        elif poll and state["status"] in {"starting", "continuing"}:
            self._schedule(operation_id, lambda: self.graph.invoke(None, self._cfg(operation_id)))
        execution = state.get("execution", {})
        journal = self._journal(state)
        attempts = (int(bool(journal.get("dispatch_attempted_at") or journal.get("phase") in {"dispatch_attempted", "outcome_pending", "complete"} and journal.get("outcome")))
                    if journal else 0 if state["status"] == "starting" else None)
        decision_receipt = execution.get("decision_receipt") or {}
        outcome_receipt = (execution.get("outcome_evidence") or {}).get("receipt") or {}
        choice = state.get("choice") or self.inflight.get(operation_id) or self.pending.get(operation_id, (None, None))[1]
        live = self.live.get(operation_id, {})
        approval_status = live.get("approval_status", state.get("approval_status"))
        choice_recorded = bool(choice and approval_status == ("approved" if choice == "approve" else "rejected"))
        detail = ("Choice selected; checking the recorded review before continuation." if state["status"] == "continuing" else
                  "Waiting for a decision. No provider request has been sent." if state["status"] == "waiting_for_review" else
                  "Rejected. The GitHub request was not sent." if state["status"] == "rejected" else
                  "Provider response observed. Receipt mode records this customer's report, not a TLS witness." if state["status"] == "succeeded" else
                  "Do not retry this action. Inspect the original operation and saved SDK outcome." if state["status"] == "unknown" else
                  "The runtime or SDK stopped this operation before further dispatch." if state["status"] == "blocked" else "Preparing the fixed GitHub read.")
        return {"operation_id": operation_id, "scenario": state["scenario"], "status": state["status"],
                "external_review": self.external_review,
                "choice": choice, "choice_source": state.get("choice_source"), "review_identity": (
                    "Configured external review channel; this page does not establish reviewer identity."
                    if self.external_review else REVIEWER_NOTE),
                "choice_recorded": choice_recorded,
                "review": execution.get("review"), "decision": execution.get("decision"),
                "original_decision": state["original_decision"],
                "final_decision": execution.get("decision") if state["status"] in {"succeeded", "failed"} else None,
                "action": state["request"]["action"], "resource": state["request"]["policy_input"]["resource"],
                "policy_context": state["request"]["policy_input"]["context"], "target_url": TARGET_URL,
                "provider_attempts": attempts, "provider_attempts_note": "SDK journal send intent, not independent network proof.",
                "provider_http_status": state.get("provider_http_status"), "response_body": state.get("response_body"),
                "response_truncated": state.get("response_truncated", False),
                "decision_receipt_state": decision_receipt.get("status", "unavailable"),
                "decision_receipt_id": decision_receipt.get("receipt_id") or decision_receipt.get("receipt", {}).get("receipt_id"),
                "outcome_receipt_state": outcome_receipt.get("status", "unavailable"),
                "outcome_receipt_id": outcome_receipt.get("receipt_id") or outcome_receipt.get("receipt", {}).get("receipt_id"),
                "resolution_receipt_id": state.get("resolution_receipt_id"), "outcome_pending": state.get("outcome_pending", False),
                "error": state.get("error"), "detail": detail,
                **{key: value for key, value in live.items() if key != "choice_recorded"}}

    def status(self):
        if time.monotonic() - self.health_checked_at > 5:
            async def health():
                async with Allowly(self.config["api_key"], base_url=self.config["api_base_url"],
                                   dangerously_allow_insecure_base_url=not self.external_review) as client:
                    return await client.readiness()
            try:
                self.ready = asyncio.run(health())
            except Exception:  # noqa: BLE001 - any failed readiness check must disable the lab
                self.ready = False
            self.health_checked_at = time.monotonic()
        return {"lab_mode": "approval", "ready": self.ready, "csrf_token": self.csrf_token,
                "external_review": self.external_review,
                "target_url": TARGET_URL, "evidence_mode": "receipt", "review_identity": (
                    "Configured external review channel; this page does not establish reviewer identity."
                    if self.external_review else REVIEWER_NOTE),
                "jobs": [{**self.snapshot(operation_id), "response_body": None} for operation_id in self._job_ids()]}

    def _job_ids(self):
        ids = []
        for checkpoint in self.saver.list(None):
            operation_id = checkpoint.config["configurable"]["thread_id"]
            if operation_id not in ids:
                ids.append(operation_id)
            if len(ids) == 50:
                break
        return ids


def make_server(lab, port):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def send(self, code, value, content_type="application/json"):
            data = value if isinstance(value, bytes) else json.dumps(value).encode()
            self.send_response(code)
            if code == 401:
                self.send_header("WWW-Authenticate", 'Basic realm="Allowly execution lab", charset="UTF-8"')
            for name, header_value in {"Content-Type": content_type, "Content-Length": str(len(data)), "Cache-Control": "no-store",
                                "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'"}.items():
                self.send_header(name, header_value)
            self.end_headers()
            self.wfile.write(data)

        def local(self, *, mutation=False):
            origin = lab.config["public_origin"] if lab.external_review else f"http://127.0.0.1:{self.server.server_port}"
            return (self.headers.get("Host") == urlsplit(origin).netloc
                    and self.headers.get("Origin") in {None, origin}
                    and (not mutation or hmac.compare_digest(self.headers.get("X-Demo-Token", ""), lab.csrf_token)))

        def authenticated(self):
            if not lab.external_review:
                return True
            authorization = self.headers.get("Authorization", "")
            if not authorization.startswith("Basic ") or len(authorization) > 1024:
                return False
            try:
                credential = base64.b64decode(authorization[6:], validate=True)
            except (ValueError, binascii.Error):
                return False
            auth = lab.config["browser_auth"]
            return hmac.compare_digest(credential, (auth["username"] + ":" + auth["password"]).encode())

        def do_GET(self):
            if not self.authenticated():
                return self.send(401, {"error": "browser_auth_required"})
            if not self.local():
                return self.send(403, {"error": "invalid_local_request"})
            try:
                if self.path == "/":
                    return self.send(200, Path(__file__).with_name("index.html").read_bytes(), "text/html; charset=utf-8")
                if self.path == "/api/status":
                    return self.send(200, {"lab_mode": "approval", "ready": False, "target_url": TARGET_URL,
                                           "detail": "Use the approval continuation panel"})
                if self.path == "/api/approval-lab/status":
                    return self.send(200, lab.status())
                if self.path.startswith("/api/approval-lab/jobs/"):
                    return self.send(200, lab.snapshot(self.path.removeprefix("/api/approval-lab/jobs/")))
            except LabError as exc:
                return self.send(exc.status, {"error": exc.code})
            return self.send(404, {"error": "not_found"})

        def do_POST(self):
            if not self.authenticated():
                return self.send(401, {"error": "browser_auth_required"})
            if not self.local(mutation=True):
                return self.send(403, {"error": "invalid_local_request"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if (self.headers.get("Transfer-Encoding") or not 0 < length <= 4096
                        or self.headers.get_content_type() != "application/json"):
                    raise LabError("invalid_body", 400)
                value = json.loads(self.rfile.read(length))
                if not isinstance(value, dict):
                    raise LabError("invalid_body", 400)
                if self.path == "/api/approval-lab/jobs" and set(value) == {"scenario"}:
                    return self.send(202, lab.start(value["scenario"]))
                match = re.fullmatch(r"/api/approval-lab/jobs/(html-review-[0-9a-f]{32})/resolve", self.path)
                if match and set(value) == {"choice"}:
                    return self.send(202, lab.resolve(match[1], value["choice"]))
                raise LabError("invalid_request", 400)
            except LabError as exc:
                return self.send(exc.status, {"error": exc.code})
            except (ValueError, TypeError):
                return self.send(400, {"error": "invalid_body"})
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8812)
    args = parser.parse_args()
    lab = ApprovalLab(load_config(args.config), args.state_dir)
    server = make_server(lab, args.port)
    lab.start_monitor()
    print(f"Allowly approval lab: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        lab.close()


if __name__ == "__main__":
    main()
