"""Private configuration and identity checks for the existing-workspace demo."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from native_runner import _fingerprint
from witness_config import workspace_key

ROOT = Path(__file__).resolve().parents[1]
APP_DIR = ROOT.parent.parent / "allowly_app"
TARGET_RESOURCE = "github:octocat/Hello-World"
TARGET_ACTION = "github.issues.list"
PUBLIC_TEST_POINT = bytes.fromhex(
    "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
)
TOKEN_SCRIPT = """
import asyncio
import sys
from app.database import AsyncSessionLocal, engine
from app.services import auth0_management

async def main():
    workspace_id, subject, audience, issuer = sys.argv[1:]
    async with AsyncSessionLocal() as db:
        connector = await auth0_management.connector_for_workspace(db, workspace_id)
        if issuer != f"https://{connector.domain}/":
            raise RuntimeError("Auth0 tenant changed")
        generation, client_id, domain = connector.generation, connector.client_id, connector.domain
        client = await auth0_management.management_client(connector)
        token = await client.access_token_for_application(subject[:-8], audience)
        current = await auth0_management.connector_for_workspace(db, workspace_id)
        if (current.generation, current.client_id, current.domain) != (generation, client_id, domain):
            raise RuntimeError("Auth0 connector changed")
        sys.stdout.write(token)
    await engine.dispose()

asyncio.run(main())
"""


class ExistingWorkspaceError(RuntimeError):
    pass


def _private_json(path: Path) -> dict:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        with os.fdopen(os.open(path, flags), "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_size > 64 * 1024):
                raise ExistingWorkspaceError("Use an owner-only 0600 private JSON file")
            value = json.loads(stream.read(64 * 1024 + 1))
    except (OSError, ValueError, TypeError, UnicodeError) as exc:
        raise ExistingWorkspaceError("Private demo configuration is unavailable or invalid") from exc
    if not isinstance(value, dict):
        raise ExistingWorkspaceError("Private demo configuration must be a JSON object")
    return value


def _required(config: dict, name: str, *, maximum: int = 4096) -> str:
    value = config.get(name)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ExistingWorkspaceError(f"Private demo configuration needs {name}")
    return value


def load_config(path: Path) -> tuple[dict, dict, dict]:
    """Load a fixed read-only action. Never copy credentials into browser state."""
    private = _private_json(path)
    workspace_id = _required(private, "workspace_id", maximum=128)
    if not re.fullmatch(r"ws_[A-Za-z0-9_]+", workspace_id):
        raise ExistingWorkspaceError("Invalid workspace ID")
    api_url = _required(private, "api_base_url", maximum=256).rstrip("/")
    try:
        parsed = urlsplit(api_url)
        port = parsed.port
    except ValueError as exc:
        raise ExistingWorkspaceError("Invalid loopback API address") from exc
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or port is None
            or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise ExistingWorkspaceError("Existing-workspace API must be a loopback HTTP endpoint")
    config = {
        "existing_workspace": True,
        "workspace_id": workspace_id,
        "api_base_url": api_url,
        "authorization_id": _required(private, "authorization_id", maximum=128),
        "enabled_executable_id": _required(private, "enabled_executable_id", maximum=128),
        "agent_id": _required(private, "agent_id", maximum=128),
        "auth0_subject": _required(private, "auth0_subject", maximum=136),
        "auth0_issuer": _required(private, "auth0_issuer", maximum=256),
        "auth0_audience": _required(private, "auth0_audience", maximum=512),
        "policy_resource": TARGET_RESOURCE,
        "identity_status": "auth0_configured_pending_check",
        "local_test_signer": private.get("local_test_signer") is True,
    }
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}@clients", config["auth0_subject"]):
        raise ExistingWorkspaceError("Invalid Auth0 machine subject")
    issuer = urlsplit(config["auth0_issuer"])
    if (issuer.scheme != "https" or not issuer.hostname or issuer.path != "/"
            or issuer.query or issuer.fragment or issuer.username or issuer.password):
        raise ExistingWorkspaceError("Invalid Auth0 issuer")
    audience = urlsplit(config["auth0_audience"])
    if audience.scheme != "https" or not audience.hostname or audience.username or audience.password:
        raise ExistingWorkspaceError("Invalid Auth0 audience")
    version = _required(private, "witness_kms_key_version", maximum=512)
    try:
        key_ref, *_ = workspace_key(version, workspace_id)
    except ValueError as exc:
        raise ExistingWorkspaceError("Witness key does not belong to the workspace") from exc
    config["witness_kms_key_ref"] = key_ref
    config["witness_kms_key_version"] = version
    if config["local_test_signer"] and not version.startswith("projects/test-only/"):
        raise ExistingWorkspaceError("The local test signer needs an explicit test-only key version")
    trust_path = Path(_required(private, "trusted_key_file", maximum=1024))
    if not trust_path.is_absolute():
        raise ExistingWorkspaceError("Use an absolute trusted-key path")
    trusted_key = _private_json(trust_path)
    if type(trusted_key.get("alg")) is not int:
        raise ExistingWorkspaceError("The trusted key has an invalid algorithm")
    try:
        fingerprint = _fingerprint(trusted_key)
    except ValueError as exc:
        raise ExistingWorkspaceError("The trusted witness key is malformed") from exc
    if fingerprint != _required(private, "notary_fingerprint_sha256", maximum=64):
        raise ExistingWorkspaceError("The trusted witness key does not match its pinned fingerprint")
    if (config["local_test_signer"]
            and fingerprint != hashlib.sha256(PUBLIC_TEST_POINT).hexdigest()):
        raise ExistingWorkspaceError("The local test signer requires its public test key")
    config["trusted_notary_key_fingerprint_sha256"] = fingerprint
    credentials = {
        "api_key": _required(private, "api_key", maximum=4096),
        "internal_token": _required(private, "internal_token", maximum=4096),
    }
    return config, credentials, trusted_key


def verify_runtime_state(api, config: dict, trusted_key: dict) -> None:
    """Check live authorization, Auth0 binding and KMS key before any provider send."""
    workspace_id, agent_id = config["workspace_id"], config["agent_id"]
    page = api("/v1/authorizations?" + urlencode({"agent_id": agent_id, "limit": 100}))
    items = page.get("items") if isinstance(page, dict) else None
    if not isinstance(items, list):
        raise ExistingWorkspaceError("Could not check the live authorization")
    authorization = next(
        (item for item in items if isinstance(item, dict)
         and item.get("id") == config["authorization_id"]), None
    )
    if authorization is None or authorization.get("agent_id") != agent_id:
        raise ExistingWorkspaceError("The configured authorization is not active for this agent")
    actions = authorization.get("actions")
    if not isinstance(actions, list) or len(actions) != 1:
        raise ExistingWorkspaceError("The demo requires one narrow GitHub read permission")
    action = actions[0]
    operations = action.get("executable_operations") if isinstance(action, dict) else None
    if (not isinstance(action, dict) or action.get("name") != TARGET_ACTION
            or action.get("constraints") != {"resource_pattern": TARGET_RESOURCE}
            or not isinstance(operations, list) or len(operations) != 1
            or not isinstance(operations[0], dict)
            or operations[0].get("enabled_executable_id") != config["enabled_executable_id"]
            or operations[0].get("operation_id") != TARGET_ACTION
            or operations[0].get("minimum_evidence_mode") != "witnessed"):
        raise ExistingWorkspaceError("The authorization is not limited to this witnessed GitHub read")
    provenance = authorization.get("authorization_provenance")
    protected = provenance.get("protected_item") if isinstance(provenance, dict) else None
    identity = protected.get("identity") if isinstance(protected, dict) else None
    owner = protected.get("owner") if isinstance(protected, dict) else None
    if (not isinstance(identity, dict) or identity.get("mode") != "provider"
            or identity.get("provider") != "auth0" or protected.get("id") != agent_id
            or not isinstance(owner, dict) or owner.get("status") != "customer_declared"
            or not owner.get("account_user_id")
            or any(identity.get(name) != config["auth0_" + name]
                   for name in ("subject", "issuer", "audience"))):
        raise ExistingWorkspaceError("The authorization has no matching Auth0 identity snapshot")
    binding = api(
        f"/internal/workspaces/{workspace_id}/identity-bindings?" + urlencode({"agent_id": agent_id}),
        internal=True,
    )
    if (not isinstance(binding, dict) or binding.get("status") != "configured"
            or binding.get("provider") != "auth0" or binding.get("agent_id") != agent_id
            or binding.get("owner_account_user_id") != owner["account_user_id"]
            or identity.get("binding_id") != binding.get("binding_id")
            or any(binding.get(name) != config["auth0_" + name]
                   for name in ("subject", "issuer", "audience"))):
        raise ExistingWorkspaceError("The current Auth0 binding differs from the authorization")
    connection = api(f"/internal/workspaces/{workspace_id}/identity/auth0", internal=True)
    if (not isinstance(connection, dict) or connection.get("status") != "configured"
            or connection.get("issuer") != config["auth0_issuer"]
            or connection.get("audience") != config["auth0_audience"]):
        raise ExistingWorkspaceError("The workspace Auth0 connection changed")
    witness = api(f"/internal/workspaces/{workspace_id}/witness-key", internal=True)
    if (not isinstance(witness, dict) or witness.get("workspace_id") != workspace_id
            or witness.get("kms_key_version") != config["witness_kms_key_version"]
            or witness.get("fingerprint_sha256") != "sha256:" + config["trusted_notary_key_fingerprint_sha256"]
            or witness.get("public_key") != trusted_key):
        raise ExistingWorkspaceError("The workspace witness key differs from the trusted key")


def fetch_auth0_token(config: dict) -> str:
    """Ask the running local app to mint a short-lived token, never exposing its secret."""
    if not APP_DIR.is_dir():
        raise ExistingWorkspaceError("The local Allowly app is unavailable")
    try:
        result = subprocess.run(
            ["docker", "compose", "exec", "-T", "allowly-api", "/app/.venv/bin/python", "-c", TOKEN_SCRIPT,
             config["workspace_id"], config["auth0_subject"], config["auth0_audience"],
             config["auth0_issuer"]],
            cwd=APP_DIR, capture_output=True, text=True, timeout=75, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExistingWorkspaceError("The local Auth0 connection is unavailable") from exc
    token = result.stdout.strip()
    if (result.returncode != 0 or len(token) > 16 * 1024
            or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token)):
        raise ExistingWorkspaceError("The local Auth0 connection did not issue a usable token")
    return token
