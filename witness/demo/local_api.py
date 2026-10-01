"""Run the real Allowly API against a private, isolated localhost demo database.

This seeds a public GitHub read permission, not a mock decision handler. Receipt
signing is deliberately off: the UI must distinguish pending Allowly receipts
from verification of the native TLS witness evidence.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import secrets
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from witness_config import TEST_KEY_VERSION, WORKSPACE_ID, workspace_key


def write_private_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")
    temporary.replace(path)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8811)
    parser.add_argument("--repository", default="octocat/Hello-World")
    parser.add_argument("--witness-url", required=True)
    parser.add_argument("--notary-public-key", type=Path, required=True)
    parser.add_argument("--notary-fingerprint", required=True)
    parser.add_argument("--witness-key-version", required=True)
    parser.add_argument("--local-test-signer", action="store_true")
    parser.add_argument("--verifier-bin", type=Path, required=True)
    parser.add_argument("--init-only", action="store_true")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("--repository must be an owner/repository name")
    if not re.fullmatch(r"[0-9a-f]{64}", args.notary_fingerprint):
        parser.error("--notary-fingerprint must be 64 lowercase hex characters")
    try:
        args.witness_key_ref, args.kms_project, args.kms_location, args.witness_key_ring = workspace_key(args.witness_key_version)
    except ValueError as exc:
        parser.error(str(exc))
    if args.local_test_signer and args.witness_key_version != TEST_KEY_VERSION:
        parser.error("--local-test-signer requires the dedicated test key version")
    args.state_dir = args.state_dir.expanduser().resolve()
    args.notary_public_key = args.notary_public_key.expanduser().resolve(strict=True)
    args.verifier_bin = args.verifier_bin.expanduser().resolve(strict=True)
    if not args.notary_public_key.is_file():
        parser.error("--notary-public-key must be a file")
    if not args.verifier_bin.is_file() or not os.access(args.verifier_bin, os.X_OK):
        parser.error("--verifier-bin must be an executable file")
    return args


def configure(args: argparse.Namespace) -> dict:
    os.umask(0o077)
    args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(args.state_dir, 0o700)
    secret_path = args.state_dir / "runtime-secrets.json"
    if secret_path.exists():
        secret_values = json.loads(secret_path.read_text())
        os.chmod(secret_path, 0o600)
    else:
        secret_values = {
            "hmac_secret": secrets.token_urlsafe(48),
            "api_key_lookup_secret": secrets.token_urlsafe(48),
            "internal_token": secrets.token_urlsafe(48),
        }
        write_private_json(secret_path, secret_values)

    # Explicit settings prevent an inherited shell environment from selecting a
    # production database, cloud secrets, Redis, signing, or evidence storage.
    db_url = f"sqlite+aiosqlite:///{args.state_dir / 'runtime.db'}"
    os.environ.update({
        "APP_ENV": "dev",
        "ALLOWLY_RUNTIME_ROLE": "api",
        "ALLOWLY_API_WORKERS": "1",
        "ALLOWLY_SHARD_ID": "s001",
        "DATABASE_URL": db_url,
        "WORKER_DATABASE_URL": db_url,
        "MIGRATION_DATABASE_URL": db_url,
        "REDIS_URL": "",
        "GCP_SECRETS_ENABLED": "false",
        "ENABLE_CRON": "false",
        "ENABLE_KMS_SIGNING": "false",
        "ENABLE_BIGQUERY_WRITE": "false",
        "ENABLE_RECEIPT_EVIDENCE_WRITE": "false",
        "ENABLE_RECEIPT_DELETION_EXECUTOR": "false",
        "ALLOWLY_HMAC_SECRET": secret_values["hmac_secret"],
        "API_KEY_LOOKUP_SECRET": secret_values["api_key_lookup_secret"],
        "ALLOWLY_INTERNAL_TOKEN": secret_values["internal_token"],
        "ALLOWLY_API_BASE_URL": f"http://127.0.0.1:{args.port}",
        "ALLOWLY_ISSUER_NAME": "Allowly localhost demo (unsigned receipts)",
        "ALLOWLY_CONTROL_PLANE_BASE_URL": "",
        "CORS_ALLOWED_ORIGINS": "",
        "ALLOWLY_WITNESS_URL": args.witness_url,
        "ALLOWLY_WITNESS_VERIFIER_BIN": str(args.verifier_bin),
        "GCP_PROJECT_ID": args.kms_project,
        "KMS_LOCATION": args.kms_location,
        "KMS_KEY_RING": args.witness_key_ring + "-unused-receipts",
        "WITNESS_KMS_KEY_RING": args.witness_key_ring,
    })
    os.environ.pop("ALLOWLY_WITNESS_NOTARY_PUBLIC_KEY_FILE", None)
    os.environ.pop("ALLOWLY_WITNESS_NOTARY_KEY_FINGERPRINT_SHA256", None)
    api_root = Path(__file__).resolve().parents[3] / "allowly-api"
    if not (api_root / "app/main.py").is_file():
        raise RuntimeError(f"The sibling Allowly API checkout is missing: {api_root}")
    sys.path.insert(0, str(api_root))
    return secret_values


async def seed(args: argparse.Namespace, secret_values: dict) -> dict:
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.ext.compiler import compiles

    # The runtime uses PostgreSQL JSONB. SQLite is sufficient for this single
    # process demo; its locking behavior is not a production concurrency test.
    @compiles(JSONB, "sqlite")
    def compile_jsonb_sqlite(_type, _compiler, **_kwargs):
        return "JSON"

    from app.config import settings
    from app.database import AsyncSessionLocal, engine
    from app.models import (
        ActionDefinition,
        AgentPolicy,
        ApiKey,
        Authorization,
        Base,
        EnabledExecutable,
        SealActivation,
        Workspace,
    )
    from app.services import executable_catalog
    from app.services.signing import api_key_lookup_digest, mint_api_key

    settings.validate_runtime()
    config_path = args.state_dir / "runtime-config.json"
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        if config_path.exists():
            config = json.loads(config_path.read_text())
            if (config["repository"] != args.repository
                    or config.get("witness_kms_key_ref") != args.witness_key_ref
                    or config.get("trusted_notary_key_fingerprint_sha256") != args.notary_fingerprint
                    or config.get("local_test_signer") != args.local_test_signer):
                raise RuntimeError("Demo configuration changed; choose a new private --state-dir")
            authorization = await db.get(Authorization, config["authorization_id"])
            if authorization is None or "api_key" not in secret_values:
                raise RuntimeError("Demo state is incomplete; choose a new --state-dir")
            expiry = authorization.expires_at.replace(tzinfo=timezone.utc)
            if expiry <= datetime.now(timezone.utc):
                raise RuntimeError("Demo authorization expired; choose a new --state-dir")
            config["api_base_url"] = settings.allowly_api_base_url
            config["witness_url"] = args.witness_url
            write_private_json(config_path, config)
            await engine.dispose()
            return config

        workspace_id = WORKSPACE_ID
        authorization_id = "auth_local_github_read"
        enabled_id = "exe_local_github"
        policy_id = "policy_local_github_read"
        agent_id = "local-demo-agent"
        action = "github.issues.list"
        resource = f"github:{args.repository}"
        provider = executable_catalog.provider("github-rest")
        snapshot = executable_catalog.enabled_snapshot(provider, origin="https://api.github.com")
        operation = next(item for item in snapshot["operations"] if item["operation_id"] == action)
        actions = [{
            "name": action,
            "constraints": {"resource_pattern": resource},
            "executable_operations": [{
                "enabled_executable_id": enabled_id,
                "provider_id": provider["provider_id"],
                "operation_id": action,
                "catalog_revision": executable_catalog.catalog_revision(),
                "definition_fingerprint": operation["definition_fingerprint"],
                "minimum_evidence_mode": "witnessed",
            }],
        }]
        raw_key, prefix = mint_api_key(env="test")
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=1)
        db.add(Workspace(
            id=workspace_id, name="Local GitHub witness demo",
            kms_key_ref="local-demo-no-receipt-signer", billing_exempt=True,
            witness_kms_key_ref=args.witness_key_ref,
        ))
        await db.flush()
        db.add_all([
            ApiKey(id="key_local_demo", workspace_id=workspace_id, prefix=prefix,
                   lookup_digest=api_key_lookup_digest(raw_key), role="runtime"),
            ActionDefinition(id="action_local_github_read", workspace_id=workspace_id,
                             name=action, description="Read public GitHub issues"),
            AgentPolicy(id=policy_id, workspace_id=workspace_id, agent_id=agent_id,
                        actions=actions, single_live_policy_exempt=True,
                        description="Local demo: witnessed read of one public repository"),
            Authorization(
                id=authorization_id, workspace_id=workspace_id, user_id="local-demo-user",
                agent_id=agent_id, policy_id=policy_id, actions=actions,
                requires_confirm_for=[], requires_escalation_for=[], requires_deny_for=[],
                escalation_targets={}, metadata_={}, expires_at=expires_at,
                authorization_provenance={
                    "grantor": {"kind": "unverified", "source": "runtime_api_key"},
                    "agent_identity": {"kind": "unverified", "source": "runtime_api_key"},
                },
            ),
            EnabledExecutable(
                id=enabled_id, workspace_id=workspace_id, provider_id=provider["provider_id"],
                provider_name=provider["provider_name"], category=provider["category"],
                catalog_revision=executable_catalog.catalog_revision(),
                origin=snapshot["origin"], definition_snapshot=snapshot,
            ),
            SealActivation(id=1, enabled=True),
        ])
        await db.commit()
        secret_values["api_key"] = raw_key
        write_private_json(args.state_dir / "runtime-secrets.json", secret_values)
        config = {
            "api_base_url": settings.allowly_api_base_url,
            "workspace_id": workspace_id,
            "authorization_id": authorization_id,
            "enabled_executable_id": enabled_id,
            "catalog_operation_id": action,
            "catalog_revision": executable_catalog.catalog_revision(),
            "definition_fingerprint": operation["definition_fingerprint"],
            "policy_id": policy_id,
            "action": action,
            "agent_id": agent_id,
            "identity_status": "unverified_runtime_api_key",
            "receipt_signing": "disabled_pending_receipts",
            "repository": args.repository,
            "request_url": f"https://api.github.com/repos/{args.repository}/issues?per_page=1",
            "policy_resource": resource,
            "witness_url": args.witness_url,
            "witness_kms_key_ref": args.witness_key_ref,
            "trusted_notary_key_fingerprint_sha256": args.notary_fingerprint,
            "local_test_signer": args.local_test_signer,
            "authorization_expires_at": expires_at.isoformat(),
        }
        write_private_json(config_path, config)
    await engine.dispose()
    return config


def install_local_test_signer(args: argparse.Namespace) -> None:
    """Replace KMS lookup only inside this isolated demo API process."""
    from app.services import execution_witness
    from app.services.witness_keys import WitnessKey
    from native_runner import _fingerprint

    trusted = json.loads(args.notary_public_key.read_text())
    if _fingerprint(trusted) != args.notary_fingerprint:
        raise RuntimeError("Local test trust key fingerprint mismatch")

    async def local_test_key(key_ref: str) -> WitnessKey:
        if key_ref != args.witness_key_ref:
            raise ValueError("Unexpected local test witness key")
        return WitnessKey(args.witness_key_version, args.notary_fingerprint, trusted)

    execution_witness.active_key = local_test_key


def main() -> None:
    args = arguments()
    secret_values = configure(args)
    config = asyncio.run(seed(args, secret_values))
    print(json.dumps({"demo": config, "config_path": str(args.state_dir / "runtime-config.json")}),
          flush=True)
    if not args.init_only:
        if args.local_test_signer:
            install_local_test_signer(args)
        import uvicorn
        from app.main import app

        uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
