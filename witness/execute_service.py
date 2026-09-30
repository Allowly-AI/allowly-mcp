#!/usr/bin/env python3
"""Authenticated WebSocket bridge for one-shot native TLSNotary witnesses.

The bridge never receives HTTP plaintext or provider credentials. It claims an
already-approved execution session from the Allowly runtime, starts one native
witness with that trusted approval, and relays the native MPC byte stream.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import binascii
import contextlib
import dataclasses
import datetime as dt
import hashlib
import hmac
import http
import ipaddress
import json
import logging
import os
import pathlib
import re
import secrets
import shutil
import signal
import ssl
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any, Callable

from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.exceptions import ConnectionClosed
from websockets.http11 import Request, Response


NATIVE_PROFILE = "customer_held_tlsn_bundle_v1"
REQUEST_BINDING_VERIFICATION = "customer_held_bundle"
MAX_PREFLIGHT_BYTES = 4096
MAX_CLAIM_RESPONSE_BYTES = 256 * 1024
MAX_APPROVAL_FILE_BYTES = 128 * 1024
MAX_WS_MESSAGE_BYTES = 1024 * 1024
RELAY_CHUNK_BYTES = 64 * 1024

_SAFE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_APPROVAL_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_BARE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KMS_KEY_RING_NAME = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
_KMS_RESOURCE = re.compile(
    r"^projects/[^/\s]+/locations/[^/\s]+/keyRings/[^/\s]+/"
    r"cryptoKeys/[^/\s]+/cryptoKeyVersions/[1-9][0-9]*$"
)
_CLAIM_FIELDS = frozenset(
    {
        "session_id",
        "operation_id",
        "workspace_id",
        "approval_sha256",
        "approval",
        "expires_at",
        "expected_server_name",
        "notary_kms_key_version",
        "trusted_notary_key_fingerprint_sha256",
        "native_profile",
        "request_binding_verification",
    }
)
_PREFLIGHT_FIELDS = frozenset({"session_id", "workspace_id", "admission_token"})

LOG = logging.getLogger("allowly.execute_witness_bridge")


class ConfigurationError(ValueError):
    pass


class ProtocolError(ValueError):
    pass


class ClaimError(RuntimeError):
    def __init__(self, category: str, status: int | None = None):
        super().__init__(category)
        self.category = category
        self.status = status


class NativeWitnessError(RuntimeError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError("duplicate JSON field")
        result[key] = value
    return result


def _strict_json(data: str | bytes) -> Any:
    try:
        return json.loads(data, object_pairs_hook=_strict_object)
    except ProtocolError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid JSON") from exc


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _env_int(
    env: Mapping[str, str], name: str, default: int, minimum: int, maximum: int
) -> int:
    raw = env.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _existing_file(path: str, *, executable: bool, name: str) -> pathlib.Path:
    try:
        result = pathlib.Path(path).expanduser().resolve(strict=True)
        mode = result.stat().st_mode
    except (OSError, RuntimeError) as exc:
        raise ConfigurationError(f"{name} must name an existing file") from exc
    if not stat.S_ISREG(mode):
        raise ConfigurationError(f"{name} must name a regular file")
    access = os.X_OK if executable else os.R_OK
    if not os.access(result, access):
        requirement = "executable" if executable else "readable"
        raise ConfigurationError(f"{name} must be {requirement}")
    return result


def _parse_listen(value: str) -> tuple[str, int]:
    try:
        parsed = urllib.parse.urlsplit(f"//{value}")
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError("ALLOWLY_WITNESS_LISTEN_ADDR is invalid") from exc
    if (
        not host
        or port is None
        or not 0 <= port <= 65535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigurationError("ALLOWLY_WITNESS_LISTEN_ADDR must be host:port")
    return host, port


def _is_literal_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_api_base_url(value: str, *, test_fixture: bool) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ConfigurationError("ALLOWLY_API_BASE_URL is invalid") from exc
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ConfigurationError("ALLOWLY_API_BASE_URL must be an origin URL")
    if test_fixture:
        if parsed.scheme != "http" or not _is_literal_loopback(parsed.hostname):
            raise ConfigurationError("test fixture API must be cleartext loopback HTTP")
    elif parsed.scheme != "https":
        raise ConfigurationError("production ALLOWLY_API_BASE_URL must use HTTPS")
    if port is not None and not 1 <= port <= 65535:
        raise ConfigurationError("ALLOWLY_API_BASE_URL has an invalid port")
    return value.rstrip("/")


@dataclasses.dataclass(frozen=True)
class BridgeConfig:
    api_base_url: str
    internal_token: str
    bridge_instance_id: str
    listen_host: str
    listen_port: int
    native_bin: pathlib.Path
    kms_key_version: str | None
    witness_kms_key_ring: str | None
    kms_python: pathlib.Path | None
    kms_helper: pathlib.Path | None
    tls_cert_file: pathlib.Path | None
    tls_key_file: pathlib.Path | None
    api_ca_cert_file: pathlib.Path | None = None
    preflight_timeout_seconds: int = 5
    claim_timeout_seconds: int = 10
    native_ready_timeout_seconds: int = 20
    session_timeout_seconds: int = 180
    drain_timeout_seconds: int = 180
    max_concurrent_sessions: int = 16
    test_fixture: bool = False
    allow_random_test_signer: bool = False

    def __post_init__(self) -> None:
        if not self.test_fixture and self.kms_key_version is not None:
            raise ConfigurationError("production witness key must come from the runtime claim")
        if not self.test_fixture and self.witness_kms_key_ring is None:
            raise ConfigurationError("WITNESS_KMS_KEY_RING is required in production")
        if self.witness_kms_key_ring is not None and not _KMS_KEY_RING_NAME.fullmatch(
            self.witness_kms_key_ring
        ):
            raise ConfigurationError("WITNESS_KMS_KEY_RING must be a KMS key ring name")

    @classmethod
    def from_env(
        cls, env: Mapping[str, str] | None = None, *, test_fixture: bool = False
    ) -> "BridgeConfig":
        values = os.environ if env is None else env
        project = pathlib.Path(__file__).resolve().parent
        api_base = _validate_api_base_url(
            values.get("ALLOWLY_API_BASE_URL", ""), test_fixture=test_fixture
        )
        internal_token = values.get("ALLOWLY_INTERNAL_TOKEN", "")
        if not 32 <= len(internal_token) <= 4096 or any(
            ord(char) < 0x21 or ord(char) > 0x7E for char in internal_token
        ):
            raise ConfigurationError("ALLOWLY_INTERNAL_TOKEN is missing or invalid")
        instance_id = values.get("ALLOWLY_WITNESS_BRIDGE_INSTANCE_ID", "")
        if not _SAFE_ID.fullmatch(instance_id):
            raise ConfigurationError(
                "ALLOWLY_WITNESS_BRIDGE_INSTANCE_ID must be 1..128 safe characters"
            )

        host, port = _parse_listen(
            values.get("ALLOWLY_WITNESS_LISTEN_ADDR", "127.0.0.1:8765")
        )
        native_bin = _existing_file(
            values.get(
                "ALLOWLY_WITNESS_NATIVE_BIN",
                str(project / "target" / "release" / "allowly-witness-poc"),
            ),
            executable=True,
            name="ALLOWLY_WITNESS_NATIVE_BIN",
        )

        cert_raw = values.get("ALLOWLY_WITNESS_TLS_CERT_FILE", "")
        key_raw = values.get("ALLOWLY_WITNESS_TLS_KEY_FILE", "")
        if bool(cert_raw) != bool(key_raw):
            raise ConfigurationError("both witness TLS certificate and key are required")
        cert = (
            _existing_file(cert_raw, executable=False, name="ALLOWLY_WITNESS_TLS_CERT_FILE")
            if cert_raw
            else None
        )
        key = (
            _existing_file(key_raw, executable=False, name="ALLOWLY_WITNESS_TLS_KEY_FILE")
            if key_raw
            else None
        )
        api_ca_raw = values.get("ALLOWLY_API_CA_CERT_FILE", "")
        api_ca_cert = (
            _existing_file(api_ca_raw, executable=False, name="ALLOWLY_API_CA_CERT_FILE")
            if api_ca_raw
            else None
        )
        if cert is None and not _is_literal_loopback(host):
            raise ConfigurationError("cleartext witness listener must bind to loopback")

        if (
            "ALLOWLY_WITNESS_NOTARY_SIGNING_KEY" in values
            or "ALLOWLY_WITNESS_NOTARY_KEY_FINGERPRINT_SHA256" in values
        ):
            raise ConfigurationError(
                "witness key version and fingerprint must come from the trusted runtime claim"
            )
        kms_python: pathlib.Path | None = None
        kms_helper: pathlib.Path | None = None
        if test_fixture:
            if cert is not None:
                raise ConfigurationError(
                    "fixture mode cannot use production KMS or direct TLS configuration"
                )
            if api_ca_cert is not None:
                raise ConfigurationError("fixture mode cannot use a production API CA")
            if not _is_literal_loopback(host):
                raise ConfigurationError("fixture listener must bind to loopback")
        else:
            kms_python = _existing_file(
                values.get("ALLOWLY_WITNESS_KMS_PYTHON", str(project / ".venv/bin/python")),
                executable=True,
                name="ALLOWLY_WITNESS_KMS_PYTHON",
            )
            kms_helper = _existing_file(
                values.get("ALLOWLY_WITNESS_KMS_HELPER", str(project / "kms/gcp_signer.py")),
                executable=False,
                name="ALLOWLY_WITNESS_KMS_HELPER",
            )

        return cls(
            api_base_url=api_base,
            internal_token=internal_token,
            bridge_instance_id=instance_id,
            listen_host=host,
            listen_port=port,
            native_bin=native_bin,
            kms_key_version=None,
            witness_kms_key_ring=values.get("WITNESS_KMS_KEY_RING") or None,
            kms_python=kms_python,
            kms_helper=kms_helper,
            tls_cert_file=cert,
            tls_key_file=key,
            api_ca_cert_file=api_ca_cert,
            preflight_timeout_seconds=_env_int(
                values, "ALLOWLY_WITNESS_PREFLIGHT_TIMEOUT_SECONDS", 5, 1, 30
            ),
            claim_timeout_seconds=_env_int(
                values, "ALLOWLY_WITNESS_CLAIM_TIMEOUT_SECONDS", 10, 1, 30
            ),
            native_ready_timeout_seconds=_env_int(
                values, "ALLOWLY_WITNESS_NATIVE_READY_TIMEOUT_SECONDS", 20, 1, 60
            ),
            session_timeout_seconds=_env_int(
                values, "ALLOWLY_WITNESS_SESSION_TIMEOUT_SECONDS", 180, 30, 600
            ),
            drain_timeout_seconds=_env_int(
                values, "ALLOWLY_WITNESS_DRAIN_TIMEOUT_SECONDS", 180, 1, 600
            ),
            max_concurrent_sessions=_env_int(
                values, "ALLOWLY_WITNESS_MAX_CONCURRENT_SESSIONS", 16, 1, 128
            ),
            test_fixture=test_fixture,
            # The native --local-test-key is random for each process. This
            # explicit CLI-only fixture mode cannot pre-provision that key and
            # therefore bypasses only the claim/readiness equality check.
            allow_random_test_signer=test_fixture,
        )

    def ssl_context(self) -> ssl.SSLContext | None:
        if self.tls_cert_file is None or self.tls_key_file is None:
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.tls_cert_file, self.tls_key_file)
        return context


@dataclasses.dataclass(frozen=True)
class Preflight:
    session_id: str
    workspace_id: str
    admission_token: str

    @classmethod
    def parse(cls, message: str | bytes, path_session_id: str) -> "Preflight":
        if not isinstance(message, str):
            raise ProtocolError("preflight must be text JSON")
        if len(message.encode("utf-8")) > MAX_PREFLIGHT_BYTES:
            raise ProtocolError("preflight exceeds limit")
        value = _strict_json(message)
        if not isinstance(value, dict) or frozenset(value) != _PREFLIGHT_FIELDS:
            raise ProtocolError("preflight fields are invalid")
        session_id = value.get("session_id")
        workspace_id = value.get("workspace_id")
        token = value.get("admission_token")
        if not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id):
            raise ProtocolError("session ID is invalid")
        if not isinstance(workspace_id, str) or not _SAFE_ID.fullmatch(workspace_id):
            raise ProtocolError("workspace ID is invalid")
        if session_id != path_session_id:
            raise ProtocolError("path and preflight session differ")
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            raise ProtocolError("admission token is invalid")
        try:
            decoded = base64.urlsafe_b64decode(token + "=")
        except (ValueError, binascii.Error) as exc:
            raise ProtocolError("admission token is invalid") from exc
        if len(decoded) != 32:
            raise ProtocolError("admission token is invalid")
        return cls(session_id=session_id, workspace_id=workspace_id, admission_token=token)


def _rfc3339(value: str) -> dt.datetime:
    if not isinstance(value, str) or len(value) > 64:
        raise ClaimError("invalid_response")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        result = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ClaimError("invalid_response") from exc
    if result.tzinfo is None:
        raise ClaimError("invalid_response")
    return result.astimezone(dt.timezone.utc)


def _visible_ascii(value: Any, *, maximum: int) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= maximum and all(
        0x20 <= ord(char) <= 0x7E for char in value
    )


@dataclasses.dataclass(frozen=True)
class Claim:
    session_id: str
    operation_id: str
    workspace_id: str
    approval_sha256: str
    approval: dict[str, Any]
    expires_at: str
    expected_server_name: str
    notary_kms_key_version: str
    trusted_notary_key_fingerprint_sha256: str

    @classmethod
    def parse(
        cls,
        value: Any,
        preflight: Preflight,
        witness_kms_key_ring: str | None,
    ) -> "Claim":
        if not isinstance(value, dict) or frozenset(value) != _CLAIM_FIELDS:
            raise ClaimError("invalid_response")
        if value.get("session_id") != preflight.session_id:
            raise ClaimError("invalid_response")
        if value.get("workspace_id") != preflight.workspace_id:
            raise ClaimError("invalid_response")
        if value.get("native_profile") != NATIVE_PROFILE:
            raise ClaimError("invalid_response")
        if value.get("request_binding_verification") != REQUEST_BINDING_VERIFICATION:
            raise ClaimError("invalid_response")
        operation_id = value.get("operation_id")
        if not _visible_ascii(operation_id, maximum=128):
            raise ClaimError("invalid_response")
        approval_sha = value.get("approval_sha256")
        if not isinstance(approval_sha, str) or not _APPROVAL_SHA256.fullmatch(approval_sha):
            raise ClaimError("invalid_response")
        fingerprint = value.get("trusted_notary_key_fingerprint_sha256")
        if not isinstance(fingerprint, str) or not _BARE_SHA256.fullmatch(fingerprint):
            raise ClaimError("invalid_response")
        kms_key_version = value.get("notary_kms_key_version")
        if not isinstance(kms_key_version, str) or not _KMS_RESOURCE.fullmatch(
            kms_key_version
        ):
            raise ClaimError("invalid_response")
        key_parts = kms_key_version.split("/")
        if witness_kms_key_ring is not None and key_parts[5] != witness_kms_key_ring:
            raise ClaimError("invalid_response")
        key_name = key_parts[7]
        if key_name != f"{preflight.workspace_id}-tlsnotary":
            raise ClaimError("invalid_response")
        approval = value.get("approval")
        if not isinstance(approval, dict):
            raise ClaimError("invalid_response")
        if approval.get("profile") != "allowly.execution.approval.v1":
            raise ClaimError("invalid_response")
        if approval.get("evidence_mode") != "witnessed":
            raise ClaimError("invalid_response")
        expires_at = value.get("expires_at")
        expires = _rfc3339(expires_at)
        if expires <= dt.datetime.now(dt.timezone.utc):
            raise ClaimError("invalid_response")
        if approval.get("expires_at") != expires_at:
            raise ClaimError("invalid_response")
        server_name = value.get("expected_server_name")
        if (
            not isinstance(server_name, str)
            or len(server_name) > 253
            or server_name.lower() != server_name
            or "." not in server_name
            or any(
                not label
                or len(label) > 63
                or label.startswith("-")
                or label.endswith("-")
                or not all(char.isascii() and (char.islower() or char.isdigit() or char == "-") for char in label)
                for label in server_name.split(".")
            )
        ):
            raise ClaimError("invalid_response")
        request = approval.get("request")
        if not isinstance(request, dict) or request.get("origin") != f"https://{server_name}":
            raise ClaimError("invalid_response")
        return cls(
            session_id=preflight.session_id,
            operation_id=operation_id,
            workspace_id=preflight.workspace_id,
            approval_sha256=approval_sha,
            approval=approval,
            expires_at=expires_at,
            expected_server_name=server_name,
            notary_kms_key_version=kms_key_version,
            trusted_notary_key_fingerprint_sha256=fingerprint,
        )

    def approval_file_bytes(self) -> bytes:
        encoded = _json_bytes(
            {"approval_sha256": self.approval_sha256, "approval": self.approval}
        )
        if len(encoded) > MAX_APPROVAL_FILE_BYTES:
            raise ClaimError("invalid_response")
        return encoded


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class RuntimeClaimClient:
    def __init__(self, config: BridgeConfig):
        self.config = config
        handlers: list[Any] = [_NoRedirect()]
        if config.api_ca_cert_file is not None:
            try:
                context = ssl.create_default_context(cafile=str(config.api_ca_cert_file))
            except (OSError, ssl.SSLError) as exc:
                raise ConfigurationError("ALLOWLY_API_CA_CERT_FILE is not a valid CA") from exc
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self._opener = urllib.request.build_opener(*handlers)

    def claim(self, preflight: Preflight) -> Claim:
        path = f"/internal/execution-witness/sessions/{preflight.session_id}/claim"
        body = _json_bytes(
            {
                "admission_token": preflight.admission_token,
                "bridge_instance_id": self.config.bridge_instance_id,
                "native_profile": NATIVE_PROFILE,
            }
        )
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(16)
        body_sha256 = hashlib.sha256(body).hexdigest()
        canonical = "\n".join(
            [
                "POST",
                path,
                "",
                preflight.workspace_id,
                timestamp,
                nonce,
                body_sha256,
            ]
        ).encode("utf-8")
        signature = hmac.new(
            self.config.internal_token.encode("utf-8"), canonical, hashlib.sha256
        ).hexdigest()
        request = urllib.request.Request(
            self.config.api_base_url + path,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-Allowly-Internal-Workspace": preflight.workspace_id,
                "X-Allowly-Internal-Timestamp": timestamp,
                "X-Allowly-Internal-Nonce": nonce,
                "X-Allowly-Internal-Signature": signature,
            },
        )
        try:
            with self._opener.open(
                request, timeout=self.config.claim_timeout_seconds
            ) as response:
                if response.status != http.HTTPStatus.OK:
                    raise ClaimError("http_rejected", response.status)
                content_type = response.headers.get_content_type()
                if content_type != "application/json":
                    raise ClaimError("invalid_response")
                encoded = response.read(MAX_CLAIM_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as exc:
            status = exc.code
            exc.close()
            raise ClaimError("http_rejected", status) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ClaimError("unavailable") from None
        if len(encoded) > MAX_CLAIM_RESPONSE_BYTES:
            raise ClaimError("invalid_response")
        try:
            value = _strict_json(encoded)
        except ProtocolError as exc:
            raise ClaimError("invalid_response") from exc
        return Claim.parse(value, preflight, self.config.witness_kms_key_ring)


def _private_dir() -> pathlib.Path:
    path = pathlib.Path(tempfile.mkdtemp(prefix="allowly-execution-witness-"))
    os.chmod(path, 0o700)
    return path


def _write_private(path: pathlib.Path, contents: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600)


def _read_private(path: pathlib.Path, maximum: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > maximum:
            raise NativeWitnessError("unsafe native output file")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            data = source.read(maximum + 1)
    finally:
        os.close(descriptor)
    if len(data) > maximum:
        raise NativeWitnessError("native output file exceeds limit")
    return data


@dataclasses.dataclass(frozen=True)
class NativeReady:
    host: str
    port: int
    fingerprint: str


@dataclasses.dataclass
class _ActiveSession:
    connection: ServerConnection
    state: str = "connected"
    child: asyncio.subprocess.Process | None = None


class WitnessBridgeService:
    def __init__(
        self,
        config: BridgeConfig,
        *,
        claim_client: RuntimeClaimClient | None = None,
        subprocess_factory: Callable[..., Any] = asyncio.create_subprocess_exec,
    ):
        self.config = config
        self.claim_client = claim_client or RuntimeClaimClient(config)
        self._subprocess_factory = subprocess_factory
        self._server: Server | None = None
        self._draining = False
        self._active: dict[ServerConnection, _ActiveSession] = {}
        self._active_lock = asyncio.Lock()
        self._all_done = asyncio.Event()
        self._all_done.set()

    @property
    def draining(self) -> bool:
        return self._draining

    @property
    def bound_port(self) -> int:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("bridge has not started")
        return int(self._server.sockets[0].getsockname()[1])

    async def start(self) -> Server:
        if self._server is not None:
            raise RuntimeError("bridge already started")
        self._server = await serve(
            self._handle_connection,
            self.config.listen_host,
            self.config.listen_port,
            ssl=self.config.ssl_context(),
            origins=[None],
            compression=None,
            process_request=self._process_request,
            open_timeout=self.config.preflight_timeout_seconds,
            ping_interval=20,
            ping_timeout=20,
            close_timeout=5,
            max_size=MAX_WS_MESSAGE_BYTES,
            max_queue=(4, 2),
            write_limit=RELAY_CHUNK_BYTES,
            server_header=None,
        )
        return self._server

    async def _process_request(
        self, connection: ServerConnection, request: Request
    ) -> Response | None:
        if request.path == "/healthz":
            status = http.HTTPStatus.SERVICE_UNAVAILABLE if self._draining else http.HTTPStatus.OK
            response = connection.respond(status, "draining\n" if self._draining else "ok\n")
            response.headers["Cache-Control"] = "no-store"
            return response
        if self._draining:
            return connection.respond(http.HTTPStatus.SERVICE_UNAVAILABLE, "draining\n")
        session_id = self._path_session_id(request.path)
        if session_id is None:
            return connection.respond(http.HTTPStatus.NOT_FOUND, "not found\n")
        return None

    @staticmethod
    def _path_session_id(path: str) -> str | None:
        if "?" in path or "#" in path or not path.startswith("/sessions/"):
            return None
        session_id = path.removeprefix("/sessions/")
        if not _SESSION_ID.fullmatch(session_id):
            return None
        return session_id

    async def _reserve(self, connection: ServerConnection) -> bool:
        async with self._active_lock:
            if self._draining or len(self._active) >= self.config.max_concurrent_sessions:
                return False
            self._active[connection] = _ActiveSession(connection)
            self._all_done.clear()
            return True

    async def _begin_claim(self, connection: ServerConnection) -> bool:
        async with self._active_lock:
            active = self._active.get(connection)
            if active is None or self._draining:
                return False
            active.state = "claiming"
            return True

    async def _set_claimed(self, connection: ServerConnection) -> None:
        async with self._active_lock:
            active = self._active.get(connection)
            if active is not None:
                active.state = "claimed"

    async def _set_child(
        self, connection: ServerConnection, child: asyncio.subprocess.Process
    ) -> None:
        async with self._active_lock:
            active = self._active.get(connection)
            if active is not None:
                active.child = child

    async def _release(self, connection: ServerConnection) -> None:
        async with self._active_lock:
            self._active.pop(connection, None)
            if not self._active:
                self._all_done.set()

    async def _handle_connection(self, connection: ServerConnection) -> None:
        if not await self._reserve(connection):
            await self._safe_close(connection, 1013, "witness capacity unavailable")
            return
        try:
            await asyncio.wait_for(
                self._run_session(connection),
                timeout=self.config.session_timeout_seconds,
            )
        except ProtocolError:
            LOG.info("event=session_rejected category=protocol")
            await self._safe_close(connection, 1008, "invalid witness session")
        except ClaimError as exc:
            LOG.info("event=session_rejected category=claim status=%s", exc.status or 0)
            code = 1013 if exc.status == 503 or exc.category == "unavailable" else 1008
            await self._safe_close(connection, code, "witness admission failed")
        except asyncio.TimeoutError:
            LOG.warning("event=session_failed category=deadline")
            await self._safe_close(connection, 1011, "session deadline; outcome unknown")
        except (NativeWitnessError, ConnectionError, OSError):
            LOG.warning("event=session_failed category=native")
            await self._safe_close(connection, 1011, "witness unavailable; outcome unknown")
        except ConnectionClosed:
            LOG.info("event=session_closed category=peer")
        except Exception:
            # Exception text can contain peer-controlled protocol values. Keep
            # logs categorical even for an unexpected implementation error.
            LOG.error("event=session_failed category=internal")
            await self._safe_close(connection, 1011, "witness unavailable; outcome unknown")
        finally:
            active = self._active.get(connection)
            if active is not None and active.child is not None:
                await self._stop_child(active.child)
            await self._release(connection)

    async def _run_session(self, connection: ServerConnection) -> None:
        request = connection.request
        path_session_id = self._path_session_id(request.path if request else "")
        if path_session_id is None:
            raise ProtocolError("invalid session path")
        first = await asyncio.wait_for(
            connection.recv(), timeout=self.config.preflight_timeout_seconds
        )
        preflight = Preflight.parse(first, path_session_id)
        if not await self._begin_claim(connection):
            await self._safe_close(connection, 1012, "service draining")
            return
        claim = await asyncio.to_thread(self.claim_client.claim, preflight)
        await self._set_claimed(connection)
        private_dir = _private_dir()
        child: asyncio.subprocess.Process | None = None
        try:
            approval_path = private_dir / "execution-approval.json"
            public_key_path = private_dir / "notary-public-key.json"
            ready_path = private_dir / "native-ready.json"
            _write_private(approval_path, claim.approval_file_bytes())
            child = await self._start_native(
                approval_path=approval_path,
                public_key_path=public_key_path,
                ready_path=ready_path,
                claim=claim,
            )
            await self._set_child(connection, child)
            ready = await self._wait_native_ready(child, ready_path, public_key_path, claim)
            try:
                reader, writer = await asyncio.open_connection(ready.host, ready.port)
            except OSError as exc:
                raise NativeWitnessError("native listener unavailable") from exc
            await connection.send(_json_bytes({"ready": True}).decode("utf-8"))
            await self._relay(connection, reader, writer, child)
        finally:
            if child is not None:
                await self._stop_child(child)
            try:
                shutil.rmtree(private_dir)
            except OSError:
                LOG.error("event=private_cleanup_failed")

    def _native_arguments(
        self,
        *,
        approval_path: pathlib.Path,
        public_key_path: pathlib.Path,
        ready_path: pathlib.Path,
        claim: Claim,
    ) -> list[str]:
        arguments = [
            str(self.config.native_bin),
            "witness",
            "--execution-approval",
            str(approval_path),
            "--listen",
            "127.0.0.1:0",
            "--public-key",
            str(public_key_path),
            "--ready-file",
            str(ready_path),
        ]
        if self.config.test_fixture:
            arguments.append("--fixture")
            if self.config.kms_key_version is None:
                arguments.append("--local-test-key")
            elif self.config.kms_python is not None and self.config.kms_helper is not None:
                # Test code may inject the repository's deterministic fake-KMS
                # helper so the real prover can start with a pre-trusted key.
                arguments.extend(
                    [
                        "--kms-key-version",
                        claim.notary_kms_key_version,
                        "--kms-python",
                        str(self.config.kms_python),
                        "--kms-helper",
                        str(self.config.kms_helper),
                    ]
                )
            else:
                raise NativeWitnessError("incomplete fixture signer configuration")
        else:
            if (
                self.config.kms_python is None
                or self.config.kms_helper is None
            ):
                raise NativeWitnessError("missing production signer configuration")
            arguments.extend(
                [
                    "--kms-key-version",
                    claim.notary_kms_key_version,
                    "--kms-python",
                    str(self.config.kms_python),
                    "--kms-helper",
                    str(self.config.kms_helper),
                ]
            )
        return arguments

    async def _start_native(
        self,
        *,
        approval_path: pathlib.Path,
        public_key_path: pathlib.Path,
        ready_path: pathlib.Path,
        claim: Claim,
    ) -> asyncio.subprocess.Process:
        child_env = dict(os.environ)
        for name in (
            "ALLOWLY_INTERNAL_TOKEN",
            "ALLOWLY_API_BASE_URL",
            "ALLOWLY_API_CA_CERT_FILE",
            "ALLOWLY_WITNESS_NOTARY_SIGNING_KEY",
            "ALLOWLY_WITNESS_NOTARY_KEY_FINGERPRINT_SHA256",
            "ALLOWLY_WITNESS_TLS_CERT_FILE",
            "ALLOWLY_WITNESS_TLS_KEY_FILE",
        ):
            child_env.pop(name, None)
        try:
            return await self._subprocess_factory(
                *self._native_arguments(
                    approval_path=approval_path,
                    public_key_path=public_key_path,
                    ready_path=ready_path,
                    claim=claim,
                ),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                cwd=pathlib.Path(__file__).resolve().parent,
                env=child_env,
                start_new_session=True,
            )
        except OSError as exc:
            raise NativeWitnessError("native witness could not start") from exc

    async def _wait_native_ready(
        self,
        child: asyncio.subprocess.Process,
        ready_path: pathlib.Path,
        public_key_path: pathlib.Path,
        claim: Claim,
    ) -> NativeReady:
        deadline = asyncio.get_running_loop().time() + self.config.native_ready_timeout_seconds
        last_invalid = False
        while asyncio.get_running_loop().time() < deadline:
            if ready_path.exists():
                try:
                    raw = _read_private(ready_path, 4096)
                    value = _strict_json(raw)
                    if not isinstance(value, dict) or frozenset(value) != {
                        "listen",
                        "signer_fingerprint_sha256",
                    }:
                        raise NativeWitnessError("invalid native readiness")
                    listen = value.get("listen")
                    fingerprint = value.get("signer_fingerprint_sha256")
                    if not isinstance(listen, str) or not _BARE_SHA256.fullmatch(
                        fingerprint if isinstance(fingerprint, str) else ""
                    ):
                        raise NativeWitnessError("invalid native readiness")
                    host, port = _parse_native_listen(listen)
                    _read_private(public_key_path, 4096)
                    if not self.config.allow_random_test_signer and not hmac.compare_digest(
                        fingerprint,
                        claim.trusted_notary_key_fingerprint_sha256,
                    ):
                        raise NativeWitnessError("native signer mismatch")
                    return NativeReady(host=host, port=port, fingerprint=fingerprint)
                except (FileNotFoundError, json.JSONDecodeError, ProtocolError):
                    last_invalid = True
            if child.returncode is not None:
                raise NativeWitnessError("native witness exited before readiness")
            await asyncio.sleep(0.02)
        if last_invalid:
            raise NativeWitnessError("native readiness was invalid")
        raise NativeWitnessError("native readiness timed out")

    async def _relay(
        self,
        connection: ServerConnection,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        child: asyncio.subprocess.Process,
    ) -> None:
        async def websocket_to_native() -> None:
            try:
                async for message in connection:
                    if not isinstance(message, bytes):
                        raise ProtocolError("relay messages must be binary")
                    if len(message) > MAX_WS_MESSAGE_BYTES:
                        raise ProtocolError("relay message exceeds limit")
                    writer.write(message)
                    await writer.drain()
            finally:
                with contextlib.suppress(OSError, RuntimeError):
                    writer.write_eof()

        async def native_to_websocket() -> None:
            while True:
                data = await reader.read(RELAY_CHUNK_BYTES)
                if not data:
                    break
                await connection.send(data)
            try:
                return_code = await asyncio.wait_for(child.wait(), timeout=5)
            except asyncio.TimeoutError as exc:
                raise NativeWitnessError("native witness did not exit") from exc
            if return_code != 0:
                raise NativeWitnessError("native witness failed")
            await self._safe_close(connection, 1000, "witness session complete")

        try:
            await asyncio.gather(websocket_to_native(), native_to_websocket())
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def begin_drain(self, timeout: float | None = None) -> None:
        if self._draining:
            return
        self._draining = True
        if self._server is not None:
            self._server.close(close_connections=False)
        async with self._active_lock:
            unclaimed = [
                active.connection
                for active in self._active.values()
                if active.state == "connected"
            ]
        await asyncio.gather(
            *(self._safe_close(item, 1012, "service draining") for item in unclaimed),
            return_exceptions=True,
        )
        try:
            await asyncio.wait_for(
                self._all_done.wait(),
                timeout=self.config.drain_timeout_seconds if timeout is None else timeout,
            )
        except asyncio.TimeoutError:
            async with self._active_lock:
                remaining = list(self._active.values())
            await asyncio.gather(
                *(
                    self._safe_close(
                        item.connection, 1012, "shutdown; execution outcome unknown"
                    )
                    for item in remaining
                ),
                return_exceptions=True,
            )
            await asyncio.gather(
                *(self._stop_child(item.child) for item in remaining if item.child is not None),
                return_exceptions=True,
            )
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._all_done.wait(), timeout=5)
        if self._server is not None:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._server.wait_closed(), timeout=5)

    @staticmethod
    async def _safe_close(connection: ServerConnection, code: int, reason: str) -> None:
        with contextlib.suppress(ConnectionClosed, OSError, RuntimeError):
            await connection.close(code=code, reason=reason)

    @staticmethod
    async def _stop_child(child: asyncio.subprocess.Process) -> None:
        if child.returncode is not None:
            with contextlib.suppress(Exception):
                await child.wait()
            return
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except (AttributeError, ProcessLookupError, PermissionError):
            with contextlib.suppress(ProcessLookupError):
                child.terminate()
        try:
            await asyncio.wait_for(child.wait(), timeout=3)
        except asyncio.TimeoutError:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except (AttributeError, ProcessLookupError, PermissionError):
                with contextlib.suppress(ProcessLookupError):
                    child.kill()
            with contextlib.suppress(Exception):
                await child.wait()


def _parse_native_listen(value: str) -> tuple[str, int]:
    match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", value)
    if match is None:
        raise NativeWitnessError("native listener is not loopback")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        raise NativeWitnessError("native listener port is invalid")
    return "127.0.0.1", port


async def _run(config: BridgeConfig) -> None:
    service = WitnessBridgeService(config)
    await service.start()
    shutdown = asyncio.Event()
    loop = asyncio.get_running_loop()
    installed: list[signal.Signals] = []
    for signum in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(signum, shutdown.set)
            installed.append(signum)
    scheme = "wss" if config.tls_cert_file else "ws"
    LOG.info("event=bridge_ready transport=%s", scheme)
    try:
        await shutdown.wait()
        LOG.info("event=bridge_draining")
        await service.begin_drain()
    finally:
        for signum in installed:
            with contextlib.suppress(NotImplementedError):
                loop.remove_signal_handler(signum)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--test-fixture",
        action="store_true",
        help="explicit loopback-only fixture mode using the native local test key",
    )
    parser.add_argument("--log-level", choices=("WARNING", "INFO"), default="INFO")
    args = parser.parse_args(argv)
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s %(message)s")
    try:
        config = BridgeConfig.from_env(test_fixture=args.test_fixture)
        asyncio.run(_run(config))
    except ConfigurationError as exc:
        LOG.error("event=configuration_failed reason=%s", exc)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
