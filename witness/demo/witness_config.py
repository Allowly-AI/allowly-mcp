"""Key names for the isolated local execution demo."""

from __future__ import annotations

import re

WORKSPACE_ID = "ws_local_witness_demo"
TEST_KEY_VERSION = (
    "projects/test-only/locations/global/keyRings/local-demo-witness/"
    f"cryptoKeys/{WORKSPACE_ID}-tlsnotary/cryptoKeyVersions/1"
)


def workspace_key(version: str, workspace_id: str = WORKSPACE_ID) -> tuple[str, str, str, str]:
    """Return the key ref only when its name belongs to the selected workspace."""
    if not re.fullmatch(r"ws_[A-Za-z0-9_]+", workspace_id):
        raise ValueError("Invalid witness workspace ID")
    match = re.fullmatch(
        rf"projects/([^/\s]+)/locations/([^/\s]+)/keyRings/([^/\s]+)/"
        rf"cryptoKeys/({re.escape(workspace_id)}-tlsnotary)/cryptoKeyVersions/([1-9][0-9]*)",
        version,
    )
    if match is None:
        raise ValueError(f"KMS version must belong to {workspace_id}-tlsnotary")
    return version.rsplit("/cryptoKeyVersions/", 1)[0], *match.group(1, 2, 3)
