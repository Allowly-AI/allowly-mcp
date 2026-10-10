"""The native demo uses fresh SDK identity tokens, not a cached Auth0 token."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from server import Demo


class NativeServerTest(unittest.TestCase):
    def test_native_wss_uses_supplier_and_keeps_catalog_separate_from_policy_action(self):
        calls = []
        credential = SimpleNamespace(token=lambda: "fresh-native-token")

        class Client:
            def __init__(self, key, **options):
                calls.append((key, options))

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_args):
                pass

            async def execute_http(self, url, **options):
                calls.append((url, options))
                return SimpleNamespace(
                    execution=SimpleNamespace(decision="deny", approval_sha256=None),
                    operation_dir="unused", response=None, outcome_pending=False,
                )

        module = ModuleType("allowly")
        module.Allowly = Client
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            trust = state / "public-key.json"
            trust.write_text(json.dumps({"alg": 2, "data": []}))
            config = {
                "existing_workspace": True, "identity_provider": "allowly",
                "workspace_id": "ws_s001_test", "agent_id": "demo4",
                "policy_action": "github.read", "policy_resource": "github:octocat/Hello-World",
                "api_base_url": "http://127.0.0.1:8085", "authorization_id": "auth_test",
                "enabled_executable_id": "exe_test", "local_test_signer": False,
            }
            demo = Demo(state, config, {"api_key": "test-key"}, trust, "gcloud", Path("unused"), sdk_wss=True)
            demo.runs["run-test"] = {"events": [], "timings_ms": {}}
            with (patch.dict(sys.modules, {"allowly": module}),
                  patch("server.verify_runtime_state"),
                  patch("server.load_native_credential", return_value=credential),
                  patch("server.fetch_auth0_token") as auth0,
                  patch("server.asdict", return_value={})):
                demo.run_sdk_wss("run-test")
                auth0.assert_not_called()
            self.assertIs(calls[0][1]["agent_token_supplier"], credential.token)
            self.assertEqual(calls[1][1]["action"], "github.read")
            self.assertEqual(calls[1][1]["catalog_operation_id"], "github.issues.list")
            self.assertIsNone(calls[1][1]["agent_token"])
            self.assertEqual(demo.snapshot("run-test")["stage"], "not_allowed")
            self.assertEqual(demo.snapshot("run-test")["identity_provider"], "allowly")


if __name__ == "__main__":
    unittest.main()
