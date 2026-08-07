import json
import os
from pathlib import Path
import unittest

from loom import Client, Denial, ResourceRef, _parse_response


class SDKShapeTests(unittest.TestCase):
    def test_shared_conformance_fixture(self):
        fixture_path = Path(__file__).resolve().parents[3] / "conformance" / "fixtures" / "execute-semantics.v1.json"
        fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
        self.assertEqual(fixture["schema_version"], 1)
        self.assertEqual(len(fixture["cases"]), 2)
        self.assertTrue(all(case["expected"]["allowed"] is False for case in fixture["cases"]))

    def test_response_parses_go_wire_shape(self):
        response = _parse_response(
            {
                "Allowed": False,
                "Decision": "deny",
                "Denial": {
                    "Reason": "approval_required",
                    "Step": "approval",
                    "Retryable": True,
                    "Hint": "obtain approval",
                },
            }
        )
        self.assertFalse(response.allowed)
        self.assertIsInstance(response.denial, Denial)
        self.assertEqual(response.denial.reason, "approval_required")
        self.assertTrue(response.denial.retryable)

    def test_request_models_are_json_safe(self):
        resource = ResourceRef(type="document", id="doc-1")
        self.assertEqual(resource.type, "document")
        self.assertEqual(json.loads(json.dumps({"resource": resource.__dict__}))["resource"]["id"], "doc-1")


@unittest.skipUnless(os.getenv("LOOM_CONTRACT_URL"), "contract server not configured")
class SDKContractTests(unittest.TestCase):
    def test_execute_contract(self):
        client = Client(
            base_url=os.environ["LOOM_CONTRACT_URL"],
            token=os.environ["LOOM_CONTRACT_TOKEN"],
        )
        response = client.call(
            os.environ["LOOM_CONTRACT_OPERATION"],
            boundary=os.environ["LOOM_CONTRACT_BOUNDARY"],
            input={},
        )
        self.assertTrue(response.allowed, response.denial)
        self.assertEqual(response.output.get("status"), "ok")
