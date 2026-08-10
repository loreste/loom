"""Assert package identity belongs to loreste/loom and avoids the conflict name."""

from __future__ import annotations

import sys
import tomllib
import unittest
from pathlib import Path

SDK_ROOT = Path(__file__).resolve().parents[1]
if str(SDK_ROOT) not in sys.path:
    sys.path.insert(0, str(SDK_ROOT))


class PackageIdentityTests(unittest.TestCase):
    def test_distribution_name_is_loreste_loom(self) -> None:
        data = tomllib.loads((SDK_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        project = data["project"]
        self.assertEqual(project["name"], "loreste-loom")
        self.assertNotEqual(project["name"], "loom-sdk")
        urls = project.get("urls") or {}
        repo = urls.get("Repository") or urls.get("repository") or ""
        self.assertIn("github.com/loreste/loom", repo)

    def test_import_package_remains_loom(self) -> None:
        import loom

        self.assertTrue(hasattr(loom, "Client"))

    def test_release_manifest_blocks_conflicting_pypi_name(self) -> None:
        manifest_path = Path(__file__).resolve().parents[3] / "release-manifest.json"
        text = manifest_path.read_text(encoding="utf-8")
        self.assertIn('"distribution": "loreste-loom"', text)
        self.assertIn('"blocked_name": "loom-sdk"', text)
        self.assertIn('"published": false', text)


if __name__ == "__main__":
    unittest.main()
