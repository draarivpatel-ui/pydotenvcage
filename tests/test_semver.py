"""Bounded semantic-version schema behavior through the API and CLI."""
import json
import tempfile
import unittest
from pathlib import Path

from pydotenvcage import DotenvCageError, safe_load, validate_schema
from helpers import run_cli

SCHEMA = {"keys": {"RELEASE": {"type": "semver"}}}


class TestSemver(unittest.TestCase):
    def test_strict_versions_accept_core_prerelease_and_build_metadata(self):
        for value in ("0.0.0", "1.2.3", "1.2.3-alpha.1", "1.2.3+001", "1.2.3-0+build.7",
                      "1.2.3-" + "a" * 250):
            with self.subTest(value=value[:20]):
                self.assertTrue(validate_schema({"RELEASE": value}, SCHEMA)["ok"])

    def test_malformed_and_oversized_versions_fail_closed_without_loading(self):
        for value in ("", "1.2", "v1.2.3", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01",
                      "1.2.3-alpha..x", "1.2.3+", "1.2.3+build_1", "1.2.3\n", "１.2.3",
                      "1.2.3-" + "a" * 251):
            with self.subTest(value=value[:20]):
                target = {"UNCHANGED": "yes"}
                with self.assertRaises(DotenvCageError) as error:
                    validate_schema({"RELEASE": value}, SCHEMA)
                self.assertEqual(error.exception.code, "SCHEMA_VIOLATION")
                with self.assertRaises(DotenvCageError):
                    safe_load("RELEASE=" + json.dumps(value, ensure_ascii=False), schema=SCHEMA, target=target)
                self.assertEqual(target, {"UNCHANGED": "yes"})

    def test_cli_validation_handles_valid_and_invalid_versions(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            schema = Path(tmp) / "schema.json"
            schema.write_text(json.dumps(SCHEMA), encoding="utf-8")
            env = Path(tmp) / "config.env"
            for value, expected in (("1.2.3-rc.1+build.2", 0), ("1.2.3-01", 1)):
                env.write_text("RELEASE=" + value + "\n", encoding="utf-8")
                result = run_cli(["validate", str(env), "--schema", str(schema), "--json"], cwd=root)
                self.assertEqual(result.returncode, expected, result.stderr)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["ok"], expected == 0)
