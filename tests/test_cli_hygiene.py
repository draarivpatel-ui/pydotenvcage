"""CLI behavior, packaging metadata, and repository hygiene tests."""
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from helpers import run_cli

ROOT = Path(__file__).resolve().parents[1]


class TestCli(unittest.TestCase):
    def test_version_exits_zero(self):
        result = run_cli(["--version"], cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        self.assertIn(b"pydotenvcage 1.0.0", result.stdout)

    def test_usage_exits_two(self):
        result = run_cli([], cwd=ROOT)
        self.assertEqual(result.returncode, 2)

    def test_parse_redacts_values_by_default(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "input.env"
            path.write_text("PORT=8080\nHOST=localhost\n", encoding="utf-8")
            result = run_cli(["parse", str(path)], cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        payload = json.loads(result.stdout.decode("utf-8"))
        self.assertEqual(payload["values"]["PORT"], "<redacted>")

    def test_parse_show_values_is_explicit(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "input.env"
            path.write_text("PORT=8080\n", encoding="utf-8")
            result = run_cli(["parse", str(path), "--show-values"], cwd=ROOT)
        payload = json.loads(result.stdout.decode("utf-8"))
        self.assertEqual(payload["values"]["PORT"], "8080")

    def test_audit_safe_file_exits_zero(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "input.env"
            path.write_text("PORT=8080\n", encoding="utf-8")
            result = run_cli(["audit", str(path), "--json"], cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stdout.decode("utf-8", "replace"))
        self.assertTrue(json.loads(result.stdout.decode("utf-8"))["ok"])

    def test_audit_dangerous_file_exits_one(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "input.env"
            path.write_text("NODE_OPTIONS=--require=/tmp/x\n", encoding="utf-8")
            result = run_cli(["audit", str(path), "--json"], cwd=ROOT)
        self.assertEqual(result.returncode, 1)
        codes = [item["code"] for item in json.loads(result.stdout.decode("utf-8"))["findings"]]
        self.assertIn("DANGEROUS_KEY", codes)

    def test_redact_does_not_print_secret(self):
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "input.env"
            path.write_text("A=secret-value\n", encoding="utf-8")
            result = run_cli(["redact", str(path)], cwd=ROOT)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(b"secret-value", result.stdout)
        self.assertIn(b"A=<redacted>", result.stdout)

    def test_diff_exit_and_redaction(self):
        with tempfile.TemporaryDirectory() as scratch:
            left = Path(scratch) / "left.env"
            right = Path(scratch) / "right.env"
            left.write_text("A=1\nB=left\n", encoding="utf-8")
            right.write_text("A=1\nB=right\nC=3\n", encoding="utf-8")
            result = run_cli(["diff", str(left), str(right)], cwd=ROOT)
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout.decode("utf-8"))
        self.assertEqual(payload["added"], ["C"])
        self.assertEqual(payload["changed"][0]["left"], "<redacted>")

    def test_validate_schema_exits_zero(self):
        with tempfile.TemporaryDirectory() as scratch:
            env_path = Path(scratch) / "input.env"
            schema_path = Path(scratch) / "schema.json"
            env_path.write_text("PORT=8080\n", encoding="utf-8")
            schema_path.write_text(json.dumps({"required": ["PORT"], "keys": {"PORT": {"type": "integer", "min": 1, "max": 65535}}}), encoding="utf-8")
            result = run_cli(["validate", str(env_path), "--schema", str(schema_path)], cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        self.assertTrue(json.loads(result.stdout.decode("utf-8"))["ok"])


class TestRepositoryHygiene(unittest.TestCase):
    def tracked_files(self):
        result = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
        output = []
        for item in result.stdout.split(b"\x00"):
            if not item:
                continue
            relative = item.decode("utf-8")
            normalized = relative.replace("\\", "/")
            if "__pycache__" in normalized or normalized.endswith((".pyc", ".pyo")) or normalized.startswith(".git/"):
                continue
            output.append(relative)
        return output

    def read_tracked(self, relative):
        return (ROOT / relative).read_bytes()

    def test_index_is_populated(self):
        self.assertGreater(len(self.tracked_files()), 20)

    def test_no_em_or_en_dashes_in_tracked_files(self):
        bad = []
        for relative in self.tracked_files():
            data = self.read_tracked(relative)
            if b"\xe2\x80\x94" in data or b"\xe2\x80\x93" in data:
                bad.append(relative)
        self.assertEqual(bad, [])

    def test_no_local_user_paths_in_tracked_files(self):
        needle = ("/" + "Users" + "/").encode("utf-8")
        bad = []
        for relative in self.tracked_files():
            if needle in self.read_tracked(relative):
                bad.append(relative)
        self.assertEqual(bad, [])

    def test_no_coauthored_trailer_in_tracked_files(self):
        needle = ("Co-" + "Authored" + "-By:").encode("utf-8")
        bad = []
        for relative in self.tracked_files():
            if needle in self.read_tracked(relative):
                bad.append(relative)
        self.assertEqual(bad, [])

    def test_no_personal_mailbox_fragments_in_tracked_files(self):
        needles = [(b"@" + b"gmail" + b".com"), (b"@" + b"googlemail" + b".com")]
        bad = []
        for relative in self.tracked_files():
            data = self.read_tracked(relative).lower()
            if any(fragment in data for fragment in needles):
                bad.append(relative)
        self.assertEqual(bad, [])

    def test_no_tracked_bytecode_or_build_output(self):
        bad = []
        for relative in self.tracked_files():
            normalized = relative.replace("\\", "/")
            if "__pycache__" in normalized or normalized.endswith((".pyc", ".pyo")) or normalized.startswith(("build/", "dist/")) or ".egg-info/" in normalized:
                bad.append(relative)
        self.assertEqual(bad, [])

    def test_tracked_text_files_lf_only(self):
        bad = []
        for relative in self.tracked_files():
            data = self.read_tracked(relative)
            if b"\x00" in data:
                continue
            if b"\r" in data:
                bad.append(relative)
        self.assertEqual(bad, [])

    def test_pyproject_has_zero_runtime_dependencies(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("dependencies = []", text)
        self.assertIn('version = "1.0.0"', text)
        self.assertIn('requires-python = ">=3.9"', text)
        self.assertIn('pydotenvcage = "pydotenvcage.cli:main"', text)

    def test_publish_workflow_is_release_only_oidc(self):
        text = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
        self.assertIn("types: [published]", text)
        self.assertIn("id-token: write", text)
        self.assertIn("environment:", text)
        self.assertNotIn("workflow_dispatch", text)

    def test_ci_matrix_covers_python_39_through_313(self):
        text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn('"%s"' % version, text)
        self.assertIn("ubuntu-24.04", text)

    def test_distribution_checker_exists(self):
        self.assertTrue((ROOT / "scripts/check_dist.py").is_file())

    def test_examples_exist(self):
        for name in ("basic_load.py", "audit_and_redact.py", "schema_and_diff.py"):
            self.assertTrue((ROOT / "examples" / name).is_file())

    def test_py_typed_exists(self):
        self.assertTrue((ROOT / "src/pydotenvcage/py.typed").is_file())

    def test_tests_do_not_contain_complete_vendor_token_fixture_literals(self):
        forbidden = [
            "A" + "KIA" + "0" * 16,
            "g" + "hp_" + "a" * 36,
            "s" + "k_" + "live_" + "a" * 20,
        ]
        for relative in self.tracked_files():
            if not relative.startswith("tests/") or not relative.endswith(".py"):
                continue
            text = self.read_tracked(relative).decode("utf-8")
            for fragment in forbidden:
                self.assertNotIn(fragment, text, relative)


if __name__ == "__main__":
    unittest.main()
