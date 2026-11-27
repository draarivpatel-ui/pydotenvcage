"""Regression tests for adversarial audit findings."""
from __future__ import annotations

import os
import re
import tempfile
import unittest
from pathlib import Path

from pydotenvcage import DotenvCageError, audit_dotenv, parse_dotenv, redact_input, safe_load
from pydotenvcage.diff import diff_dotenv
from pydotenvcage.schema import validate_schema
from pydotenvcage.file import read_dotenv_file_secure

from helpers import aws_fixture


class TestAdversarialRegressions(unittest.TestCase):
    def test_git_transport_keys_are_blocked(self):
        for key in ("GIT_SSH_COMMAND", "GIT_SSH", "GIT_ASKPASS", "SSH_ASKPASS", "GIT_EXEC_PATH"):
            with self.subTest(key=key):
                with self.assertRaises(DotenvCageError) as raised:
                    parse_dotenv(key + "=x", expand=False)
                self.assertEqual(raised.exception.code, "DANGEROUS_KEY")

    def test_object_introspection_keys_are_blocked(self):
        for key in ("toString", "valueOf", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString"):
            with self.subTest(key=key):
                with self.assertRaises(DotenvCageError) as raised:
                    parse_dotenv(key + "=x", expand=False)
                self.assertEqual(raised.exception.code, "PROTOTYPE_KEY")

    def test_case_variant_duplicate_rejected(self):
        with self.assertRaises(DotenvCageError) as raised:
            parse_dotenv("Alpha=1\nALPHA=2", expand=False)
        self.assertEqual(raised.exception.code, "DUPLICATE_KEY")

    def test_shadowed_duplicate_secret_is_audited(self):
        report = audit_dotenv("TOKEN=safe\nTOKEN=" + aws_fixture(), context="committed", expand=False)
        self.assertTrue(any(item.code == "SECRET_LIKE_VALUE" for item in report.findings))

    def test_redact_input_discloses_no_edge_characters(self):
        self.assertEqual(redact_input("guessable-secret-value"), "<redacted>")
        self.assertEqual(redact_input(""), "")
        self.assertEqual(redact_input(None), "")

    def test_redacted_diff_has_no_fingerprints_or_lengths(self):
        item = diff_dotenv("A=guessme1", "A=other").to_dict()["changed"][0]
        self.assertEqual(item, {"key": "A", "left": "<redacted>", "right": "<redacted>"})

    def test_backslash_expansion_parity(self):
        even = parse_dotenv("A=" + "\\" * 2 + "${B}\nB=x").values["A"]
        odd = parse_dotenv("A=" + "\\" * 3 + "${B}\nB=x").values["A"]
        self.assertEqual(even, "\\" * 2 + "x")
        self.assertEqual(odd, "\\" * 2 + "${B}")

    def test_expansion_bomb_fails_bounded(self):
        text = "A0=" + "x" * 8192 + "\n"
        for index in range(1, 13):
            text += "A%d=${A%d}${A%d}\n" % (index, index - 1, index - 1)
        with self.assertRaises(DotenvCageError) as raised:
            parse_dotenv(text)
        self.assertEqual(raised.exception.code, "EXPANSION_TOO_LARGE")

    def test_secure_file_read_rejects_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.env"
            outside.write_text("SAFE_VALUE=file-content\n")
            link = root / "linked.env"
            link.symlink_to(outside)
            with self.assertRaises(DotenvCageError):
                read_dotenv_file_secure(link)
            fifo = root / "input.fifo"
            os.mkfifo(fifo)
            with self.assertRaises(DotenvCageError) as raised:
                read_dotenv_file_secure(fifo)
            self.assertEqual(raised.exception.code, "IO_ERROR")

    def test_safe_load_rejects_symlink_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.env"
            outside.write_text("SAFE_VALUE=file-content\n")
            link = root / "linked.env"
            link.symlink_to(outside)
            with self.assertRaises(DotenvCageError):
                safe_load(str(link), input_type="path", target={})

    def test_secure_file_read_enforces_size_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "large.env"
            target.write_bytes(b"A=" + b"x" * 64 + b"\n")
            with self.assertRaises(DotenvCageError) as raised:
                read_dotenv_file_secure(target, max_bytes=16)
            self.assertEqual(raised.exception.code, "INPUT_TOO_LARGE")

    def test_compiled_schema_pattern_preserves_flags(self):
        schema = {"keys": {"MODE": {"type": "string", "pattern": re.compile("^prod$", re.IGNORECASE)}}}
        self.assertTrue(validate_schema({"MODE": "PROD"}, schema)["ok"])


if __name__ == "__main__":
    unittest.main()
