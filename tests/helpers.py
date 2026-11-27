"""Shared unittest helpers."""
from __future__ import annotations

import os
import subprocess
import sys
import unittest

from pydotenvcage import DotenvCageError, audit_dotenv, parse_dotenv


def add_generated_test(cls, name, func):
    setattr(cls, name, func)


def expect_code(testcase, fn, code):
    try:
        fn()
    except DotenvCageError as exc:
        testcase.assertEqual(exc.code, code)
        return exc
    testcase.fail("expected " + code)


def expect_parse_code(testcase, input_data, code, **options):
    return expect_code(testcase, lambda: parse_dotenv(input_data, **options), code)


def expect_audit_code(testcase, input_data, code, **options):
    report = audit_dotenv(input_data, **options)
    testcase.assertIn(code, [finding.code for finding in report.findings])
    return report


def run_cli(args, input_bytes=None, cwd=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    return subprocess.run(
        [sys.executable, "-m", "pydotenvcage"] + list(args),
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
        env=env,
        check=False,
    )


def aws_fixture():
    return "A" + "KIA" + "0" * 16


def github_fixture():
    return "g" + "hp_" + "a" * 36


def stripe_fixture():
    return "s" + "k_" + "live_" + "a" * 20


def jwt_fixture():
    return "e" + "yJ" + "a" * 12 + "." + "b" * 18 + "." + "c" * 16


def private_key_fixture():
    return "-----BEGIN " + "PRIVATE KEY-----\nredacted\n-----END " + "PRIVATE KEY-----"


def database_url_fixture():
    return "postgres://appuser:apppass@db.internal:5432/appdb"
