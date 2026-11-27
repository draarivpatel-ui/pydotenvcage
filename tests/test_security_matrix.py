"""Generated security firewall matrix tests."""
from __future__ import annotations

import json
import unittest

from pydotenvcage import DANGEROUS_RUNTIME_KEYS, PROTOTYPE_KEYS, audit_dotenv, detect_secret_kinds, parse_dotenv

from helpers import add_generated_test, aws_fixture, database_url_fixture, expect_audit_code, expect_parse_code, github_fixture, jwt_fixture, private_key_fixture, stripe_fixture


class TestSecurityMatrix(unittest.TestCase):
    pass


def _make_dangerous(key):
    def test(self):
        expect_parse_code(self, key + "=x", "DANGEROUS_KEY", expand=False)
    return test


for key in DANGEROUS_RUNTIME_KEYS:
    add_generated_test(TestSecurityMatrix, "test_dangerous_exact_%s" % key, _make_dangerous(key))
    add_generated_test(TestSecurityMatrix, "test_dangerous_lower_%s" % key, _make_dangerous(key.lower()))
    mixed = "".join(ch.lower() if index % 2 == 0 else ch.upper() for index, ch in enumerate(key))
    add_generated_test(TestSecurityMatrix, "test_dangerous_mixed_%s" % key, _make_dangerous(mixed))


class TestKeyPolicy(unittest.TestCase):
    def test_explicitly_allowed_runtime_key(self):
        parsed = parse_dotenv("PATH=/safe/bin", expand=False, allow_runtime_keys=["PATH"])
        self.assertEqual(parsed.values["PATH"], "/safe/bin")

    def test_allow_all_runtime_keys_escape_hatch(self):
        parsed = parse_dotenv("NODE_OPTIONS=--max-old-space-size=128", expand=False, allow_runtime_keys=True)
        self.assertEqual(parsed.values["NODE_OPTIONS"], "--max-old-space-size=128")

    def test_runtime_escape_does_not_allow_prototype_key(self):
        expect_parse_code(self, "__proto__=x", "PROTOTYPE_KEY", expand=False, allow_runtime_keys=True)

    def test_same_value_duplicate_rejected(self):
        expect_parse_code(self, "A=1\nA=1", "DUPLICATE_KEY", expand=False)

    def test_three_duplicates_reported_twice(self):
        report = expect_audit_code(self, "A=1\nA=2\nA=3", "DUPLICATE_KEY", expand=False)
        self.assertEqual(len([item for item in report.findings if item.code == "DUPLICATE_KEY"]), 2)


def _make_prototype(key):
    def test(self):
        expect_parse_code(self, key + "=x", "PROTOTYPE_KEY", expand=False)
    return test


for key in list(PROTOTYPE_KEYS) + ["__A__", "__CUSTOM__", "__secret__", "__x9__"]:
    add_generated_test(TestSecurityMatrix, "test_prototype_%s" % key.replace("_", "u"), _make_prototype(key))


SUBSTITUTION_CASES = [
    ("unquoted dollar", "A=$(id)"),
    ("single quoted dollar", "A='$(id)'"),
    ("double quoted dollar", 'A="$(id)"'),
    ("comment dollar", "# $(id)\nA=1"),
    ("unquoted backtick", "A=`id`"),
    ("single quoted backtick", "A='`id`'"),
    ("double quoted backtick", 'A="`id`"'),
    ("comment backtick", "# `id`\nA=1"),
    ("empty substitution", "A=$()"),
    ("nested substitution", "A=$(echo $(id))"),
    ("substitution prefix", "A=x$(id)"),
    ("substitution suffix", "A=$(id)x"),
    ("substitution middle", "A=x$(id)y"),
    ("backtick prefix", "A=x`id`"),
    ("backtick suffix", "A=`id`x"),
    ("backtick middle", "A=x`id`y"),
]


def _make_substitution(input_data):
    def test(self):
        expect_parse_code(self, input_data, "COMMAND_SUBSTITUTION", expand=False)
    return test


for index, (name, input_data) in enumerate(SUBSTITUTION_CASES):
    add_generated_test(TestSecurityMatrix, "test_substitution_%02d" % index, _make_substitution(input_data))


class TestDollarAndDuplicates(unittest.TestCase):
    def test_ordinary_dollar_signs_allowed(self):
        parsed = parse_dotenv("A=$5\nB=price-$10\nC=\\${NOT_EXPANDED}", expand=False)
        self.assertEqual(parsed.values["A"], "$5")
        self.assertEqual(parsed.values["B"], "price-$10")


for key in ["A", "FIRST", "SECOND"]:
    def make_duplicate(key):
        def test(self):
            expect_parse_code(self, key + "=1\n" + key + "=2", "DUPLICATE_KEY", expand=False)
        return test
    add_generated_test(TestSecurityMatrix, "test_duplicate_%s" % key, make_duplicate(key))


SECRET_FIXTURES = [
    ("aws", aws_fixture(), "aws-access-key"),
    ("github", github_fixture(), "github-token"),
    ("stripe", stripe_fixture(), "stripe-key"),
    ("jwt", jwt_fixture(), "jwt"),
    ("private key", private_key_fixture(), "private-key"),
    ("database url", database_url_fixture(), "database-url-with-password"),
]


def _make_detector(value, kind):
    def test(self):
        self.assertIn(kind, detect_secret_kinds(value))
    return test


def _make_detector_embedded(value, kind):
    def test(self):
        self.assertIn(kind, detect_secret_kinds("prefix " + value + " suffix"))
    return test


def _make_audit_secret(value, context, severity):
    def test(self):
        report = expect_audit_code(self, "TOKEN=" + json.dumps(value), "SECRET_LIKE_VALUE", context=context, expand=False)
        finding = [item for item in report.findings if item.code == "SECRET_LIKE_VALUE"][0]
        self.assertEqual(finding.severity, severity)
    return test


for index, (name, value, kind) in enumerate(SECRET_FIXTURES):
    add_generated_test(TestSecurityMatrix, "test_detect_%02d" % index, _make_detector(value, kind))
    add_generated_test(TestSecurityMatrix, "test_detect_embedded_%02d" % index, _make_detector_embedded(value, kind))
    add_generated_test(TestSecurityMatrix, "test_audit_committed_%02d" % index, _make_audit_secret(value, "committed", "error"))
    add_generated_test(TestSecurityMatrix, "test_audit_example_%02d" % index, _make_audit_secret(value, "example", "error"))
    add_generated_test(TestSecurityMatrix, "test_audit_runtime_%02d" % index, _make_audit_secret(value, "runtime", "warning"))


NEGATIVE_SECRET_VALUES = [
    "",
    "placeholder",
    "paste-your-token-here",
    "not-a-token",
    "A" + "KIA" + "short",
    "g" + "hp_short",
    "s" + "k_live_short",
    "postgres://user@host/db",
    "postgres://user:@host/db",
    "https://example.com/no-credential",
    "-----BEGIN PUBLIC KEY-----",
]


def _make_negative(value):
    def test(self):
        self.assertEqual(detect_secret_kinds(value), ())
    return test


for index, value in enumerate(NEGATIVE_SECRET_VALUES):
    add_generated_test(TestSecurityMatrix, "test_secret_negative_%02d" % index, _make_negative(value))


class TestAuditBehavior(unittest.TestCase):
    def test_secret_detection_can_be_disabled(self):
        report = audit_dotenv("TOKEN=" + aws_fixture(), context="committed", detect_secrets=False, expand=False)
        self.assertNotIn("SECRET_LIKE_VALUE", [finding.code for finding in report.findings])

    def test_audit_sorts_findings_by_line(self):
        report = audit_dotenv("PATH=1\nA=1\n__proto__=2", expand=False)
        lines = [finding.line for finding in report.findings if finding.line is not None]
        self.assertEqual(lines, sorted(lines))

    def test_audit_reports_keys_without_values(self):
        report = audit_dotenv("A=secret-value\nB=2", expand=False)
        self.assertEqual(report.keys, ("A", "B"))
        self.assertNotIn("secret-value", repr(report))


if __name__ == "__main__":
    unittest.main()
