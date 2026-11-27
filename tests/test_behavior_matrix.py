"""Generated schema, load, diff, and redaction tests."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from pydotenvcage import diff_dotenv, parse_dotenv, redact_dotenv, safe_load, validate_schema

from helpers import add_generated_test, expect_code


def schema_violation(testcase, values, schema):
    return expect_code(testcase, lambda: validate_schema(values, schema), "SCHEMA_VIOLATION")


class TestBehaviorMatrix(unittest.TestCase):
    pass


class TestSchemaBehavior(unittest.TestCase):
    def test_valid_strict_schema_passes(self):
        result = validate_schema({"PORT": "443", "MODE": "production"}, {
            "required": ["PORT"],
            "keys": {
                "PORT": {"type": "integer", "min": 1, "max": 65535},
                "MODE": {"type": "enum", "values": ["development", "production"]},
            },
        })
        self.assertTrue(result["ok"])
        self.assertEqual(result["validatedKeys"], 2)

    def test_integer_min_max(self):
        schema_violation(self, {"A": "0"}, {"keys": {"A": {"type": "integer", "min": 1}}})
        schema_violation(self, {"A": "65536"}, {"keys": {"A": {"type": "integer", "max": 65535}}})

    def test_url_protocol_allowlist(self):
        schema_violation(self, {"A": "http://example.com/"}, {"keys": {"A": {"type": "url", "protocols": ["https:"]}}})
        self.assertTrue(validate_schema({"A": "https://example.com/"}, {"keys": {"A": {"type": "url", "protocols": ["https:"]}}})["ok"])

    def test_string_bounds_pattern(self):
        schema_violation(self, {"A": "x"}, {"keys": {"A": {"type": "string", "minLength": 2}}})
        schema_violation(self, {"A": "xxx"}, {"keys": {"A": {"type": "string", "maxLength": 2}}})
        schema_violation(self, {"A": "abc"}, {"keys": {"A": {"type": "string", "pattern": "^[0-9]+$"}}})
        self.assertTrue(validate_schema({"A": "123"}, {"keys": {"A": {"type": "string", "pattern": "^[0-9]+$"}}})["ok"])

    def test_required_keys(self):
        schema_violation(self, {}, {"required": ["A"], "keys": {"A": {"type": "string"}}})
        schema_violation(self, {}, {"keys": {"A": {"type": "string", "required": True}}})
        schema_violation(self, {"A": ""}, {"keys": {"A": {"type": "string", "required": True}}})

    def test_empty_optional_allowed(self):
        self.assertTrue(validate_schema({"A": ""}, {"keys": {"A": {"type": "string", "allowEmpty": True}}})["ok"])

    def test_unknown_keys_default_and_opt_in(self):
        schema_violation(self, {"UNKNOWN": "x"}, {"keys": {}})
        self.assertTrue(validate_schema({"UNKNOWN": "x"}, {"keys": {}, "allowUnknown": True})["ok"])


def _make_valid_value(value, kind):
    def test(self):
        self.assertTrue(validate_schema({"A": value}, {"keys": {"A": {"type": kind}}})["ok"])
    return test


def _make_invalid_value(value, kind):
    def test(self):
        schema_violation(self, {"A": value}, {"keys": {"A": {"type": kind}}})
    return test


for index, value in enumerate(["0", "1", "-1", "443", "65535", "9007199254740991", "-9007199254740991"]):
    add_generated_test(TestBehaviorMatrix, "test_integer_valid_%02d" % index, _make_valid_value(value, "integer"))
for index, value in enumerate(["", "01", "1.0", "x", " 1", "1 ", "+1", "9007199254740993", "1e3", "--1", "NaN", "Infinity"]):
    add_generated_test(TestBehaviorMatrix, "test_integer_invalid_%02d" % index, _make_invalid_value(value, "integer"))
for index, value in enumerate(["0", "1", "-1", "1.5", "0.25", "10e3", "1e-3", "2E+4"]):
    add_generated_test(TestBehaviorMatrix, "test_number_valid_%02d" % index, _make_valid_value(value, "number"))
for index, value in enumerate(["", ".5", "1.", "x", "NaN", "Infinity", " 1", "1 ", "01.5", "--1"]):
    add_generated_test(TestBehaviorMatrix, "test_number_invalid_%02d" % index, _make_invalid_value(value, "number"))
for index, value in enumerate(["true", "false"]):
    add_generated_test(TestBehaviorMatrix, "test_boolean_valid_%02d" % index, _make_valid_value(value, "boolean"))
for index, value in enumerate(["TRUE", "False", "0", "1", "yes", ""]):
    add_generated_test(TestBehaviorMatrix, "test_boolean_invalid_%02d" % index, _make_invalid_value(value, "boolean"))

ENUM_VALUES = ["development", "test", "production", "staging"]
for index, value in enumerate(ENUM_VALUES):
    def make_enum_valid(value):
        def test(self):
            self.assertTrue(validate_schema({"A": value}, {"keys": {"A": {"type": "enum", "values": ENUM_VALUES}}})["ok"])
        return test
    add_generated_test(TestBehaviorMatrix, "test_enum_valid_%02d" % index, make_enum_valid(value))
for index, value in enumerate(["dev", "PRODUCTION", "", "local"]):
    def make_enum_invalid(value):
        def test(self):
            schema_violation(self, {"A": value}, {"keys": {"A": {"type": "enum", "values": ENUM_VALUES}}})
        return test
    add_generated_test(TestBehaviorMatrix, "test_enum_invalid_%02d" % index, make_enum_invalid(value))

for index, value in enumerate(["https://example.com/", "http://localhost:3000/x", "postgres://host/db", "custom+v1://host/path"]):
    add_generated_test(TestBehaviorMatrix, "test_url_valid_%02d" % index, _make_valid_value(value, "url"))
for index, value in enumerate(["", "example.com", "/relative", "://", "not a url"]):
    add_generated_test(TestBehaviorMatrix, "test_url_invalid_%02d" % index, _make_invalid_value(value, "url"))
for index, value in enumerate(["{}", "[]", "null", "true", "1", '"x"', '{"a":1}', "[1,2,3]"]):
    add_generated_test(TestBehaviorMatrix, "test_json_valid_%02d" % index, _make_valid_value(value, "json"))
for index, value in enumerate(["", "{", "[1,]", "undefined", "{'a':1}"]):
    add_generated_test(TestBehaviorMatrix, "test_json_invalid_%02d" % index, _make_invalid_value(value, "json"))
for index, value in enumerate(["a" * 12, "x" * 32, "token-with-hyphens"]):
    add_generated_test(TestBehaviorMatrix, "test_secret_valid_%02d" % index, _make_valid_value(value, "secret"))
for index, value in enumerate(["short", "has space", "<placeholder>", "paste-token-here", "replace-me"]):
    add_generated_test(TestBehaviorMatrix, "test_secret_invalid_%02d" % index, _make_invalid_value(value, "secret"))

INVALID_SCHEMAS = [
    None,
    [],
    {"keys": []},
    {"keys": {"1A": {"type": "string"}}},
    {"keys": {"A": None}},
    {"keys": {"A": {"type": "unknown"}}},
    {"keys": {"A": {"type": "enum"}}},
    {"keys": {"A": {"type": "string", "pattern": "["}}},
]


def _make_invalid_schema(schema):
    def test(self):
        expect_code(self, lambda: validate_schema({}, schema), "INVALID_SCHEMA")
    return test


for index, schema in enumerate(INVALID_SCHEMAS):
    add_generated_test(TestBehaviorMatrix, "test_invalid_schema_%02d" % index, _make_invalid_schema(schema))


class TestSafeLoad(unittest.TestCase):
    def test_writes_new_keys(self):
        target = {}
        result = safe_load("A=1\nB=2", target=target)
        self.assertEqual(result.loaded, ("A", "B"))
        self.assertEqual(target["A"], "1")
        self.assertEqual(target["B"], "2")

    def test_does_not_override_by_default(self):
        target = {"A": "existing"}
        result = safe_load("A=new", target=target)
        self.assertEqual(result.skipped, ("A",))
        self.assertEqual(target["A"], "existing")

    def test_override_true_replaces(self):
        target = {"A": "existing"}
        result = safe_load("A=new", target=target, override=True)
        self.assertEqual(result.overridden, ("A",))
        self.assertEqual(target["A"], "new")

    def test_existing_error_transactional(self):
        target = {"A": "existing", "Z": "kept"}
        expect_code(self, lambda: safe_load("A=new\nZ=new", target=target, on_existing="error"), "OVERRIDE_DENIED")
        self.assertEqual(target["A"], "existing")
        self.assertEqual(target["Z"], "kept")

    def test_schema_failure_transactional(self):
        target = {}
        schema = {"keys": {"PORT": {"type": "integer", "max": 65535}, "A": {"type": "string"}}}
        expect_code(self, lambda: safe_load("PORT=99999\nA=1", target=target, schema=schema), "SCHEMA_VIOLATION")
        self.assertEqual(target, {})

    def test_parse_failure_transactional(self):
        target = {}
        expect_code(self, lambda: safe_load("PATH=/bad\nA=1", target=target), "DANGEROUS_KEY")
        self.assertEqual(target, {})

    def test_expands_before_loading(self):
        target = {}
        safe_load("A=${B}\nB=x", target=target)
        self.assertEqual(target["A"], "x")

    def test_input_type_path(self):
        with tempfile.TemporaryDirectory() as scratch:
            file_path = Path(scratch) / "input.env"
            file_path.write_text("A=file-value\n", encoding="utf-8")
            target = {}
            result = safe_load(str(file_path), target=target, input_type="path")
            self.assertEqual(result.loaded, ("A",))
            self.assertEqual(target["A"], "file-value")

    def test_path_option(self):
        with tempfile.TemporaryDirectory() as scratch:
            file_path = Path(scratch) / "input.env"
            file_path.write_text("A=file-value\n", encoding="utf-8")
            target = {}
            safe_load(path=str(file_path), target=target)
            self.assertEqual(target["A"], "file-value")

    def test_missing_file_io_error(self):
        expect_code(self, lambda: safe_load("missing-file", input_type="path", target={}), "IO_ERROR")

    def test_result_omits_values(self):
        result = safe_load("A=secret-value", target={})
        self.assertNotIn("secret-value", repr(result))


class TestDiff(unittest.TestCase):
    def test_detects_added_removed_changed_unchanged(self):
        result = diff_dotenv("A=1\nB=left\nC=3", "A=1\nB=right\nD=4")
        self.assertEqual(result.added, ("D",))
        self.assertEqual(result.removed, ("C",))
        self.assertEqual(result.unchanged, ("A",))
        self.assertEqual([item.key for item in result.changed], ["B"])
        self.assertFalse(result.same)

    def test_same_inputs(self):
        self.assertTrue(diff_dotenv("A=1", "A=1").same)

    def test_redacts_by_default(self):
        result = diff_dotenv("A=left", "A=right")
        self.assertEqual(result.changed[0].left, "<redacted>")
        self.assertEqual(result.changed[0].right, "<redacted>")
        rendered = result.changed[0].to_dict()
        self.assertNotIn("leftSha256", rendered)
        self.assertNotIn("rightSha256", rendered)
        self.assertNotIn("leftLength", rendered)
        self.assertNotIn("rightLength", rendered)

    def test_can_reveal_values(self):
        result = diff_dotenv("A=left", "A=right", redact=False)
        self.assertEqual(result.changed[0].left, "left")
        self.assertEqual(result.changed[0].right, "right")

    def test_accepts_values_mappings(self):
        self.assertEqual(diff_dotenv({"A": "1"}, {"A": "1", "B": "2"}).added, ("B",))

    def test_accepts_parse_results(self):
        left = parse_dotenv("A=1")
        right = parse_dotenv("A=2")
        self.assertFalse(diff_dotenv(left, right).same)


def _make_diff_same(count):
    def test(self):
        entries = "\n".join("K%d=v%d" % (index, index) for index in range(count))
        self.assertTrue(diff_dotenv(entries, entries).same)
    return test


for count in range(31):
    add_generated_test(TestBehaviorMatrix, "test_diff_same_%02d" % count, _make_diff_same(count))


class TestRedact(unittest.TestCase):
    def test_redacts_simple_assignments(self):
        output = redact_dotenv("A=secret\nB=two\n")
        self.assertNotIn("secret", output)
        self.assertIn("A=<redacted>", output)
        self.assertIn("B=<redacted>", output)

    def test_preserves_comments_blank_lines(self):
        output = redact_dotenv("# top\n\nA=secret # keep\n")
        self.assertIn("# top", output)
        self.assertIn("# keep", output)

    def test_handles_quoted_values(self):
        output = redact_dotenv("A=\"secret value\"\nB='hidden'\n")
        self.assertNotIn("secret value", output)
        self.assertNotIn("hidden", output)

    def test_removes_multiline_continuation_content(self):
        output = redact_dotenv('A="first\nsecond secret\nthird"\nB=safe\n')
        self.assertNotIn("second secret", output)
        self.assertNotIn("third", output)

    def test_values_mapping(self):
        output = redact_dotenv({"A": "secret", "B": ""})
        self.assertEqual(output["A"], "<redacted>")
        self.assertEqual(output["B"], "")

    def test_custom_placeholder(self):
        self.assertIn("A=[hidden]", redact_dotenv("A=x", placeholder="[hidden]"))


def _make_redact_key(key):
    def test(self):
        output = redact_dotenv(key + "=value-" + key)
        self.assertNotIn("value-" + key, output)
        self.assertIn(key + "=<redacted>", output)
    return test


for index in range(40):
    add_generated_test(TestBehaviorMatrix, "test_redact_key_%02d" % index, _make_redact_key("K%d" % index))


def _make_redact_quoted(quote, index):
    def test(self):
        secret = "secret%d" % index
        output = redact_dotenv("A=" + quote + secret + quote)
        self.assertNotIn(secret, output)
    return test


for quote in ('"', "'"):
    for index in range(20):
        add_generated_test(TestBehaviorMatrix, "test_redact_quoted_%s_%02d" % ("double" if quote == '"' else "single", index), _make_redact_quoted(quote, index))


if __name__ == "__main__":
    unittest.main()
