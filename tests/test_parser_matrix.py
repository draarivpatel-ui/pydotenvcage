"""Generated strict parser matrix tests."""
from __future__ import annotations

import unittest

from pydotenvcage import parse_dotenv, scan_dotenv

from helpers import add_generated_test, expect_audit_code, expect_parse_code


class TestParserMatrix(unittest.TestCase):
    pass


VALID_CASES = [
    ("simple", "A=1", "A", "1"),
    ("empty", "A=", "A", ""),
    ("spaces trimmed", "  A  =  value  ", "A", "value"),
    ("inner spaces kept", "A=a b c", "A", "a b c"),
    ("inline comment", "A=value # comment", "A", "value"),
    ("hash starts empty comment", "A=# comment", "A", ""),
    ("hash inside value", "A=a#b", "A", "a#b"),
    ("export prefix", "export A=value", "A", "value"),
    ("export wide spacing", "export   A   =   value", "A", "value"),
    ("underscore key", "_A=value", "_A", "value"),
    ("digit in key", "A1=value", "A1", "value"),
    ("lower key", "a=value", "a", "value"),
    ("mixed key", "Ab_C9=value", "Ab_C9", "value"),
    ("unicode value", "A=café", "A", "café"),
    ("symbols value", "A=!%&*+,-./:?@[]^_{}~", "A", "!%&*+,-./:?@[]^_{}~"),
    ("single quoted empty", "A=''", "A", ""),
    ("single quoted spaces", "A=' a b '", "A", " a b "),
    ("single quoted hash", "A='a # b'", "A", "a # b"),
    ("single quoted double quote", "A='a\"b'", "A", "a\"b"),
    ("double quoted empty", 'A=""', "A", ""),
    ("double quoted spaces", 'A=" a b "', "A", " a b "),
    ("double quoted hash", 'A="a # b"', "A", "a # b"),
    ("double quoted quote escape", 'A="a\\"b"', "A", 'a"b'),
    ("double quoted backslash escape", 'A="a\\\\b"', "A", "a\\b"),
    ("double quoted single escape", 'A="a\\\'b"', "A", "a'b"),
    ("comment after quote", "A='x' # comment", "A", "x"),
    ("equals in quoted value", "A='x=y'", "A", "x=y"),
    ("equals in unquoted value", "A=x=y", "A", "x=y"),
    ("blank lines around", "\nA=1\n\n", "A", "1"),
    ("comment lines around", "# one\nA=1\n# two", "A", "1"),
]


def _make_valid(input_data, key, expected):
    def test(self):
        parsed = parse_dotenv(input_data, expand=False)
        self.assertEqual(parsed.values[key], expected)
        self.assertEqual(parsed.entries[0].key, key)
    return test


for index, (name, input_data, key, expected) in enumerate(VALID_CASES):
    add_generated_test(TestParserMatrix, "test_valid_%02d" % index, _make_valid(input_data, key, expected))


class TestParserBehavior(unittest.TestCase):
    def test_export_metadata(self):
        parsed = parse_dotenv("export A=1\nB=2", expand=False)
        self.assertTrue(parsed.entries[0].exported)
        self.assertFalse(parsed.entries[1].exported)

    def test_first_value_wins_while_duplicate_is_rejected(self):
        scanned = scan_dotenv("A=1\nA=2", expand=False)
        self.assertEqual(scanned.values["A"], "1")
        self.assertIn("DUPLICATE_KEY", [finding.code for finding in scanned.findings])

    def test_utf8_bom_accepted_by_default(self):
        self.assertEqual(parse_dotenv("\ufeffA=1", expand=False).values["A"], "1")

    def test_utf8_bom_can_be_rejected(self):
        expect_parse_code(self, "\ufeffA=1", "UNICODE_SMUGGLING", expand=False, allow_bom=False)

    def test_crlf_accepted(self):
        parsed = parse_dotenv("A=1\r\nB=2\r\n", expand=False)
        self.assertEqual(parsed.values["A"], "1")
        self.assertEqual(parsed.values["B"], "2")

    def test_bare_carriage_return_rejected(self):
        expect_parse_code(self, "A=1\rB=2", "CR_LINE_ENDING", expand=False)

    def test_single_multiline_rejected_by_default(self):
        expect_parse_code(self, "A='one\ntwo'", "MULTILINE_VALUE", expand=False)

    def test_single_multiline_explicitly_allowed(self):
        parsed = parse_dotenv("A='one\ntwo'", expand=False, allow_multiline=True)
        self.assertEqual(parsed.values["A"], "one\ntwo")

    def test_double_escaped_newline_rejected_by_default(self):
        expect_parse_code(self, 'A="one\\ntwo"', "CONTROL_CHARACTER", expand=False)

    def test_double_escaped_newline_allowed_with_multiline(self):
        parsed = parse_dotenv('A="one\\ntwo"', expand=False, allow_multiline=True)
        self.assertEqual(parsed.values["A"], "one\ntwo")

    def test_bytes_input_accepted(self):
        self.assertEqual(parse_dotenv(b"A=1\n", expand=False).values["A"], "1")

    def test_invalid_utf8_rejected(self):
        expect_parse_code(self, b"\xff\xfeA", "INVALID_ENCODING", expand=False)

    def test_non_string_input_rejected(self):
        expect_parse_code(self, {"A": "1"}, "INVALID_INPUT", expand=False)

    def test_input_byte_limit(self):
        expect_parse_code(self, "A=" + "x" * 100, "INPUT_TOO_LARGE", expand=False, limits={"max_bytes": 20})

    def test_line_limit(self):
        expect_parse_code(self, "A=1\nB=2\nC=3", "INPUT_TOO_LARGE", expand=False, limits={"max_lines": 2})

    def test_entry_limit(self):
        expect_parse_code(self, "A=1\nB=2", "INPUT_TOO_LARGE", expand=False, limits={"max_entries": 1})

    def test_key_length_limit(self):
        expect_parse_code(self, "ABCDEF=x", "INVALID_KEY", expand=False, limits={"max_key_length": 3})

    def test_value_length_limit(self):
        expect_parse_code(self, "A=xxxx", "INPUT_TOO_LARGE", expand=False, limits={"max_value_length": 3})

    def test_invalid_lines_do_not_become_values(self):
        report = expect_audit_code(self, "A=1\nnot-an-assignment\nB=2", "INVALID_LINE", expand=False)
        self.assertIn("A", report.keys)
        self.assertIn("B", report.keys)


INVALID_LINES = [
    "1A=value", "A B=value", "A-value=1", "A.value=1", "A", "export", "=x",
    "A x", "A\t=1", "é=1", "A\x7f=1", "A B", "EXPORT A=1", "A :=1",
]


def _make_invalid_line(line):
    def test(self):
        scanned = scan_dotenv(line, expand=False)
        self.assertGreater(len(scanned.findings), 0)
    return test


for index, line in enumerate(INVALID_LINES):
    add_generated_test(TestParserMatrix, "test_invalid_line_%02d" % index, _make_invalid_line(line))


def _make_valid_key(key):
    def test(self):
        self.assertEqual(parse_dotenv(key + "=x", expand=False).values[key], "x")
    return test


for index in range(26):
    key = "K_" + chr(65 + index) + str(index)
    add_generated_test(TestParserMatrix, "test_valid_key_%02d" % index, _make_valid_key(key))


def _make_invalid_key(key):
    def test(self):
        expect_parse_code(self, key + "=x", "INVALID_LINE", expand=False)
    return test


for index, key in enumerate(["0A", "9_", "-A", "A-B", "A.B", "A B", "é", "_é", "Aé"]):
    add_generated_test(TestParserMatrix, "test_invalid_key_%02d" % index, _make_invalid_key(key))


def _make_control(cp):
    def test(self):
        expect_parse_code(self, "A=a" + chr(cp) + "b", "CONTROL_CHARACTER", expand=False)
    return test


for cp in list(range(0, 10)) + [11, 12] + list(range(14, 32)) + list(range(127, 160)):
    add_generated_test(TestParserMatrix, "test_control_%03d" % cp, _make_control(cp))


def _make_bidi(cp):
    def test(self):
        expect_parse_code(self, "A=a" + chr(cp) + "b", "BIDI_CONTROL", expand=False)
    return test


for cp in [0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]:
    add_generated_test(TestParserMatrix, "test_bidi_%04x" % cp, _make_bidi(cp))


def _make_zero_width(cp):
    def test(self):
        expect_parse_code(self, "A=a" + chr(cp) + "b", "UNICODE_SMUGGLING", expand=False)
    return test


for cp in [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF]:
    add_generated_test(TestParserMatrix, "test_zero_width_%04x" % cp, _make_zero_width(cp))


QUOTE_ERRORS = [
    ("unterminated single", "A='abc", "QUOTE_SYNTAX"),
    ("unterminated double", 'A="abc', "QUOTE_SYNTAX"),
    ("trailing after single", "A='abc'x", "QUOTE_SYNTAX"),
    ("trailing after double", 'A="abc"x', "QUOTE_SYNTAX"),
    ("unknown escape", 'A="a\\q"', "INVALID_ESCAPE"),
    ("backslash at line end", 'A="abc\\', "INVALID_ESCAPE"),
]


def _make_quote_error(input_data, code):
    def test(self):
        expect_parse_code(self, input_data, code, expand=False)
    return test


for index, (name, input_data, code) in enumerate(QUOTE_ERRORS):
    add_generated_test(TestParserMatrix, "test_quote_error_%02d" % index, _make_quote_error(input_data, code))


if __name__ == "__main__":
    unittest.main()
