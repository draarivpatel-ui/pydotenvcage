"""Generated expansion firewall matrix tests."""
from __future__ import annotations

import os
import unittest

from pydotenvcage import parse_dotenv, scan_dotenv

from helpers import add_generated_test, expect_parse_code


class TestExpansionMatrix(unittest.TestCase):
    pass


class TestExpansionBehavior(unittest.TestCase):
    def test_simple_braced_expansion_resolves_regardless_of_order(self):
        self.assertEqual(parse_dotenv("A=${B}\nB=value").values["A"], "value")

    def test_multiple_references_resolve(self):
        self.assertEqual(parse_dotenv("A=${B}-${C}\nB=one\nC=two").values["A"], "one-two")

    def test_nested_references_resolve(self):
        self.assertEqual(parse_dotenv("A=${B}\nB=${C}\nC=final").values["A"], "final")

    def test_same_reference_repeated(self):
        self.assertEqual(parse_dotenv("A=${B}/${B}\nB=x").values["A"], "x/x")

    def test_external_expansion_environment_explicit(self):
        self.assertEqual(parse_dotenv("A=${EXTERNAL}", expansion_env={"EXTERNAL": "outside"}).values["A"], "outside")

    def test_process_environment_not_implicitly_read(self):
        os.environ["PYDOTENVCAGE_IMPLICIT"] = "leak"
        try:
            expect_parse_code(self, "A=${PYDOTENVCAGE_IMPLICIT}", "EXPANSION_UNDEFINED")
        finally:
            os.environ.pop("PYDOTENVCAGE_IMPLICIT", None)

    def test_undefined_reference_rejected(self):
        expect_parse_code(self, "A=${MISSING}", "EXPANSION_UNDEFINED")

    def test_undefined_reference_rejected_when_expansion_disabled(self):
        expect_parse_code(self, "A=${MISSING}", "EXPANSION_UNDEFINED", expand=False)

    def test_self_reference_circular(self):
        expect_parse_code(self, "A=${A}", "EXPANSION_CIRCULAR")

    def test_depth_bound_enforced(self):
        lines = ["A=${X0}"]
        for index in range(8):
            lines.append("X%d=${X%d}" % (index, index + 1))
        lines.append("X8=final")
        expect_parse_code(self, "\n".join(lines), "EXPANSION_TOO_DEEP", limits={"max_expansion_depth": 3})

    def test_output_length_bound_enforced(self):
        input_data = "A=" + "x" * 30 + "\nB=${A}${A}${A}"
        expect_parse_code(self, input_data, "EXPANSION_TOO_LARGE", limits={"max_expanded_length": 40})

    def test_step_count_bound_enforced(self):
        lines = ["K%d=v%d" % (index, index) for index in range(20)]
        lines.append("A=" + "-".join("${K%d}" % index for index in range(20)))
        expect_parse_code(self, "\n".join(lines), "EXPANSION_TOO_LARGE", limits={"max_expansion_steps": 4, "max_expansion_depth": 30})

    def test_expansion_cannot_smuggle_command_substitution(self):
        expect_parse_code(self, "A=${EXTERNAL}", "COMMAND_SUBSTITUTION", expansion_env={"EXTERNAL": "$(id)"})

    def test_expansion_cannot_smuggle_control_characters(self):
        expect_parse_code(self, "A=${EXTERNAL}", "CONTROL_CHARACTER", expansion_env={"EXTERNAL": "a\nb"})

    def test_references_metadata(self):
        parsed = parse_dotenv("A=${B}-${C}\nB=x\nC=y")
        self.assertEqual(parsed.references["A"], ("B", "C"))

    def test_expansion_disabled_leaves_reference_literal(self):
        self.assertEqual(parse_dotenv("A=${B}\nB=x", expand=False).values["A"], "${B}")

    def test_external_empty_string_is_defined(self):
        self.assertEqual(parse_dotenv("A=${EXTERNAL}", expansion_env={"EXTERNAL": ""}).values["A"], "")

    def test_numeric_external_value_stringified(self):
        self.assertEqual(parse_dotenv("A=${EXTERNAL}", expansion_env={"EXTERNAL": 42}).values["A"], "42")


def _make_undefined(name):
    def test(self):
        expect_parse_code(self, "A=${" + name + "}", "EXPANSION_UNDEFINED")
    return test


for name in ["B", "MISSING", "X1", "VERY_LONG_NAME", "_PRIVATE"]:
    add_generated_test(TestExpansionMatrix, "test_undefined_%s" % name, _make_undefined(name))


def _make_cycle(length):
    def test(self):
        lines = []
        for index in range(length):
            lines.append("X%d=${X%d}" % (index, (index + 1) % length))
        expect_parse_code(self, "\n".join(lines), "EXPANSION_CIRCULAR")
    return test


for length in range(2, 21):
    add_generated_test(TestExpansionMatrix, "test_cycle_%02d" % length, _make_cycle(length))


MALFORMED = [
    ("unclosed", "A=${B"),
    ("empty", "A=${}"),
    ("space", "A=${B C}"),
    ("digit start", "A=${1B}"),
    ("dash", "A=${B-C}"),
    ("nested opener", "A=${${B}}"),
    ("unicode", "A=${é}"),
]


def _make_malformed(input_data):
    def test(self):
        expect_parse_code(self, input_data, "INVALID_EXPANSION")
    return test


for index, (name, input_data) in enumerate(MALFORMED):
    add_generated_test(TestExpansionMatrix, "test_malformed_%02d" % index, _make_malformed(input_data))


class TestEscapedReferences(unittest.TestCase):
    def test_escaped_unquoted_literal(self):
        self.assertEqual(parse_dotenv("A=\\${B}\nB=value").values["A"], "${B}")

    def test_escaped_double_literal(self):
        self.assertEqual(parse_dotenv('A="\\${B}"\nB=value').values["A"], "${B}")

    def test_escaped_single_literal(self):
        self.assertEqual(parse_dotenv("A='\\${B}'\nB=value").values["A"], "${B}")


LITERAL_CONTEXTS = [
    ("prefix", "x\\${B}"),
    ("suffix", "\\${B}x"),
    ("middle", "x\\${B}y"),
    ("twice", "\\${B}\\${B}"),
]


def _make_literal_context(value):
    def test(self):
        parsed = parse_dotenv("A=" + value + "\nB=z")
        self.assertEqual(parsed.values["A"], value.replace("\\${", "${"))
    return test


for index, (name, value) in enumerate(LITERAL_CONTEXTS):
    add_generated_test(TestExpansionMatrix, "test_literal_context_%02d" % index, _make_literal_context(value))


def _make_valid_depth(depth):
    def test(self):
        lines = ["A=${X0}"]
        for index in range(depth):
            lines.append("X%d=${X%d}" % (index, index + 1))
        lines.append("X%d=final" % depth)
        self.assertEqual(parse_dotenv("\n".join(lines)).values["A"], "final")
    return test


for depth in range(3, 16):
    add_generated_test(TestExpansionMatrix, "test_valid_depth_%02d" % depth, _make_valid_depth(depth))


EXPANSION_SHAPES = [
    ("empty value", "${B}", "", ""),
    ("prefix suffix", "pre-${B}-post", "X", "pre-X-post"),
    ("adjacent", "${B}${B}", "X", "XX"),
    ("slash join", "${B}/${B}", "x", "x/x"),
    ("equals value", "a=${B}", "b=c", "a=b=c"),
    ("unicode value", "u-${B}", "é", "u-é"),
    ("space value", "x ${B} y", "mid", "x mid y"),
    ("empty reference target", "a${B}b", "", "ab"),
]


def _make_shape(template, replacement, expected):
    def test(self):
        self.assertEqual(parse_dotenv("A=" + template + "\nB=" + replacement).values["A"], expected)
    return test


for index, (name, template, replacement, expected) in enumerate(EXPANSION_SHAPES):
    add_generated_test(TestExpansionMatrix, "test_shape_%02d" % index, _make_shape(template, replacement, expected))


def _make_fanout(count):
    def test(self):
        template = "-".join(["${B}"] * count)
        expected = "-".join(["x"] * count)
        self.assertEqual(parse_dotenv("A=" + template + "\nB=x").values["A"], expected)
    return test


for count in range(1, 26):
    add_generated_test(TestExpansionMatrix, "test_fanout_%02d" % count, _make_fanout(count))


class TestCircularMetadata(unittest.TestCase):
    def test_duplicate_keys_in_circular_input_have_security_finding(self):
        scanned = scan_dotenv("A=${B}\nB=${A}\nA=x")
        self.assertTrue(any(finding.code in ("EXPANSION_CIRCULAR", "DUPLICATE_KEY") for finding in scanned.findings))


if __name__ == "__main__":
    unittest.main()
