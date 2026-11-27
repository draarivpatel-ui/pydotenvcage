"""Strict bounded dotenv parser and expansion firewall."""
from __future__ import annotations

import re
from dataclasses import dataclass
from collections.abc import Mapping as MappingABC
from typing import Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .constants import DEFAULT_LIMITS
from .errors import ERROR_CODES, Finding, make_finding, throw_first_error
from .security import key_findings, scan_raw_line_security, scan_value_security

KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
LINE_PATTERN = re.compile(r"^ *(export +)?([A-Za-z_][A-Za-z0-9_]*) *= *(.*)$")


@dataclass(frozen=True)
class Entry:
    key: str
    value: str
    raw_value: str
    line: int
    end_line: int
    quote: str
    exported: bool


@dataclass(frozen=True)
class ScanResult:
    entries: Tuple[Entry, ...]
    values: Dict[str, str]
    references: Dict[str, Tuple[str, ...]]
    findings: Tuple[Finding, ...]


@dataclass(frozen=True)
class ParseResult:
    values: Dict[str, str]
    entries: Tuple[Entry, ...]
    references: Dict[str, Tuple[str, ...]]


def _merge_limits(limits: Optional[Mapping[str, int]]) -> Dict[str, int]:
    merged = dict(DEFAULT_LIMITS)
    if limits:
        merged.update(limits)
    for key, value in merged.items():
        if not isinstance(value, int) or value < 1:
            raise TypeError("limit " + key + " must be a positive integer")
    return merged


def _add(findings: List[Finding], finding: Finding, limits: Mapping[str, int]) -> None:
    if len(findings) < limits["max_findings"]:
        findings.append(finding)


def _decode_input(input_data: Union[str, bytes, bytearray], limits: Mapping[str, int], findings: List[Finding]) -> Optional[str]:
    if isinstance(input_data, str):
        size = len(input_data.encode("utf-8"))
        text = input_data
    elif isinstance(input_data, (bytes, bytearray)):
        raw = bytes(input_data)
        size = len(raw)
        text = None
        if size <= limits["max_bytes"]:
            try:
                text = raw.decode("utf-8", "strict")
            except UnicodeDecodeError:
                _add(findings, make_finding(ERROR_CODES["INVALID_ENCODING"], "error", "input is not valid UTF-8"), limits)
    else:
        _add(findings, make_finding(ERROR_CODES["INVALID_INPUT"], "error", "input must be a string or UTF-8 bytes"), limits)
        return None
    if size > limits["max_bytes"]:
        _add(findings, make_finding(ERROR_CODES["INPUT_TOO_LARGE"], "error", "input exceeds the bounded byte limit"), limits)
        return None
    return text


def _parse_unquoted(rest: str) -> str:
    end = len(rest)
    for index, ch in enumerate(rest):
        if ch == "#" and (index == 0 or rest[index - 1] == " "):
            end = index
            break
    return rest[:end].rstrip(" ")


def _trailing_is_clean(trailing: str) -> bool:
    return re.match(r"^ *(#.*)?$", trailing) is not None


def _parse_quoted(lines: Sequence[str], start_index: int, start_column: int, quote: str, findings: List[Finding], limits: Mapping[str, int]) -> Tuple[str, str, bool, str, int, int]:
    value = ""
    raw_value = ""
    line_index = start_index
    column = start_column
    closed = False
    trailing = ""
    invalid_escape_reported = False
    escapes = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", '"': '"', "'": "'", "$": "\\$"}

    while line_index < len(lines) and not closed:
        line = lines[line_index]
        while column < len(line):
            ch = line[column]
            if ch == quote:
                closed = True
                trailing = line[column + 1:]
                column += 1
                break
            if quote == '"' and ch == "\\":
                if column + 1 >= len(line):
                    if not invalid_escape_reported:
                        _add(findings, make_finding(ERROR_CODES["INVALID_ESCAPE"], "error", "escape character ends a line", line_index + 1), limits)
                        invalid_escape_reported = True
                    value += "\\"
                    raw_value += "\\"
                    column += 1
                    continue
                nxt = line[column + 1]
                if nxt not in escapes:
                    if not invalid_escape_reported:
                        _add(findings, make_finding(ERROR_CODES["INVALID_ESCAPE"], "error", "unsupported escape sequence in double-quoted value", line_index + 1), limits)
                        invalid_escape_reported = True
                else:
                    value += escapes[nxt]
                raw_value += ch + nxt
                column += 2
                continue
            value += ch
            raw_value += ch
            column += 1
        if not closed:
            if line_index + 1 >= len(lines):
                break
            value += "\n"
            raw_value += "\n"
            line_index += 1
            column = 0
    return value, raw_value, closed, trailing, line_index, line_index + 1


def _extract_references(value: str, key: str, line: int, findings: List[Finding], limits: Mapping[str, int]) -> Tuple[str, ...]:
    references = []
    seen = set()
    index = 0
    while index < len(value):
        if value[index] != "$" or index + 1 >= len(value) or value[index + 1] != "{":
            index += 1
            continue
        slashes = 0
        cursor = index - 1
        while cursor >= 0 and value[cursor] == "\\":
            slashes += 1
            cursor -= 1
        if slashes % 2 == 1:
            index += 1
            continue
        close = value.find("}", index + 2)
        if close == -1:
            _add(findings, make_finding(ERROR_CODES["INVALID_EXPANSION"], "error", "unclosed variable expansion reference", line, key), limits)
            index += 1
            continue
        name = value[index + 2:close]
        if not KEY_PATTERN.match(name):
            _add(findings, make_finding(ERROR_CODES["INVALID_EXPANSION"], "error", "variable expansion reference is not a valid key", line, key), limits)
        elif name not in seen:
            seen.add(name)
            references.append(name)
        index = close + 1
    return tuple(references)


def _substitute_references(value: str, resolver, max_bytes: int):
    output = ""
    output_bytes = 0
    exceeded = False

    def byte_len(text: str) -> int:
        return len(text.encode("utf-8"))

    def append(part: str) -> None:
        nonlocal output, output_bytes, exceeded
        if exceeded:
            return
        output_bytes += byte_len(part)
        if output_bytes > max_bytes:
            exceeded = True
            output = ""
            return
        output += part

    index = 0
    while index < len(value) and not exceeded:
        if value[index] == "\\":
            slash_end = index
            while slash_end < len(value) and value[slash_end] == "\\":
                slash_end += 1
            slash_count = slash_end - index
            if slash_end + 1 < len(value) and value[slash_end] == "$" and value[slash_end + 1] == "{":
                close = value.find("}", slash_end + 2)
                name = "" if close == -1 else value[slash_end + 2:close]
                if close != -1 and KEY_PATTERN.match(name):
                    if slash_count % 2 == 1:
                        append("\\" * (slash_count - 1) + value[slash_end:close + 1])
                        index = close + 1
                    else:
                        append("\\" * slash_count)
                        index = slash_end
                    continue
            append(value[index:slash_end])
            index = slash_end
            continue
        if value.startswith("${", index):
            close = value.find("}", index + 2)
            if close != -1:
                name = value[index + 2:close]
                if KEY_PATTERN.match(name):
                    append(resolver(name))
                    index = close + 1
                    continue
        append(value[index])
        index += 1
    return output, exceeded


def _expansion_analysis(entries: Sequence[Entry], expand: bool, expansion_env: Optional[Mapping[str, object]], limits: Mapping[str, int], findings: List[Finding]):
    raw_values = {}
    references = {}
    lines = {}
    for entry in entries:
        if entry.key not in raw_values:
            raw_values[entry.key] = entry.value
            lines[entry.key] = entry.line
        references[entry.key] = _extract_references(entry.value, entry.key, entry.line, findings, limits)

    state = {}
    reported_cycles = set()

    def visit(key: str, path: List[str]) -> None:
        mark = state.get(key)
        if mark == "done":
            return
        if mark == "visiting":
            start = path.index(key) if key in path else 0
            cycle = path[start:] + [key]
            label = "|".join(sorted(cycle))
            if label not in reported_cycles:
                reported_cycles.add(label)
                _add(findings, make_finding(ERROR_CODES["EXPANSION_CIRCULAR"], "error", "circular variable expansion reference: " + " -> ".join(cycle), lines.get(key), key), limits)
            return
        state[key] = "visiting"
        next_path = path + [key]
        for reference in references.get(key, ()):
            if reference in raw_values:
                visit(reference, next_path)
        state[key] = "done"

    for key in raw_values:
        visit(key, [])
    if reported_cycles:
        return references, {}, True

    external = expansion_env if isinstance(expansion_env, MappingABC) else {}
    undefined_reported = set()
    for key, refs in references.items():
        for reference in refs:
            if reference not in raw_values and reference not in external:
                label = key + "|" + reference
                if label not in undefined_reported:
                    undefined_reported.add(label)
                    _add(findings, make_finding(ERROR_CODES["EXPANSION_UNDEFINED"], "error", "variable expansion reference is undefined: " + reference, lines.get(key), key), limits)

    expanded = {}
    if not expand or undefined_reported:
        return references, expanded, False

    memo = {}
    steps = [0]
    too_deep = set()
    too_large = set()

    def expand_key(key: str, depth: int) -> str:
        if key in memo:
            return memo[key]
        if depth > limits["max_expansion_depth"]:
            if key not in too_deep:
                too_deep.add(key)
                _add(findings, make_finding(ERROR_CODES["EXPANSION_TOO_DEEP"], "error", "variable expansion exceeds the bounded depth", lines.get(key), key), limits)
            return ""
        steps[0] += 1
        if steps[0] > limits["max_expansion_steps"]:
            _add(findings, make_finding(ERROR_CODES["EXPANSION_TOO_LARGE"], "error", "variable expansion exceeds the bounded step count", lines.get(key), key), limits)
            return ""
        source = raw_values.get(key, "")

        def resolve(reference: str) -> str:
            if reference in raw_values:
                return expand_key(reference, depth + 1)
            return str(external[reference]) if reference in external else "${" + reference + "}"

        output, exceeded = _substitute_references(source, resolve, limits["max_expanded_length"])
        if (exceeded or len(output.encode("utf-8")) > limits["max_expanded_length"]) and key not in too_large:
            too_large.add(key)
            _add(findings, make_finding(ERROR_CODES["EXPANSION_TOO_LARGE"], "error", "variable expansion exceeds the bounded output length", lines.get(key), key), limits)
        memo[key] = output
        return output

    for key in raw_values:
        expanded[key] = expand_key(key, 0)
    return references, expanded, False


def scan_dotenv(
    input_data: Union[str, bytes, bytearray],
    *,
    expand: bool = True,
    allow_bom: bool = True,
    allow_multiline: bool = False,
    allow_runtime_keys: Union[bool, Sequence[str]] = False,
    expansion_env: Optional[Mapping[str, object]] = None,
    limits: Optional[Mapping[str, int]] = None,
) -> ScanResult:
    merged_limits = _merge_limits(limits)
    findings: List[Finding] = []
    entries: List[Entry] = []
    text = _decode_input(input_data, merged_limits, findings)
    if text is None:
        return ScanResult(tuple(), {}, {}, tuple(findings))

    if allow_bom and text.startswith("\ufeff"):
        text = text[1:]
    for index, ch in enumerate(text):
        if ch == "\r" and (index + 1 >= len(text) or text[index + 1] != "\n"):
            _add(findings, make_finding(ERROR_CODES["CR_LINE_ENDING"], "error", "bare carriage return line ending or smuggled carriage return is forbidden"), merged_limits)
            break
    raw_lines = text.split("\n")
    if len(raw_lines) > merged_limits["max_lines"]:
        _add(findings, make_finding(ERROR_CODES["INPUT_TOO_LARGE"], "error", "input exceeds the bounded line count"), merged_limits)
    lines = [line[:-1] if line.endswith("\r") else line for line in raw_lines]
    for index, line in enumerate(lines):
        for finding in scan_raw_line_security(line, index + 1):
            _add(findings, finding, merged_limits)

    seen_keys = {}
    seen_key_fold = {}
    entry_count = 0
    line_index = 0
    while line_index < len(lines):
        line_number = line_index + 1
        line = lines[line_index]
        if re.match(r"^ *$", line) or re.match(r"^ *#", line):
            line_index += 1
            continue
        match = LINE_PATTERN.match(line)
        if match is None:
            _add(findings, make_finding(ERROR_CODES["INVALID_LINE"], "error", "line is not a strict KEY=value assignment or comment", line_number), merged_limits)
            line_index += 1
            continue
        entry_count += 1
        if entry_count > merged_limits["max_entries"]:
            _add(findings, make_finding(ERROR_CODES["INPUT_TOO_LARGE"], "error", "input exceeds the bounded assignment count", line_number), merged_limits)
            line_index += 1
            continue
        exported = match.group(1) is not None
        key = match.group(2)
        rest = match.group(3)
        if len(key.encode("utf-8")) > merged_limits["max_key_length"]:
            _add(findings, make_finding(ERROR_CODES["INVALID_KEY"], "error", "key exceeds the bounded length", line_number, key), merged_limits)
        for finding in key_findings(key, line_number, allow_runtime_keys):
            _add(findings, finding, merged_limits)
        key_fold = key.upper()
        if key in seen_keys:
            _add(findings, make_finding(ERROR_CODES["DUPLICATE_KEY"], "error", "duplicate key shadows an earlier assignment", line_number, key), merged_limits)
        elif key_fold in seen_key_fold:
            _add(findings, make_finding(ERROR_CODES["DUPLICATE_KEY"], "error", "case-variant key shadows an earlier assignment on case-insensitive platforms", line_number, key), merged_limits)
        else:
            seen_keys[key] = line_number
            seen_key_fold[key_fold] = line_number

        value = ""
        raw_value = ""
        quote = "none"
        end_index = line_index
        end_line = line_number
        if rest.startswith("'") or rest.startswith('"'):
            quote = "single" if rest[0] == "'" else "double"
            start_column = len(line) - len(rest) + 1
            value, raw_value, closed, trailing, end_index, end_line = _parse_quoted(lines, line_index, start_column, rest[0], findings, merged_limits)
            if not closed:
                _add(findings, make_finding(ERROR_CODES["QUOTE_SYNTAX"], "error", "quoted value is not closed", line_number, key), merged_limits)
            if end_index != line_index and not allow_multiline:
                _add(findings, make_finding(ERROR_CODES["MULTILINE_VALUE"], "error", "multiline values are disabled by default", line_number, key), merged_limits)
            if not _trailing_is_clean(trailing):
                _add(findings, make_finding(ERROR_CODES["QUOTE_SYNTAX"], "error", "unexpected content after a closed quoted value", line_number, key), merged_limits)
        else:
            value = _parse_unquoted(rest)
            raw_value = value
        if len(value.encode("utf-8")) > merged_limits["max_value_length"]:
            _add(findings, make_finding(ERROR_CODES["INPUT_TOO_LARGE"], "error", "value exceeds the bounded length", line_number, key), merged_limits)
        for finding in scan_value_security(value, key, line_number, allow_multiline):
            _add(findings, finding, merged_limits)
        entries.append(Entry(key=key, value=value, raw_value=raw_value, line=line_number, end_line=end_line, quote=quote, exported=exported))
        line_index = end_index + 1

    references, expanded, _circular = _expansion_analysis(entries, expand, expansion_env, merged_limits, findings)
    values = {}
    first_entries = {}
    for entry in entries:
        if entry.key not in first_entries:
            first_entries[entry.key] = entry
    for key, entry in first_entries.items():
        final_value = entry.value
        if expand and key in expanded:
            final_value = expanded[key]
        if final_value != entry.value:
            for finding in scan_value_security(final_value, key, entry.line, allow_multiline):
                _add(findings, finding, merged_limits)
            if len(final_value.encode("utf-8")) > merged_limits["max_expanded_length"]:
                _add(findings, make_finding(ERROR_CODES["EXPANSION_TOO_LARGE"], "error", "expanded value exceeds the bounded length", entry.line, key), merged_limits)
        values[key] = final_value
    return ScanResult(tuple(entries), values, references, tuple(findings))


def parse_dotenv(input_data: Union[str, bytes, bytearray], **options) -> ParseResult:
    scanned = scan_dotenv(input_data, **options)
    throw_first_error(scanned.findings)
    return ParseResult(values=scanned.values, entries=scanned.entries, references=scanned.references)
