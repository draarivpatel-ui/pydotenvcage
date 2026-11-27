"""Best-effort redaction for dotenv text and values mappings."""
from __future__ import annotations

import re
from collections.abc import Mapping as MappingABC
from typing import Dict, Mapping, Union

from .errors import ERROR_CODES, DotenvCageError

ASSIGNMENT = re.compile(r"^(\s*(?:export\s+)?)([A-Za-z_][A-Za-z0-9_]*)(\s*=\s*)(.*)$")
DEFAULT_PLACEHOLDER = "<redacted>"


def _split_unquoted_comment(rest: str):
    for index, ch in enumerate(rest):
        if ch == "#" and (index == 0 or rest[index - 1] in (" ", "\t")):
            return rest[:index], rest[index:]
    return rest, ""


def _closes_on_line(text: str, quote: str, start_index: int = 1) -> bool:
    for index in range(start_index, len(text)):
        if text[index] != quote:
            continue
        if quote == "'":
            return True
        slashes = 0
        cursor = index - 1
        while cursor >= 0 and text[cursor] == "\\":
            slashes += 1
            cursor -= 1
        if slashes % 2 == 0:
            return True
    return False


def redact_dotenv(input_data: Union[str, bytes, bytearray, Mapping[str, str]], *, placeholder: str = DEFAULT_PLACEHOLDER):
    if not isinstance(placeholder, str) or not placeholder or len(placeholder) > 128:
        raise DotenvCageError(ERROR_CODES["INVALID_INPUT"], "placeholder must be 1 to 128 characters")
    if isinstance(input_data, MappingABC):
        return {key: ("" if value == "" else placeholder) for key, value in input_data.items()}
    if isinstance(input_data, (bytes, bytearray)):
        text = bytes(input_data).decode("utf-8", "replace")
    elif isinstance(input_data, str):
        text = input_data
    else:
        raise DotenvCageError(ERROR_CODES["INVALID_INPUT"], "input must be a string, bytes, or values mapping")
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    output = []
    skip_multiline = False
    multiline_quote = None
    for line in lines:
        if skip_multiline:
            if multiline_quote and _closes_on_line(line, multiline_quote, 0):
                skip_multiline = False
            continue
        match = ASSIGNMENT.match(line)
        if match is None:
            output.append(line)
            continue
        prefix = match.group(1) + match.group(2) + match.group(3)
        rest = match.group(4)
        if not rest:
            output.append(line)
            continue
        first = rest[0]
        if first in ("'", '"'):
            output.append(prefix + first + placeholder + first)
            if not _closes_on_line(rest, first):
                skip_multiline = True
                multiline_quote = first
            continue
        value, comment = _split_unquoted_comment(rest)
        value = value.rstrip(" \t")
        if not value:
            output.append(prefix + comment)
        else:
            output.append(prefix + placeholder + (" " + comment if comment else ""))
    return "\n".join(output)
