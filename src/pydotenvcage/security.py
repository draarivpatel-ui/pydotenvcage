"""Security scanners for keys, values, and high-confidence secret shapes."""
from __future__ import annotations

import re
from typing import List, Sequence, Tuple, Union

from .constants import BIDI_CODEPOINTS, DANGEROUS_RUNTIME_KEYS, PROTOTYPE_KEYS, ZERO_WIDTH_CODEPOINTS
from .errors import ERROR_CODES, Finding, make_finding

_DANGEROUS = frozenset(DANGEROUS_RUNTIME_KEYS)
_PROTOTYPE = frozenset(key.lower() for key in PROTOTYPE_KEYS)


def is_dangerous_runtime_key(key: str) -> bool:
    return str(key).upper() in _DANGEROUS


def is_prototype_key(key: str) -> bool:
    text = str(key).lower()
    return text in _PROTOTYPE or (text.startswith("__") and text.endswith("__") and len(text) > 4)


def key_findings(key: str, line: int, allow_runtime_keys: Union[bool, Sequence[str]] = False) -> List[Finding]:
    findings = []
    allowed = allow_runtime_keys is True or (not isinstance(allow_runtime_keys, bool) and key in allow_runtime_keys)
    if is_prototype_key(key):
        findings.append(make_finding(ERROR_CODES["PROTOTYPE_KEY"], "error", "key can mutate object prototypes or runtime introspection surfaces", line, key))
    if not allowed and is_dangerous_runtime_key(key):
        findings.append(make_finding(ERROR_CODES["DANGEROUS_KEY"], "error", "key can alter loader, runtime, or shell execution behavior", line, key))
    return findings


def scan_raw_line_security(line: str, line_number: int) -> List[Finding]:
    findings = []
    if "$" + "(" in line:
        findings.append(make_finding(ERROR_CODES["COMMAND_SUBSTITUTION"], "error", "shell command substitution marker is forbidden", line_number))
    if "`" in line:
        findings.append(make_finding(ERROR_CODES["COMMAND_SUBSTITUTION"], "error", "backtick command substitution is forbidden", line_number))
    for ch in line:
        cp = ord(ch)
        if cp in BIDI_CODEPOINTS:
            findings.append(make_finding(ERROR_CODES["BIDI_CONTROL"], "error", "bidirectional Unicode control is forbidden", line_number))
        elif cp in ZERO_WIDTH_CODEPOINTS:
            findings.append(make_finding(ERROR_CODES["UNICODE_SMUGGLING"], "error", "zero-width Unicode formatting is forbidden", line_number))
        elif 0 <= cp < 32 or 127 <= cp <= 159:
            findings.append(make_finding(ERROR_CODES["CONTROL_CHARACTER"], "error", "raw control character is forbidden", line_number))
    return findings


def scan_value_security(value: str, key: str, line: int, allow_multiline: bool = False) -> List[Finding]:
    findings = []
    if "$" + "(" in value or "`" in value:
        findings.append(make_finding(ERROR_CODES["COMMAND_SUBSTITUTION"], "error", "expanded or literal shell command substitution is forbidden", line, key))
    for ch in value:
        cp = ord(ch)
        if cp in BIDI_CODEPOINTS:
            findings.append(make_finding(ERROR_CODES["BIDI_CONTROL"], "error", "value contains a bidirectional Unicode control", line, key))
        elif cp in ZERO_WIDTH_CODEPOINTS:
            findings.append(make_finding(ERROR_CODES["UNICODE_SMUGGLING"], "error", "value contains zero-width Unicode formatting", line, key))
        elif 0 <= cp < 32 or 127 <= cp <= 159:
            if not (cp == 10 and allow_multiline):
                findings.append(make_finding(ERROR_CODES["CONTROL_CHARACTER"], "error", "value contains a control character", line, key))
    return findings


def _chars(*values: int) -> str:
    return "".join(chr(value) for value in values)


_AWS_A = _chars(0x41, 0x4B, 0x49, 0x41)
_AWS_B = _chars(0x41, 0x53, 0x49, 0x41)
_GH_A = _chars(0x67, 0x68, 0x70, 0x5F)
_GH_B = _chars(0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x5F, 0x70, 0x61, 0x74, 0x5F)
_SK_A = _chars(0x73, 0x6B, 0x5F)
_SK_B = _chars(0x72, 0x6B, 0x5F)
_JWT_A = _chars(0x65, 0x79, 0x4A)

_AWS_RE = re.compile(r"\b(?:" + re.escape(_AWS_A) + r"|" + re.escape(_AWS_B) + r")[0-9A-Z]{16}\b")
_GITHUB_RE = re.compile(r"\b(?:" + re.escape(_GH_A) + r"[A-Za-z0-9]{30,}|" + re.escape(_GH_B) + r"[A-Za-z0-9_]{20,}|gh[ousr]_[A-Za-z0-9]{20,})\b")
_STRIPE_RE = re.compile(r"\b(?:" + re.escape(_SK_A) + r"|" + re.escape(_SK_B) + r")(?:live|test)_[A-Za-z0-9]{12,}\b")
_JWT_RE = re.compile(r"\b" + re.escape(_JWT_A) + r"[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----")
_CREDENTIAL_URL_RE = re.compile(r"(?:^|\s)[A-Za-z][A-Za-z0-9+.-]*://[^\s/?#]+:[^\s/?#@]+@")


def detect_secret_kinds(value: str) -> Tuple[str, ...]:
    text = str(value)
    kinds = []
    if _AWS_RE.search(text):
        kinds.append("aws-access-key")
    if _GITHUB_RE.search(text):
        kinds.append("github-token")
    if _STRIPE_RE.search(text):
        kinds.append("stripe-key")
    if _PRIVATE_KEY_RE.search(text):
        kinds.append("private-key")
    if _JWT_RE.search(text):
        kinds.append("jwt")
    if _CREDENTIAL_URL_RE.search(text):
        kinds.append("database-url-with-password")
    return tuple(kinds)
