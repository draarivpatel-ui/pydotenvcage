"""Error and finding types for pydotenvcage."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


ERROR_CODES = {
    "INPUT_TOO_LARGE": "INPUT_TOO_LARGE",
    "INVALID_INPUT": "INVALID_INPUT",
    "INVALID_ENCODING": "INVALID_ENCODING",
    "INVALID_LINE": "INVALID_LINE",
    "INVALID_KEY": "INVALID_KEY",
    "PROTOTYPE_KEY": "PROTOTYPE_KEY",
    "DANGEROUS_KEY": "DANGEROUS_KEY",
    "DUPLICATE_KEY": "DUPLICATE_KEY",
    "COMMAND_SUBSTITUTION": "COMMAND_SUBSTITUTION",
    "CONTROL_CHARACTER": "CONTROL_CHARACTER",
    "BIDI_CONTROL": "BIDI_CONTROL",
    "UNICODE_SMUGGLING": "UNICODE_SMUGGLING",
    "CR_LINE_ENDING": "CR_LINE_ENDING",
    "MULTILINE_VALUE": "MULTILINE_VALUE",
    "QUOTE_SYNTAX": "QUOTE_SYNTAX",
    "INVALID_ESCAPE": "INVALID_ESCAPE",
    "INVALID_EXPANSION": "INVALID_EXPANSION",
    "EXPANSION_CIRCULAR": "EXPANSION_CIRCULAR",
    "EXPANSION_UNDEFINED": "EXPANSION_UNDEFINED",
    "EXPANSION_TOO_DEEP": "EXPANSION_TOO_DEEP",
    "EXPANSION_TOO_LARGE": "EXPANSION_TOO_LARGE",
    "SECRET_LIKE_VALUE": "SECRET_LIKE_VALUE",
    "INVALID_SCHEMA": "INVALID_SCHEMA",
    "SCHEMA_VIOLATION": "SCHEMA_VIOLATION",
    "OVERRIDE_DENIED": "OVERRIDE_DENIED",
    "IO_ERROR": "IO_ERROR",
}


class DotenvCageError(ValueError):
    """Structured security error raised by strict parsing, validation, and loading."""

    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.reason = message
        for key, value in details.items():
            setattr(self, key, value)


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str
    line: Optional[int] = None
    key: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "line": self.line,
            "key": self.key,
        }


def make_finding(code: str, severity: str, message: str, line: Optional[int] = None, key: Optional[str] = None) -> Finding:
    return Finding(code=code, severity=severity, message=message, line=line, key=key)


def first_error(findings: Tuple[Finding, ...]) -> Optional[Finding]:
    for finding in findings:
        if finding.severity == "error":
            return finding
    return None


def throw_first_error(findings: Tuple[Finding, ...]) -> None:
    finding = first_error(findings)
    if finding is not None:
        raise DotenvCageError(finding.code, finding.message, line=finding.line, key=finding.key, findings=findings)


def redact_input(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    return "<redacted>" if text else ""
