"""pydotenvcage public API."""
from __future__ import annotations

from .audit import AuditReport, audit_dotenv
from .constants import DANGEROUS_RUNTIME_KEYS, DEFAULT_LIMITS, PROTOTYPE_KEYS, VERSION
from .diff import DiffChange, DiffResult, diff_dotenv
from .errors import ERROR_CODES, DotenvCageError, Finding, redact_input
from .load import SafeLoadResult, safe_load
from .parser import Entry, ParseResult, ScanResult, parse_dotenv, scan_dotenv
from .redact import redact_dotenv
from .schema import validate_schema
from .security import detect_secret_kinds, is_dangerous_runtime_key, is_prototype_key

__all__ = [
    "AuditReport",
    "DANGEROUS_RUNTIME_KEYS",
    "DEFAULT_LIMITS",
    "DiffChange",
    "DiffResult",
    "DotenvCageError",
    "Entry",
    "ERROR_CODES",
    "Finding",
    "ParseResult",
    "PROTOTYPE_KEYS",
    "SafeLoadResult",
    "ScanResult",
    "VERSION",
    "audit_dotenv",
    "detect_secret_kinds",
    "diff_dotenv",
    "is_dangerous_runtime_key",
    "is_prototype_key",
    "parse_dotenv",
    "redact_dotenv",
    "redact_input",
    "safe_load",
    "scan_dotenv",
    "validate_schema",
]
