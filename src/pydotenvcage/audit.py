"""Non-throwing dotenv security audit API."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple, Union

from .errors import ERROR_CODES, Finding, first_error, make_finding
from .parser import scan_dotenv
from .security import detect_secret_kinds


@dataclass(frozen=True)
class AuditReport:
    ok: bool
    findings: Tuple[Finding, ...]
    error_count: int
    warning_count: int
    keys: Tuple[str, ...]
    entry_count: int
    references: Dict[str, Tuple[str, ...]]

    def to_dict(self):
        return {
            "ok": self.ok,
            "findings": [finding.to_dict() for finding in self.findings],
            "errorCount": self.error_count,
            "warningCount": self.warning_count,
            "keys": list(self.keys),
            "entryCount": self.entry_count,
            "references": {key: list(refs) for key, refs in self.references.items()},
        }


def audit_dotenv(input_data: Union[str, bytes, bytearray], *, context: str = "runtime", detect_secrets: bool = True, **options) -> AuditReport:
    scanned = scan_dotenv(input_data, **options)
    findings = list(scanned.findings)
    severity = "error" if context in ("example", "committed") else "warning"
    if detect_secrets:
        for entry in scanned.entries:
            candidates = [entry.value]
            effective = scanned.values.get(entry.key, entry.value)
            if effective not in candidates:
                candidates.append(effective)
            kinds = sorted(set(kind for candidate in candidates for kind in detect_secret_kinds(candidate)))
            if kinds:
                findings.append(make_finding(ERROR_CODES["SECRET_LIKE_VALUE"], severity, "value resembles committed secret material: " + ", ".join(kinds), entry.line, entry.key))
    findings.sort(key=lambda item: (item.line or 0, item.code))
    error = first_error(tuple(findings))
    return AuditReport(
        ok=error is None,
        findings=tuple(findings),
        error_count=sum(1 for item in findings if item.severity == "error"),
        warning_count=sum(1 for item in findings if item.severity == "warning"),
        keys=tuple(sorted({entry.key for entry in scanned.entries})),
        entry_count=len(scanned.entries),
        references=scanned.references,
    )
