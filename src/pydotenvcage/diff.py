"""Redacted dotenv diffing."""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Mapping as MappingABC
from typing import Dict, Mapping, Tuple, Union

from .errors import ERROR_CODES, DotenvCageError
from .parser import parse_dotenv


@dataclass(frozen=True)
class DiffChange:
    key: str
    left: str
    right: str

    def to_dict(self):
        return {
            "key": self.key,
            "left": self.left,
            "right": self.right,
        }


@dataclass(frozen=True)
class DiffResult:
    same: bool
    added: Tuple[str, ...]
    removed: Tuple[str, ...]
    changed: Tuple[DiffChange, ...]
    unchanged: Tuple[str, ...]
    redacted: bool

    def to_dict(self):
        return {
            "same": self.same,
            "added": list(self.added),
            "removed": list(self.removed),
            "changed": [item.to_dict() for item in self.changed],
            "unchanged": list(self.unchanged),
            "redacted": self.redacted,
        }



def _values_from(input_data, options) -> Mapping[str, str]:
    if isinstance(input_data, (str, bytes, bytearray)):
        return parse_dotenv(input_data, **options).values
    if hasattr(input_data, "values") and not isinstance(input_data, MappingABC):
        values = getattr(input_data, "values")
        if isinstance(values, MappingABC):
            return values
    if isinstance(input_data, MappingABC):
        return input_data
    raise DotenvCageError(ERROR_CODES["INVALID_INPUT"], "diff inputs must be dotenv content, parse results, or values mappings")


def diff_dotenv(left_input, right_input, *, redact: bool = True, **options) -> DiffResult:
    left = _values_from(left_input, options)
    right = _values_from(right_input, options)
    added = []
    removed = []
    changed = []
    unchanged = []
    for key in sorted(set(left.keys()) | set(right.keys())):
        has_left = key in left
        has_right = key in right
        if has_left and not has_right:
            removed.append(key)
        elif not has_left and has_right:
            added.append(key)
        elif left[key] == right[key]:
            unchanged.append(key)
        else:
            if redact:
                item = DiffChange(key, "<redacted>", "<redacted>")
            else:
                item = DiffChange(key, str(left[key]), str(right[key]))
            changed.append(item)
    return DiffResult(
        same=not added and not removed and not changed,
        added=tuple(added),
        removed=tuple(removed),
        changed=tuple(changed),
        unchanged=tuple(unchanged),
        redacted=redact,
    )
