"""Transactional safe process environment loader."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping, MutableMapping, Optional, Tuple, Union

from .errors import ERROR_CODES, DotenvCageError
from .file import read_dotenv_file_secure
from .parser import parse_dotenv
from .schema import validate_schema


@dataclass(frozen=True)
class SafeLoadResult:
    ok: bool
    count: int
    loaded: Tuple[str, ...]
    skipped: Tuple[str, ...]
    overridden: Tuple[str, ...]


def safe_load(
    input_data: Optional[Union[str, bytes, bytearray]] = None,
    *,
    path: Optional[str] = None,
    input_type: str = "content",
    target: Optional[MutableMapping[str, str]] = None,
    override: bool = False,
    on_existing: str = "skip",
    schema: Optional[Mapping[str, object]] = None,
    **options,
) -> SafeLoadResult:
    if input_type not in ("content", "path"):
        raise DotenvCageError(ERROR_CODES["INVALID_INPUT"], "input_type must be content or path")
    source = input_data
    read_path = path
    if input_data is None and read_path is None:
        read_path = ".env"
    if input_type == "path" and isinstance(input_data, str):
        read_path = input_data
    if read_path is not None:
        source = read_dotenv_file_secure(read_path)
    if source is None:
        raise DotenvCageError(ERROR_CODES["INVALID_INPUT"], "input content or a path is required")
    parsed = parse_dotenv(source, **options)
    if schema is not None:
        validate_schema(parsed.values, schema)
    if target is None:
        target = os.environ
    if on_existing not in ("skip", "error"):
        raise DotenvCageError(ERROR_CODES["INVALID_INPUT"], "on_existing must be skip or error")
    keys = list(parsed.values.keys())
    conflicts = [key for key in keys if key in target]
    if not override and on_existing == "error" and conflicts:
        raise DotenvCageError(ERROR_CODES["OVERRIDE_DENIED"], "existing process environment keys would be shadowed", keys=tuple(conflicts))
    loaded = []
    skipped = []
    overridden = []
    for key in keys:
        exists = key in target
        if exists and not override:
            skipped.append(key)
            continue
        target[key] = parsed.values[key]
        if exists:
            overridden.append(key)
        else:
            loaded.append(key)
    return SafeLoadResult(True, len(keys), tuple(loaded), tuple(skipped), tuple(overridden))
