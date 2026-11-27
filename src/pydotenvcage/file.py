"""Fail-closed regular-file reads for dotenv files."""
from __future__ import annotations

import os
import stat
from typing import Union

from .constants import DEFAULT_LIMITS
from .errors import ERROR_CODES, DotenvCageError


def _io_error(message: str, path: Union[str, os.PathLike], cause: OSError = None) -> DotenvCageError:
    return DotenvCageError(ERROR_CODES["IO_ERROR"], message, path=str(path))


def read_dotenv_file_secure(path: Union[str, os.PathLike], max_bytes: int = DEFAULT_LIMITS["max_bytes"]) -> bytes:
    """Read a bounded regular file without following a final symlink.

    Devices, FIFOs, directories and other non-regular files fail closed. The opened
    file identity is checked again after reading so a concurrent replacement cannot
    silently swap in different content.
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _io_error("dotenv file is not a directly readable regular file", path, exc)
    try:
        try:
            before = os.fstat(descriptor)
        except OSError as exc:
            raise _io_error("dotenv file metadata could not be read", path, exc)
        if not stat.S_ISREG(before.st_mode):
            raise _io_error("dotenv file must be a regular file", path)
        if before.st_size > max_bytes:
            raise DotenvCageError(ERROR_CODES["INPUT_TOO_LARGE"], "dotenv file exceeds the bounded byte limit", path=str(path))
        chunks = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise DotenvCageError(ERROR_CODES["INPUT_TOO_LARGE"], "dotenv file exceeds the bounded byte limit", path=str(path))
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, getattr(before, "st_mtime_ns", before.st_mtime))
        current = (after.st_dev, after.st_ino, after.st_size, getattr(after, "st_mtime_ns", after.st_mtime))
        if identity != current:
            raise _io_error("dotenv file changed while being read", path)
        return data
    finally:
        os.close(descriptor)
