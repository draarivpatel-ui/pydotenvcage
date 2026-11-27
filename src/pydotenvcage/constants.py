"""Bounded defaults and hostile environment key tables."""
from __future__ import annotations

VERSION = "1.0.0"

DEFAULT_LIMITS = {
    "max_bytes": 65536,
    "max_lines": 1024,
    "max_entries": 256,
    "max_key_length": 128,
    "max_value_length": 8192,
    "max_expanded_length": 16384,
    "max_expansion_depth": 16,
    "max_expansion_steps": 1024,
    "max_findings": 256,
}

DANGEROUS_RUNTIME_KEYS = (
    "PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_PRINT_LIBRARIES",
    "NODE_OPTIONS",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "PYTHONINSPECT",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "IFS",
    "CDPATH",
    "GLOBIGNORE",
    "SHELLOPTS",
    "BASHOPTS",
    "PERL5LIB",
    "RUBYLIB",
    "GEM_PATH",
    "CLASSPATH",
    "GIT_SSH_COMMAND",
    "GIT_SSH",
    "GIT_ASKPASS",
    "SSH_ASKPASS",
    "GIT_EXEC_PATH",
    "GIT_PAGER",
    "PAGER",
    "EDITOR",
    "VISUAL",
    "OPENSSL_CONF",
    "PERL5OPT",
    "RUBYOPT",
)

PROTOTYPE_KEYS = (
    "__proto__",
    "constructor",
    "prototype",
    "toString",
    "toLocaleString",
    "valueOf",
    "hasOwnProperty",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "__class__",
    "__dict__",
    "__bases__",
    "__definegetter__",
    "__definesetter__",
    "__lookupgetter__",
    "__lookupsetter__",
)

BIDI_CODEPOINTS = frozenset((0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069))
ZERO_WIDTH_CODEPOINTS = frozenset((0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF))
