"""Strict typed schema validation for parsed dotenv values."""
from __future__ import annotations

import json
import re
from collections.abc import Mapping as MappingABC
from typing import Dict, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from .errors import ERROR_CODES, DotenvCageError, Finding, make_finding

KEY_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
INTEGER_PATTERN = re.compile(r"^-?(?:0|[1-9][0-9]*)$")
NUMBER_PATTERN = re.compile(r"^-?(?:(?:0|[1-9][0-9]*)(?:\.[0-9]+)?)(?:[eE][+-]?[0-9]+)?$")
TYPES = frozenset(("string", "integer", "number", "boolean", "enum", "url", "json", "secret"))


def _schema_error(message: str) -> DotenvCageError:
    return DotenvCageError(ERROR_CODES["INVALID_SCHEMA"], message)


def _normalize_schema(schema: Mapping[str, object]):
    if not isinstance(schema, MappingABC):
        raise _schema_error("schema must be a mapping")
    keys = schema.get("keys", {})
    if not isinstance(keys, MappingABC):
        raise _schema_error("schema.keys must be a mapping")
    if len(keys) > 256:
        raise _schema_error("schema has too many keys")
    rules = {}
    for name, rule in keys.items():
        if not isinstance(name, str) or not KEY_PATTERN.match(name):
            raise _schema_error("schema key is not a valid dotenv key: " + str(name))
        if not isinstance(rule, MappingABC):
            raise _schema_error("schema rule must be a mapping for " + name)
        copy = dict(rule)
        if copy.get("type") not in TYPES:
            raise _schema_error("schema rule has an unknown type for " + name)
        if copy["type"] == "enum":
            values = copy.get("values")
            if not isinstance(values, (list, tuple)) or not values or len(values) > 256 or any(not isinstance(item, str) for item in values):
                raise _schema_error("enum rule requires 1 to 256 string values for " + name)
        if "pattern" in copy:
            pattern = copy["pattern"]
            compiled = pattern if hasattr(pattern, "pattern") else None
            source = pattern.pattern if compiled is not None else pattern
            if not isinstance(source, str) or len(source) > 512:
                raise _schema_error("pattern must be a bounded string or compiled regex for " + name)
            if compiled is not None:
                copy["compiled_pattern"] = compiled
            else:
                try:
                    copy["compiled_pattern"] = re.compile(source)
                except re.error:
                    raise _schema_error("pattern does not compile for " + name)
        for field in ("minLength", "maxLength", "min", "max"):
            if field in copy and not isinstance(copy[field], (int, float)):
                raise _schema_error(field + " must be numeric for " + name)
        rules[name] = copy
    required_value = schema.get("required", ())
    if isinstance(required_value, str) or not hasattr(required_value, "__iter__"):
        raise _schema_error("schema.required must be an iterable of keys")
    required = set(required_value)
    if len(required) > 256:
        raise _schema_error("schema has too many required keys")
    for name in required:
        if not isinstance(name, str) or not KEY_PATTERN.match(name):
            raise _schema_error("required entry is not a valid key")
    for name, rule in rules.items():
        if rule.get("required") is True:
            required.add(name)
    return rules, required, schema.get("allowUnknown") is True


def _check_value(value: str, rule: Mapping[str, object]) -> Optional[str]:
    kind = rule.get("type")
    if kind == "string":
        if "minLength" in rule and len(value) < rule["minLength"]:
            return "is shorter than minLength"
        if "maxLength" in rule and len(value) > rule["maxLength"]:
            return "is longer than maxLength"
        if "compiled_pattern" in rule and not rule["compiled_pattern"].search(value):
            return "does not match the required pattern"
        return None
    if kind == "integer":
        if not INTEGER_PATTERN.match(value):
            return "is not a strict integer"
        number = int(value)
        if abs(number) > 9007199254740991:
            return "is outside the safe integer range"
        if "min" in rule and number < rule["min"]:
            return "is below the minimum"
        if "max" in rule and number > rule["max"]:
            return "is above the maximum"
        return None
    if kind == "number":
        if not NUMBER_PATTERN.match(value):
            return "is not a strict finite number"
        number = float(value)
        if number in (float("inf"), float("-inf")) or number != number:
            return "is not finite"
        if "min" in rule and number < rule["min"]:
            return "is below the minimum"
        if "max" in rule and number > rule["max"]:
            return "is above the maximum"
        return None
    if kind == "boolean":
        return None if value in ("true", "false") else "is not exactly true or false"
    if kind == "enum":
        return None if value in rule["values"] else "is not one of the allowed enum values"
    if kind == "url":
        try:
            parsed = urlsplit(value)
        except ValueError:
            return "is not an absolute URL"
        if not parsed.scheme or (parsed.scheme in ("http", "https") and not parsed.netloc):
            return "is not an absolute URL"
        protocols = rule.get("protocols")
        if isinstance(protocols, (list, tuple)) and parsed.scheme + ":" not in protocols:
            return "uses a disallowed URL protocol"
        return None
    if kind == "json":
        if len(value) > 8192:
            return "JSON value is too large"
        try:
            json.loads(value)
        except ValueError:
            return "is not valid JSON"
        return None
    if kind == "secret":
        minimum = rule.get("minLength", 12)
        if len(value) < minimum:
            return "is shorter than the secret minimum"
        if any(ch.isspace() for ch in value):
            return "contains whitespace"
        lowered = value.lower()
        if (value.startswith("<") and value.endswith(">")) or lowered.startswith("paste-") or lowered.startswith("replace-"):
            return "appears to be a placeholder"
        return None
    return "has an unknown type"


def validate_schema(values: Mapping[str, str], schema: Mapping[str, object]) -> Dict[str, object]:
    if not isinstance(values, MappingABC):
        raise DotenvCageError(ERROR_CODES["INVALID_INPUT"], "values must be a mapping")
    rules, required, allow_unknown = _normalize_schema(schema)
    findings = []
    for key in values:
        if key not in rules and not allow_unknown:
            findings.append(make_finding(ERROR_CODES["SCHEMA_VIOLATION"], "error", "unknown key is not allowed by the strict schema", key=key))
    for key in required:
        if key not in values or values[key] == "":
            findings.append(make_finding(ERROR_CODES["SCHEMA_VIOLATION"], "error", "required key is missing or empty", key=key))
    for key, rule in rules.items():
        if key not in values:
            continue
        value = values[key]
        if not isinstance(value, str):
            findings.append(make_finding(ERROR_CODES["SCHEMA_VIOLATION"], "error", "value is not a string", key=key))
            continue
        if value == "" and rule.get("allowEmpty") is True:
            continue
        problem = _check_value(value, rule)
        if problem:
            findings.append(make_finding(ERROR_CODES["SCHEMA_VIOLATION"], "error", key + " " + problem, key=key))
    if findings:
        first = findings[0]
        raise DotenvCageError(ERROR_CODES["SCHEMA_VIOLATION"], first.message, key=first.key, findings=tuple(findings))
    return {"ok": True, "validatedKeys": len(rules)}
