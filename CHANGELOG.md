# Changelog

## 1.0.0

Initial local release candidate.

- Strict bounded dotenv parser with duplicate-key, quoting, control-character, Unicode, and line-ending defenses.
- Bounded `${VAR}` expansion with undefined-reference, depth, step-count, output-size, and circular-reference enforcement.
- Loader, runtime, shell substitution, prototype and introspection key, transport-command key, and process environment shadowing defenses.
- Secret-material detectors for cloud keys, repository tokens, payment keys, private keys, JWTs, and credentialed database URLs.
- Safe environment loading with `override=False` by default.
- Typed schema validation, redaction, diffing, CLI, examples, type markers, wheel, and source distribution checks.

- Fail-closed regular-file loading, fingerprint-free redacted diffs, edge-free diagnostic redaction, case-variant duplicate rejection, and byte-budgeted expansion output.
