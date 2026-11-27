# Security policy

pydotenvcage is a security boundary for untrusted or semi-trusted dotenv files. It is designed to fail closed before values reach `os.environ`.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | yes |

## Reporting

Do not open a public issue with a proof of concept that contains live secret material. Redact values first with `pydotenvcage redact` or `redact_dotenv`. Report repository-security issues through the repository security contact listed on the project page.

## Threat model

The parser treats dotenv input as hostile. It blocks shell substitution markers, loader and runtime hijacking keys, exact and case-variant duplicate key shadowing, symlinked or non-regular file input, unbounded input and expansion work, raw control characters, bidirectional Unicode controls, malformed quoting, and unsafe process environment replacement.

Secret detection is an audit control, not proof that a value is or is not a secret. Rotate any value that appears in a committed file, even when a detector does not match it.

## Non-goals

The library does not execute shell commands and does not store secrets. It cannot make an already compromised host safe. Application code still needs least-privilege secret storage and rotation.
