# pydotenvcage

Zero-dependency strict dotenv security firewall for Python 3.9 and newer.

pydotenvcage parses `.env` content as hostile input. It blocks shell command substitution, runtime loader hijacking keys, duplicate key shadowing, silent environment replacement, malformed quoting, unbounded expansion work, circular `${VAR}` references, control characters, bidirectional Unicode controls, and secret material leaked into example or committed files.

## Install

```sh
python3 -m pip install pydotenvcage
```

Python 3.9 or newer is required. Runtime code uses only the standard library.

## Quick start

```python
from pydotenvcage import parse_dotenv, safe_load

parsed = parse_dotenv("PORT=8080\nHOST=localhost\n")
print(parsed.values["PORT"])

result = safe_load(
    "PORT=8080\n",
    target={},
    schema={
        "required": ["PORT"],
        "keys": {"PORT": {"type": "integer", "min": 1, "max": 65535}},
    },
)
print(result.loaded, result.skipped)
```

`safe_load` is transactional. The file is parsed, security checked, expanded, and schema validated before any key is written. `override` is `False` by default, so existing environment keys are skipped and reported rather than silently replaced.

## API

### `parse_dotenv(input_data, **options)`

Parses a string or UTF-8 bytes and returns `ParseResult` with:

- `values`: first-value key mapping after bounded expansion.
- `entries`: key, value, quote style, line, and export metadata.
- `references`: variable expansion references by key.

It raises `DotenvCageError` on the first error and attaches the full `findings` tuple.

### `audit_dotenv(input_data, context="runtime", **options)`

Returns an `AuditReport` instead of raising. Contexts are `runtime`, `example`, and `committed`. Secret-shaped values are warnings in runtime context because real local secrets are expected there. They are errors in example and committed contexts.

### `safe_load(input_data=None, **options)`

Loads values into `os.environ` or a caller-supplied mutable `target` mapping. Input is content by default. Pass `input_type="path"` or `path=` to read a file.

```python
safe_load(
    ".env.production",
    input_type="path",
    override=False,
    on_existing="error",
    schema=schema,
)
```

### `redact_dotenv(input_data, placeholder="<redacted>")`

Redacts assignment values while preserving comments and unassigned lines. String input returns a redacted string. A values mapping returns a redacted values mapping. Multiline quoted payloads are removed rather than partially leaked.

### `diff_dotenv(left, right, redact=True, **options)`

Compares two dotenv sources, parse results, or values mappings. Values are redacted by default without hashes, lengths, or other brute-forceable fingerprints. Pass `redact=False` only when exposing values is safe.

### `validate_schema(values, schema)`

Strict typed validation for required and optional keys. Supported types are `string`, `integer`, `number`, `boolean`, `enum`, `url`, `json`, and `secret`. Unknown keys are rejected unless `allowUnknown` is true.

## Security behavior

The strict parser rejects or reports:

- `$(` and backtick shell substitution markers.
- Loader, shell, and runtime control keys such as `PATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `NODE_OPTIONS`, `PYTHONPATH`, `BASH_ENV`, `PROMPT_COMMAND`, and `IFS`.
- Prototype and introspection keys such as `__proto__`, `constructor`, `prototype`, and dunder-form keys.
- Duplicate keys, including case-only variants that shadow across platforms.
- Raw control characters, NUL bytes, carriage-return smuggling, bidirectional controls, and zero-width formatting.
- Unterminated quotes, unsupported escapes, trailing content after a quote, and multiline values unless `allow_multiline=True`.
- Undefined, malformed, circular, too-deep, too-large, or too-frequent variable expansion.
- Symlinked, non-regular, oversized, or concurrently swapped dotenv files when loading from a path.
- Secret-shaped cloud keys, repository tokens, payment keys, private keys, JWTs, and database URLs with embedded passwords when auditing, including shadowed duplicate values.

Expansion is bounded and enabled by default. Only braced `${NAME}` references expand. Use `\${NAME}` for a literal reference. External expansion values are not read from the real process environment unless supplied through `expansion_env`.

## Parser dialect

Accepted lines are blank lines, comments, and strict assignments:

```dotenv
# comment
PORT=8080
HOST="localhost"
export MODE=production
```

Keys must match `[A-Za-z_][A-Za-z0-9_]*`. Unquoted values may contain spaces and use ` #` for an inline comment. Single quotes are literal. Double quotes support `\\`, `\"`, `\'`, `\$`, `\n`, `\r`, and `\t` escapes, but decoded control characters are rejected unless the relevant bounded multiline behavior is explicitly enabled.

CRLF line endings are accepted as line endings. Bare carriage returns are rejected. Input is bounded to 64 KiB, 1024 lines, 256 assignments, 128-byte keys, and 8192-byte values by default. Limits can be tightened through the `limits` mapping; they cannot be disabled.

## CLI

```sh
pydotenvcage audit .env --committed
pydotenvcage parse .env
pydotenvcage redact .env
pydotenvcage diff .env .env.production
pydotenvcage validate .env --schema schema.json
python3 -m pydotenvcage --version
```

`parse` and `diff` redact values unless `--show-values` is explicitly passed. Audit exits 1 when errors are present. Usage errors exit 2.

## Examples

See `examples/basic_load.py`, `examples/audit_and_redact.py`, and `examples/schema_and_diff.py`.

## License

MIT
