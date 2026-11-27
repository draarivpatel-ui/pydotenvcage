# Contributing

Contributions are welcome once the public repository is open.

## Local verification

Run these commands before sending a change:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 -m pydotenvcage --version
python3 -m build
python3 scripts/check_dist.py dist
```

The project has zero runtime dependencies. Keep it that way unless a maintainer approves a documented exception.

## Rules for security changes

- Add regression tests for every rejected malicious input and every accepted benign input.
- Keep failure closed: ambiguous input must not reach `os.environ`.
- Never commit live tokens, private keys, passwords, or realistic test secrets. Build detector fixtures by concatenating fragments in tests.
- Keep the package standard-library only and typed through `py.typed`.
