"""pydotenvcage command line interface."""
from __future__ import annotations

import argparse
import json
import sys

from .audit import audit_dotenv
from .constants import VERSION
from .diff import diff_dotenv
from .errors import DotenvCageError
from .file import read_dotenv_file_secure
from .parser import parse_dotenv
from .redact import redact_dotenv
from .schema import validate_schema


def _read_input(path: str) -> bytes:
    return read_dotenv_file_secure(path)


def _emit(value) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pydotenvcage")
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")

    audit = sub.add_parser("audit")
    audit.add_argument("file")
    audit.add_argument("--example", action="store_true")
    audit.add_argument("--committed", action="store_true")
    audit.add_argument("--json", action="store_true")

    parse = sub.add_parser("parse")
    parse.add_argument("file")
    parse.add_argument("--show-values", action="store_true")
    parse.add_argument("--json", action="store_true")

    redact = sub.add_parser("redact")
    redact.add_argument("file")
    redact.add_argument("--placeholder", default="<redacted>")

    diff = sub.add_parser("diff")
    diff.add_argument("left_file")
    diff.add_argument("right_file")
    diff.add_argument("--show-values", action="store_true")
    diff.add_argument("--json", action="store_true")

    validate = sub.add_parser("validate")
    validate.add_argument("file")
    validate.add_argument("--schema", required=True)
    validate.add_argument("--json", action="store_true")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    if args.version:
        print("pydotenvcage " + VERSION)
        return 0
    if not args.command:
        _parser().print_usage(sys.stderr)
        return 2
    try:
        if args.command == "audit":
            context = "example" if args.example else "committed" if args.committed else "runtime"
            report = audit_dotenv(_read_input(args.file), context=context)
            output = report.to_dict()
            if args.json:
                _emit(output)
            else:
                for finding in report.findings:
                    print(str(finding.line or "-") + " " + finding.severity + " " + finding.code + (" " + finding.key if finding.key else ""))
                print("ok" if report.ok else "failed")
            return 0 if report.ok else 1
        if args.command == "parse":
            parsed = parse_dotenv(_read_input(args.file))
            values = parsed.values if args.show_values else {key: ("" if value == "" else "<redacted>") for key, value in parsed.values.items()}
            _emit({"ok": True, "values": values, "keys": sorted(parsed.values), "entries": len(parsed.entries)})
            return 0
        if args.command == "redact":
            text = _read_input(args.file)
            sys.stdout.write(redact_dotenv(text, placeholder=args.placeholder))
            if not text.endswith(b"\n"):
                sys.stdout.write("\n")
            return 0
        if args.command == "diff":
            result = diff_dotenv(_read_input(args.left_file), _read_input(args.right_file), redact=not args.show_values)
            _emit(result.to_dict())
            return 0 if result.same else 1
        if args.command == "validate":
            schema = json.loads(_read_input(args.schema))
            parsed = parse_dotenv(_read_input(args.file))
            _emit(validate_schema(parsed.values, schema))
            return 0
    except DotenvCageError as exc:
        _emit({"ok": False, "code": exc.code, "message": exc.reason, "line": getattr(exc, "line", None), "key": getattr(exc, "key", None)})
        return 1
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
