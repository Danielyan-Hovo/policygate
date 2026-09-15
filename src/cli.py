from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .engine import PolicyEngine
from .models import PolicyRule
from .parser import DocumentError, load_document
from .reporting import as_json, as_sarif, format_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="policygate")
    subparsers = parser.add_subparsers(dest="command", required=True)
    evaluate = subparsers.add_parser("evaluate")
    evaluate.add_argument("document", type=Path)
    evaluate.add_argument("--policy", type=Path, action="append", default=[])
    evaluate.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    return parser


def run_evaluate(args: argparse.Namespace) -> int:
    try:
        document = load_document(args.document)
        rules = [PolicyRule(**load_document(policy)) for policy in args.policy]
        report = PolicyEngine(rules).evaluate(document)
    except (DocumentError, ValueError) as exc:
        print(f"PolicyGate error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(as_json(report), indent=2))
    elif args.format == "sarif":
        print(json.dumps(as_sarif(report), indent=2))
    else:
        print(format_text(report))
    return 1 if not report.passed else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "evaluate":
        return run_evaluate(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
