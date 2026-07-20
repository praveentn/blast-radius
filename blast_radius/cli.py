"""blast-radius: score what an AI agent could destroy before anyone can stop it."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .report import Report
from .scanner import (
    capabilities_from_credentials,
    load_manifest,
    scan_environment,
    scan_tree,
)

DESCRIPTION = """\
Score the blast radius of an AI agent.

Two surfaces get scanned:
  declared   the tools you handed it (--manifest)
  ambient    the credentials it can find on its own (--path, --env)

The second one is where the expensive incidents come from.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blast-radius",
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "path",
        nargs="?",
        default=".",
        help="working directory the agent runs in (default: current directory)",
    )
    p.add_argument(
        "-m",
        "--manifest",
        help="JSON tool manifest: a list, {'tools': [...]}, or {'mcpServers': {...}}",
    )
    p.add_argument(
        "--env",
        action="store_true",
        help="also scan the current process environment for credentials",
    )
    p.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    p.add_argument(
        "--fail-over",
        type=int,
        metavar="N",
        help="exit 1 if the score exceeds N (for CI)",
    )
    p.add_argument(
        "--fail-on-irreversible",
        action="store_true",
        help="exit 1 if any ungated irreversible capability is reachable (for CI)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path)

    if not root.exists():
        print(f"blast-radius: no such path: {root}", file=sys.stderr)
        return 2

    declared = []
    if args.manifest:
        try:
            declared = load_manifest(args.manifest)
        except (OSError, ValueError) as exc:
            print(f"blast-radius: could not read manifest: {exc}", file=sys.stderr)
            return 2

    credentials = scan_tree(root)
    if args.env:
        credentials += scan_environment()

    report = Report(
        declared=declared,
        ambient=capabilities_from_credentials(credentials),
        credentials=credentials,
        root=str(root.resolve()),
    )

    if args.json:
        print(report.to_json())
    else:
        color = not args.no_color and sys.stdout.isatty() and os.name != "nt"
        print(report.to_text(color=color))

    if args.fail_on_irreversible and report.nine_second:
        return 1
    if args.fail_over is not None and report.score > args.fail_over:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
