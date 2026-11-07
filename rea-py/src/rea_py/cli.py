"""Command line interface: `rea-py <tool> <path> [options]`, `rea-py list-tools`, `rea-py serve`."""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__, analyzers  # noqa: F401  (import registers tools)
from .registry import TOOLS, call_tool
from .util import ReaError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rea-py", description="Static reverse-engineering analyzers (CLI + MCP server).")
    p.add_argument("--version", action="version", version=f"rea-py {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="Run as an MCP server on stdio.")
    sub.add_parser("list-tools", help="List available analysis tools.")
    for t in TOOLS.values():
        sp = sub.add_parser(t.name.replace("_", "-"), help=t.description, description=t.description)
        sp.set_defaults(_tool=t.name)
        for key, spec in t.schema["properties"].items():
            desc = spec.get("description", "")
            if key == "path":
                sp.add_argument("path", help=desc)
            elif spec.get("type") == "boolean":
                sp.add_argument("--" + key.replace("_", "-"), dest=key, action="store_true", help=desc)
            else:
                sp.add_argument("--" + key.replace("_", "-"), dest=key, type=int if spec.get("type") == "integer" else str, help=desc)
        sp.add_argument("--compact", action="store_true", help="Print compact JSON.")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "serve":
        from .mcp_server import serve
        if hasattr(sys.stdin, "reconfigure"):
            sys.stdin.reconfigure(encoding="utf-8")
            sys.stdout.reconfigure(encoding="utf-8")
        serve()
        return 0
    if args.command == "list-tools":
        for t in TOOLS.values():
            print(f"{t.name.replace('_', '-'):34} {t.description}")
        return 0
    params = {k: v for k, v in vars(args).items() if k not in ("command", "_tool", "compact") and v is not None and v is not False}
    try:
        out = call_tool(args._tool, params)
    except ReaError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(out, default=str, indent=None if args.compact else 2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
