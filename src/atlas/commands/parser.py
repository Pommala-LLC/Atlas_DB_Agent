from __future__ import annotations

import argparse
from pathlib import Path

from atlas import __version__
from .common import dialect


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="atlas", description="Atlas multi-database stored-routine behavior intelligence")
    parser.add_argument("--version", action="version", version=f"Atlas {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    dialects = sub.add_parser("dialects", help="List admitted dialect adapters.")
    dialects.add_argument("--json", action="store_true")
    sub.add_parser("coverage", help="Print the digest-bound dialect semantic coverage manifest.")
    sub.add_parser("naming", help="Print the frozen naming and compatibility contract.")
    sub.add_parser("capabilities", help="Print implementation and validation state by dialect.")
    _analysis_parser(sub, "analyze", "Analyze every stored routine in one source file.")
    unit = _analysis_parser(sub, "analyze-unit", "Discover and analyze every stored routine in one source file.")
    unit.set_defaults(unit_only=True)
    public = sub.add_parser("validate-public-db2", help="Validate a pinned public Db2 repository manifest.")
    public.add_argument("manifest", type=Path)
    public.add_argument("--repository-root", type=Path, required=True)
    public.add_argument("--output", type=Path, required=True)
    serve = sub.add_parser("serve", help="Run the Atlas procedure review console.")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--workspace", default="reports/atlas")
    serve.add_argument("--tenant-ref", default="tenant:local")
    serve.add_argument("--actor-ref", default="actor:local-admin")
    serve.add_argument("--role", default="ADMIN", choices=("VIEWER", "ANALYST", "REVIEWER", "ADMIN"))
    return parser


def _analysis_parser(sub, name: str, help_text: str):
    command = sub.add_parser(name, help=help_text)
    command.add_argument("source", type=Path)
    command.add_argument("--dialect", required=True, type=dialect)
    command.add_argument("--output", type=Path, required=True)
    command.add_argument("--emit-gherkin", action="store_true")
    command.add_argument("--emit-graph", action="store_true")
    return command
