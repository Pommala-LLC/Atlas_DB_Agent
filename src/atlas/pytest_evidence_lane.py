from __future__ import annotations

import argparse
import json
from pathlib import Path

from atlas.release_evidence import run_pytest


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute one isolated pytest evidence lane.")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--launcher", choices=("module", "console"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    pytest_args = tuple(args.pytest_args[1:] if args.pytest_args[:1] == ["--"] else args.pytest_args)
    result = run_pytest(args.root, launcher=args.launcher, args=pytest_args)
    payload = {
        "launcher": result.launcher,
        "command": list(result.command),
        "returncode": result.completed.returncode,
        "stdout": result.completed.stdout,
        "stderr": result.completed.stderr,
        "structured": result.structured,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
