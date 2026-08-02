from __future__ import annotations

from atlas.commands import HANDLERS
from atlas.commands.parser import build_parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for handler in HANDLERS:
        result = handler(args)
        if result is not None:
            return result
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
