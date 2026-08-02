from __future__ import annotations

import argparse

from .support_parts import HANDLERS


def handle(args: argparse.Namespace) -> int | None:
    for handler in HANDLERS:
        result = handler(args)
        if result is not None:
            return result
    return None
