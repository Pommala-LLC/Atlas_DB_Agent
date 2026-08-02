"""Thin CLI composition facade."""
from __future__ import annotations

from .argparse_builder import build_parser
from .dispatcher import main

__all__ = ["build_parser", "main"]
