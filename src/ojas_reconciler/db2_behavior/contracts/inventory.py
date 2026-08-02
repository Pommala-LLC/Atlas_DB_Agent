"""Gate 0 inventory port."""
from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..parsing.inventory_models import ProcedureInventory


class ProcedureInventoryPort(Protocol):
    def analyze_path(self, path: Path) -> ProcedureInventory: ...
