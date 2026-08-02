from __future__ import annotations

from importlib.resources import files
from pathlib import Path


def packaged_contract_path(filename: str) -> Path:
    resource = files("ojas_reconciler.db2_behavior.contracts_schemas").joinpath(filename)
    return Path(str(resource))
