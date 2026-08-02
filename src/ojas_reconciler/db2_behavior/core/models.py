"""Shared immutable model base with no domain dependencies."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class CanonicalModel(BaseModel):
    """Strict, immutable base for machine-readable artifacts."""

    model_config = ConfigDict(frozen=True, extra="forbid", strict=True)
