from __future__ import annotations

from typing import Literal
from pydantic import Field

from atlas.dialects.db2.clp import (
    ClpSourceRange,
    Db2ClpScript,
    Db2ClpScriptSegmenter,
    Db2ClpSourceUnit,
)
from ..core.models import CanonicalModel
from .models import ProcedureParseResult


class Db2ScriptParseResult(CanonicalModel):
    schema_version: Literal["db2-script-parse-1.0"] = "db2-script-parse-1.0"
    artifact_id: str
    artifact_revision_id: str
    source_name: str
    source_digest: str
    detected_terminator: str
    expected_source_unit_count: int = Field(ge=0)
    discovered_source_unit_count: int = Field(ge=0)
    procedure_results: tuple[ProcedureParseResult, ...]
    complete_count: int = Field(ge=0)
    partial_count: int = Field(ge=0)
    blocked_count: int = Field(ge=0)
    unclassified_fragment_count: int = Field(ge=0)
    source_unit_count_matches: bool


__all__ = [
    "ClpSourceRange",
    "Db2ClpSourceUnit",
    "Db2ClpScript",
    "Db2ClpScriptSegmenter",
    "Db2ScriptParseResult",
]
