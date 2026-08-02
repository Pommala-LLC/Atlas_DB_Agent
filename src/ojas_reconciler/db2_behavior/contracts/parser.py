from __future__ import annotations

from pathlib import Path
from typing import Protocol

from ..parsing.clp import Db2ScriptParseResult
from ..parsing.models import EmbeddedQueryParseResult, EmbeddedQueryRequest, ProcedureParseResult


class Db2ProcedureParserPort(Protocol):
    """Technology-neutral contract for parsing DB2 stored-procedure source."""

    def parse_file(self, path: Path) -> ProcedureParseResult: ...

    def parse_text(
        self,
        *,
        source_text: str,
        artifact_id: str,
        artifact_revision_id: str,
        source_name: str = "<memory>",
    ) -> ProcedureParseResult: ...

    def parse_script_file(self, path: Path) -> Db2ScriptParseResult: ...

    def parse_script_text(
        self,
        *,
        source_text: str,
        artifact_id: str,
        artifact_revision_id: str,
        source_name: str = "<memory>",
    ) -> Db2ScriptParseResult: ...


class EmbeddedSqlParserPort(Protocol):
    """Parses residual SQL after SQL PL bindings have been removed."""

    def parse(self, request: EmbeddedQueryRequest) -> EmbeddedQueryParseResult: ...
