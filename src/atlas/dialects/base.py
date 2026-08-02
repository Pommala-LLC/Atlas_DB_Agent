from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Protocol

from atlas.core.models import DialectId, RoutineIR, RoutineKind, RoutineParameter, SemanticNodeKind
from .normalization import DialectNormalizer

if TYPE_CHECKING:
    from .scanner import _Statement


class DialectAdapterError(RuntimeError):
    pass


class DialectAdapter(Protocol):
    adapter_id: str
    dialect: DialectId
    capabilities: DialectCapabilities
    normalizer: DialectNormalizer

    def parse(self, source: Path) -> RoutineIR: ...
    def parse_text(self, text: str, source_name: str = "inline.sql") -> RoutineIR: ...


StatementClassification = tuple[SemanticNodeKind, dict[str, object]]
ParameterParser = Callable[[str, str | None], tuple[RoutineParameter, ...]]
RoutineAttributeExtractor = Callable[[str, re.Match[str], RoutineKind], dict[str, object]]


class DialectStatementClassifier(Protocol):
    dialect: DialectId

    def classify(
        self,
        statement: _Statement,
        profile: ProceduralDialectProfile,
        in_declare_section: bool,
    ) -> StatementClassification: ...


class DialectSemanticPolicy(Protocol):
    dialect: DialectId

    def enrich(self, ir: RoutineIR) -> RoutineIR: ...


@dataclass(frozen=True, slots=True)
class DialectCapabilities:
    """Package-owned description of the executable dialect surface.

    This is implementation metadata, not a claim that every future vendor extension
    is inferred. Unsupported syntax remains visible as OPAQUE evidence.
    """

    dialect: DialectId
    routine_kinds: tuple[RoutineKind, ...]
    statement_families: tuple[str, ...]
    vendor_constructs: tuple[str, ...]
    explicit_boundaries: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProceduralDialectProfile:
    dialect: DialectId
    adapter_id: str
    header_patterns: tuple[str, ...]
    function_patterns: tuple[str, ...] = ()
    trigger_patterns: tuple[str, ...] = ()
    package_procedure_patterns: tuple[str, ...] = ()
    package_function_patterns: tuple[str, ...] = ()
    body_style: str = "AFTER_HEADER"
    identifier_quotes: tuple[tuple[str, str], ...] = (("\"", "\""),)
    parameter_prefix: str = ""
    declaration_keywords: tuple[str, ...] = ("DECLARE",)
    assignment_operators: tuple[str, ...] = ("=", ":=")
    elseif_keywords: tuple[str, ...] = ("ELSEIF", "ELSIF")
    raise_keywords: tuple[str, ...] = ("RAISE",)
    call_keywords: tuple[str, ...] = ("CALL",)
    dynamic_keywords: tuple[str, ...] = ("EXECUTE IMMEDIATE", "EXECUTE", "PREPARE")
    result_set_markers: tuple[str, ...] = ()
    lexical_scope_blocks: bool = True
    supports_functions: bool = True
    supports_triggers: bool = True
    reference_urls: tuple[str, ...] = ()
    parameter_parser: ParameterParser | None = None
    routine_attribute_extractor: RoutineAttributeExtractor | None = None
    initial_declare_section: bool = False
