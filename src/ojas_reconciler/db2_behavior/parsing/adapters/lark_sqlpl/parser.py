from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Literal, cast

from lark import Lark

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.parsing.lexer import Db2LexicalScanner, Token, TokenKind
from ojas_reconciler.db2_behavior.parsing.clp import Db2ClpScriptSegmenter, Db2ScriptParseResult
from ojas_reconciler.db2_behavior.type_system.models import DeclaredSymbolType
from ojas_reconciler.db2_behavior.type_system.resolver import parse_declared_sql_type
from ojas_reconciler.db2_behavior.parsing.models import (
    AssignmentBinding,
    AstNode,
    CompoundRegion,
    ConditionDeclaration,
    CursorOpenEffect,
    DynamicExecuteBinding,
    DynamicPrepareBinding,
    FetchBinding,
    HandlerKind,
    HandlerRegion,
    IfArm,
    IfRegion,
    LoopKind,
    LoopRegion,
    MergeAction,
    MergeStructure,
    NodeKind,
    ParseFinding,
    ParseOutcome,
    ParserFindingCode,
    ProcedureAst,
    ProcedureParameter,
    ProcedureParseResult,
    ReturnedCursorDeclaration,
    SelectIntoBinding,
    SourceRange,
    StateAccessFact,
    StateAccessKind,
)


from .binding_mixin import BindingParsingMixin
from .header_mixin import HeaderParsingMixin
from .region_mixin import RegionParsingMixin
from .source_mixin import SourceUtilitiesMixin
from .symbol_mixin import SymbolAnalysisMixin


class LarkSqlPlSpikeParser(
    HeaderParsingMixin,
    RegionParsingMixin,
    BindingParsingMixin,
    SymbolAnalysisMixin,
    SourceUtilitiesMixin,
):
    """Deterministic DB2 SQL PL procedural-shell adapter behind the parser port."""

    adapter_name = "LARK_SQLPL_SPIKE"
    adapter_version = "0.9.0"
    def __init__(self) -> None:
        grammar_path = Path(__file__).with_name("header.lark")
        grammar = grammar_path.read_text(encoding="utf-8")
        self._header_parser = Lark(
            grammar,
            parser="earley",
            ambiguity="explicit",
            propagate_positions=True,
            start="start",
        )
        self._condition_parser = Lark(
            grammar,
            parser="earley",
            ambiguity="explicit",
            propagate_positions=True,
            start="condition_decl_stmt",
        )
        self._handler_condition_parser = Lark(
            grammar,
            parser="earley",
            ambiguity="explicit",
            propagate_positions=True,
            start="handler_condition",
        )
        self._scanner = Db2LexicalScanner()
        self._script_segmenter = Db2ClpScriptSegmenter()

    def parse_file(self, path: Path) -> ProcedureParseResult:
        data = path.read_bytes()
        text = data.decode("utf-8-sig")
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        script = self._script_segmenter.segment_text(text, source_name=path.name)
        if script.expected_source_unit_count > 1:
            finding = ParseFinding(
                code=ParserFindingCode.MULTIPLE_PROCEDURE_SOURCE_UNITS,
                message=(
                    f"{script.expected_source_unit_count} CREATE PROCEDURE units were found; "
                    "use parse_script_file() so every unit is analyzed independently."
                ),
                consequence="No procedure AST was emitted from the file-level compatibility API.",
            )
            return ProcedureParseResult(
                parser_adapter=self.adapter_name,
                parser_version=self.adapter_version,
                artifact_id=path.as_posix(),
                artifact_revision_id=digest,
                source_name=path.name,
                source_digest="sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
                normalized_ast_digest=None,
                outcome=ParseOutcome.REFUSES_EXPECTED,
                ast=None,
                findings=(finding,),
            )
        return self.parse_text(
            source_text=text,
            artifact_id=path.as_posix(),
            artifact_revision_id=digest,
            source_name=path.name,
        )

    def parse_script_file(self, path: Path) -> Db2ScriptParseResult:
        data = path.read_bytes()
        text = data.decode("utf-8-sig")
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        return self.parse_script_text(
            source_text=text,
            artifact_id=path.as_posix(),
            artifact_revision_id=digest,
            source_name=path.name,
        )

    def parse_script_text(
        self,
        *,
        source_text: str,
        artifact_id: str,
        artifact_revision_id: str,
        source_name: str = "<memory>",
    ) -> Db2ScriptParseResult:
        script = self._script_segmenter.segment_text(source_text, source_name=source_name)
        results: list[ProcedureParseResult] = []
        for unit in script.source_units:
            results.append(
                self.parse_text(
                    source_text=unit.source_text,
                    artifact_id=f"{artifact_id}#unit-{unit.unit_index:03d}",
                    artifact_revision_id=unit.source_digest,
                    source_name=f"{source_name}#unit-{unit.unit_index:03d}",
                )
            )
        complete = sum(result.outcome == ParseOutcome.PARSES_COMPLETE for result in results)
        partial = sum(result.outcome == ParseOutcome.PARSES_PARTIAL for result in results)
        blocked = len(results) - complete - partial
        return Db2ScriptParseResult(
            artifact_id=artifact_id,
            artifact_revision_id=artifact_revision_id,
            source_name=source_name,
            source_digest=script.source_digest,
            detected_terminator=script.detected_terminator,
            expected_source_unit_count=script.expected_source_unit_count,
            discovered_source_unit_count=script.discovered_source_unit_count,
            procedure_results=tuple(results),
            complete_count=complete,
            partial_count=partial,
            blocked_count=blocked,
            unclassified_fragment_count=script.unclassified_fragment_count,
            source_unit_count_matches=(
                script.expected_source_unit_count == script.discovered_source_unit_count
            ),
        )

    def parse_text(
        self,
        *,
        source_text: str,
        artifact_id: str,
        artifact_revision_id: str,
        source_name: str = "<memory>",
    ) -> ProcedureParseResult:
        source_digest = "sha256:" + hashlib.sha256(source_text.encode("utf-8")).hexdigest()
        script = self._script_segmenter.segment_text(source_text, source_name=source_name)
        if script.expected_source_unit_count > 1:
            return ProcedureParseResult(
                parser_adapter=self.adapter_name,
                parser_version=self.adapter_version,
                artifact_id=artifact_id,
                artifact_revision_id=artifact_revision_id,
                source_name=source_name,
                source_digest=source_digest,
                normalized_ast_digest=None,
                outcome=ParseOutcome.REFUSES_EXPECTED,
                ast=None,
                findings=(
                    ParseFinding(
                        code=ParserFindingCode.MULTIPLE_PROCEDURE_SOURCE_UNITS,
                        message=(
                            f"{script.expected_source_unit_count} CREATE PROCEDURE units were found; "
                            "use parse_script_text() so every unit is analyzed independently."
                        ),
                        consequence="No procedure AST was emitted from the single-unit API.",
                    ),
                ),
            )
        lex = self._scanner.scan(source_text)
        tokens = list(lex.tokens)
        findings: list[ParseFinding] = []
        try:
            header = self._parse_header(source_text, tokens)
        except Exception as exc:  # Adapter translates parser-specific failures.
            findings.append(
                ParseFinding(
                    code=ParserFindingCode.PROCEDURE_HEADER_PARSE_FAILED,
                    message=str(exc),
                    consequence="No AST or downstream artifacts were emitted.",
                )
            )
            return ProcedureParseResult(
                parser_adapter=self.adapter_name,
                parser_version=self.adapter_version,
                artifact_id=artifact_id,
                artifact_revision_id=artifact_revision_id,
                source_name=source_name,
                source_digest=source_digest,
                normalized_ast_digest=None,
                outcome=ParseOutcome.REFUSES_UNEXPECTED,
                ast=None,
                findings=tuple(findings),
            )

        begin_index = self._find_body_begin(tokens)
        end_index = self._find_final_end(tokens)
        if begin_index is None or end_index is None or end_index <= begin_index:
            findings.append(
                ParseFinding(
                    code=ParserFindingCode.UNBALANCED_COMPOUND_STATEMENT,
                    message="A top-level BEGIN/END procedure body was not identified.",
                    consequence="No body AST was emitted.",
                )
            )
            return ProcedureParseResult(
                parser_adapter=self.adapter_name,
                parser_version=self.adapter_version,
                artifact_id=artifact_id,
                artifact_revision_id=artifact_revision_id,
                source_name=source_name,
                source_digest=source_digest,
                normalized_ast_digest=None,
                outcome=ParseOutcome.REFUSES_EXPECTED,
                ast=None,
                findings=tuple(findings),
            )

        body_tokens = tokens[begin_index + 1 : end_index]
        body_node_refs, nodes, body_findings = self._parse_sequence(
            source_text,
            body_tokens,
            lexical_scope_ref="procedure-body",
        )
        findings.extend(body_findings)
        nodes, condition_findings = self._resolve_named_conditions(nodes)
        findings.extend(condition_findings)
        procedure_range = self._range_from_offsets(source_text, 0, len(source_text))
        procedure_node_id = self._node_id("procedure", procedure_range, header.name)
        returned_cursors, cursor_opens, result_set_findings = self._result_set_facts(
            nodes,
            header.declared_result_set_capacity,
        )
        findings.extend(result_set_findings)
        ast = ProcedureAst(
            node_id=procedure_node_id,
            schema_name=header.schema,
            procedure_name=header.name,
            specific_name=header.specific_name,
            routine_version_id=header.routine_version_id,
            commit_on_return=header.commit_on_return,
            parameters=header.parameters,
            body_node_refs=body_node_refs,
            nodes=tuple(nodes),
            state_access_facts=self._build_state_access_facts(header.parameters, nodes),
            declared_symbol_types=self._build_declared_symbol_types(header.parameters, nodes),
            declared_result_set_capacity=header.declared_result_set_capacity,
            returned_cursor_declarations=returned_cursors,
            cursor_open_effects=cursor_opens,
            source_range=procedure_range,
        )
        partial = any(node.kind == NodeKind.OPAQUE for node in nodes)
        outcome = ParseOutcome.PARSES_PARTIAL if partial else ParseOutcome.PARSES_COMPLETE
        return ProcedureParseResult(
            parser_adapter=self.adapter_name,
            parser_version=self.adapter_version,
            artifact_id=artifact_id,
            artifact_revision_id=artifact_revision_id,
            source_name=source_name,
            source_digest=source_digest,
            normalized_ast_digest=canonical_digest(ast),
            outcome=outcome,
            ast=ast,
            findings=tuple(findings),
        )



    @staticmethod
    def _result_set_facts(
        nodes: list[AstNode],
        declared_capacity: int | None,
    ) -> tuple[
        tuple[ReturnedCursorDeclaration, ...],
        tuple[CursorOpenEffect, ...],
        list[ParseFinding],
    ]:
        declarations: list[ReturnedCursorDeclaration] = []
        declaration_names: set[str] = set()
        for node in nodes:
            if node.kind != NodeKind.DECLARE_CURSOR:
                continue
            match = re.search(
                r"\bDECLARE\s+([A-Za-z_][A-Za-z0-9_$]*)\b.*?\bCURSOR\s+WITH\s+RETURN"
                r"(?:\s+TO\s+(CLIENT|CALLER))?\b",
                node.text,
                flags=re.IGNORECASE | re.DOTALL,
            )
            if match is None:
                continue
            name = match.group(1).upper()
            scope = (match.group(2) or "UNSPECIFIED").upper()
            declarations.append(
                ReturnedCursorDeclaration(
                    cursor_name=name,
                    return_scope=cast("Literal['CLIENT','CALLER','UNSPECIFIED']", scope),
                    declaration_node_ref=node.node_id,
                    source_range=node.source_range,
                )
            )
            declaration_names.add(name)

        opens: list[CursorOpenEffect] = []
        opened_returned: set[str] = set()
        for node in nodes:
            if node.kind != NodeKind.OPEN_CURSOR:
                continue
            match = re.search(r"\bOPEN\s+([A-Za-z_][A-Za-z0-9_$]*)\b", node.text, re.IGNORECASE)
            if match is None:
                continue
            name = match.group(1).upper()
            returned = name in declaration_names
            if returned:
                opened_returned.add(name)
            opens.append(
                CursorOpenEffect(
                    cursor_name=name,
                    open_node_ref=node.node_id,
                    source_range=node.source_range,
                    returned_cursor=returned,
                )
            )

        findings: list[ParseFinding] = []
        if declared_capacity is not None and len(declarations) > declared_capacity:
            findings.append(
                ParseFinding(
                    code=ParserFindingCode.RESULT_SET_CAPACITY_EXCEEDED,
                    message=(
                        f"{len(declarations)} returned cursors were declared but the routine capacity is "
                        f"{declared_capacity}."
                    ),
                    consequence="Returned-result-set admission is blocked until the declaration is reconciled.",
                )
            )
        for declaration in declarations:
            if declaration.cursor_name not in opened_returned:
                findings.append(
                    ParseFinding(
                        code=ParserFindingCode.RETURNED_CURSOR_NOT_OPENED,
                        message=f"Returned cursor {declaration.cursor_name} is declared but not opened.",
                        source_range=declaration.source_range,
                        consequence="The cursor is eligible for return but no returned result-set effect is emitted.",
                    )
                )
        return tuple(declarations), tuple(opens), findings
