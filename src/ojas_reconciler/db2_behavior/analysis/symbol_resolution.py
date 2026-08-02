from __future__ import annotations

import difflib
import hashlib
from collections import defaultdict
from dataclasses import dataclass

from ojas_reconciler.db2_behavior.parsing.lexer import Db2LexicalScanner, TokenKind
from ojas_reconciler.db2_behavior.parsing.models import (
    NodeKind,
    ProcedureAst,
    StateAccessKind,
)
from ojas_reconciler.db2_behavior.analysis.models import SemanticFinding, SemanticFindingCode


@dataclass(frozen=True, slots=True)
class SymbolReferenceIssue:
    """One unresolved procedural symbol reference after lexical-scope binding."""

    symbol_name: str
    source_node_ref: str
    usage_kind: str
    resolution_reason: str
    nearest_declared_symbol: str | None = None


class ProceduralSymbolValidator:
    """Validates procedural identifiers against parameters and lexical declarations.

    Parsing remains successful when syntax is recognized. This pass reports semantic
    binding failures and never invents implicit variables or typo corrections.
    """

    _SUPPLEMENTAL_TEXT_KINDS = frozenset(
        {
            NodeKind.DML,
            NodeKind.CALL,
            NodeKind.GET_DIAGNOSTICS,
            NodeKind.RETURN,
            NodeKind.SIGNAL,
            NodeKind.RESIGNAL,
            NodeKind.EXECUTE,
            NodeKind.EXECUTE_IMMEDIATE,
        }
    )

    def __init__(self) -> None:
        self._scanner = Db2LexicalScanner()

    def analyze(self, ast: ProcedureAst) -> tuple[SemanticFinding, ...]:
        issues = self.issues(ast)
        node_by_id = {node.node_id: node for node in ast.nodes}
        grouped: dict[tuple[str, str], list[SymbolReferenceIssue]] = defaultdict(list)
        for issue in issues:
            grouped[(issue.symbol_name, issue.resolution_reason)].append(issue)

        findings: list[SemanticFinding] = []
        for (symbol, reason), values in sorted(grouped.items()):
            refs = tuple(dict.fromkeys(value.source_node_ref for value in values if value.source_node_ref in node_by_id))
            usage_kinds = tuple(sorted({value.usage_kind for value in values}))
            nearest = next((value.nearest_declared_symbol for value in values if value.nearest_declared_symbol), None)
            payload = "|".join(
                (
                    SemanticFindingCode.UNDECLARED_SYMBOL_REFERENCE.value,
                    symbol,
                    reason,
                    *refs,
                    *usage_kinds,
                )
            )
            if reason == "OUT_OF_SCOPE":
                detail = f"Procedural symbol {symbol} is declared, but not visible from the referencing lexical scope."
            else:
                detail = f"Procedural symbol {symbol} is referenced but has no parameter or local declaration."
            if nearest is not None:
                detail += f" Nearest declared symbol is {nearest}; no automatic binding was applied."
            findings.append(
                SemanticFinding(
                    finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
                    code=SemanticFindingCode.UNDECLARED_SYMBOL_REFERENCE,
                    message=detail + f" Usage kinds: {', '.join(usage_kinds)}.",
                    evidence_node_refs=refs,
                    source_ranges=tuple(node_by_id[ref].source_range for ref in refs),
                    consequence=(
                        "Every behavior slice depending on this symbol is partial and ScenarioSpec admission is blocked."
                    ),
                )
            )
        return tuple(sorted(findings, key=lambda item: item.finding_id))

    def issues(self, ast: ProcedureAst) -> tuple[SymbolReferenceIssue, ...]:
        node_by_id = {node.node_id: node for node in ast.nodes}
        scope_parent = self._scope_parent(ast)
        declarations_by_scope, all_declared = self._declarations(ast)
        parameters = {parameter.name.upper() for parameter in ast.parameters}
        known_names = parameters | all_declared

        references: dict[tuple[str, str], set[str]] = defaultdict(set)
        for fact in ast.state_access_facts:
            references[(fact.source_node_ref, fact.symbol_name.upper())].add(
                f"{fact.access_kind.value}:{fact.context_kind}"
            )

        # Parser state facts cover typed bindings and conditions. These leaf kinds
        # may contain procedural values without a dedicated binding model.
        for node in ast.nodes:
            if node.kind not in self._SUPPLEMENTAL_TEXT_KINDS:
                continue
            for symbol in self._procedural_candidates(node.text):
                references[(node.node_id, symbol)].add("USE:STATEMENT_TEXT")

        issues: list[SymbolReferenceIssue] = []
        for (node_ref, symbol), usage_kinds in sorted(references.items()):
            node = node_by_id.get(node_ref)
            if node is None:
                continue
            if self._is_visible(
                symbol,
                node.lexical_scope_ref or "procedure-body",
                parameters,
                declarations_by_scope,
                scope_parent,
            ):
                continue
            reason = "OUT_OF_SCOPE" if symbol in all_declared else "UNDECLARED"
            visible_names = self._visible_names(
                node.lexical_scope_ref or "procedure-body",
                parameters,
                declarations_by_scope,
                scope_parent,
            )
            nearest = self._nearest(symbol, visible_names or known_names)
            for usage_kind in sorted(usage_kinds):
                issues.append(
                    SymbolReferenceIssue(
                        symbol_name=symbol,
                        source_node_ref=node_ref,
                        usage_kind=usage_kind,
                        resolution_reason=reason,
                        nearest_declared_symbol=nearest,
                    )
                )
        return tuple(issues)

    def unresolved_symbols_by_node(self, ast: ProcedureAst) -> dict[str, frozenset[str]]:
        result: dict[str, set[str]] = defaultdict(set)
        for issue in self.issues(ast):
            result[issue.source_node_ref].add(issue.symbol_name)
        return {node_ref: frozenset(symbols) for node_ref, symbols in result.items()}

    @staticmethod
    def _scope_parent(ast: ProcedureAst) -> dict[str, str | None]:
        result: dict[str, str | None] = {"procedure-body": None}
        for node in ast.nodes:
            if node.compound_region is not None:
                result[node.node_id] = node.compound_region.lexical_scope_ref
            if node.handler_region is not None:
                result[node.node_id] = node.handler_region.lexical_scope_ref
        return result

    @staticmethod
    def _declarations(ast: ProcedureAst) -> tuple[dict[str, set[str]], set[str]]:
        by_scope: dict[str, set[str]] = defaultdict(set)
        all_names: set[str] = set()
        for declaration in ast.declared_symbol_types:
            if declaration.symbol_kind != "LOCAL_VARIABLE":
                continue
            symbol = declaration.symbol_name.upper()
            scope = declaration.lexical_scope_ref or "procedure-body"
            by_scope[scope].add(symbol)
            all_names.add(symbol)
        return by_scope, all_names

    @staticmethod
    def _is_visible(
        symbol: str,
        scope: str,
        parameters: set[str],
        declarations_by_scope: dict[str, set[str]],
        scope_parent: dict[str, str | None],
    ) -> bool:
        if symbol in parameters:
            return True
        current: str | None = scope
        visited: set[str] = set()
        while current is not None and current not in visited:
            visited.add(current)
            if symbol in declarations_by_scope.get(current, set()):
                return True
            current = scope_parent.get(current)
        return False

    @staticmethod
    def _visible_names(
        scope: str,
        parameters: set[str],
        declarations_by_scope: dict[str, set[str]],
        scope_parent: dict[str, str | None],
    ) -> set[str]:
        result = set(parameters)
        current: str | None = scope
        visited: set[str] = set()
        while current is not None and current not in visited:
            visited.add(current)
            result.update(declarations_by_scope.get(current, set()))
            current = scope_parent.get(current)
        return result

    @staticmethod
    def _nearest(symbol: str, candidates: set[str]) -> str | None:
        match = difflib.get_close_matches(symbol, sorted(candidates), n=1, cutoff=0.72)
        return match[0] if match else None

    def _procedural_candidates(self, text: str) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    token.upper.strip('"')
                    for token in self._scanner.scan(text).tokens
                    if token.kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}
                    and self._looks_procedural(token.upper.strip('"'))
                }
            )
        )

    @staticmethod
    def _looks_procedural(value: str) -> bool:
        return value.startswith(("P_", "V_")) and len(value) > 2
