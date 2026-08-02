from __future__ import annotations

import hashlib
import re
from collections import defaultdict

from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ProcedureAst
from ojas_reconciler.db2_behavior.analysis.models import (
    ControlFlowGraph,
    HandlerCoverageFact,
    SemanticFinding,
    SemanticFindingCode,
)


class HandlerCoverageAnalyzer:
    """Reports NOT FOUND coverage for statements that may raise SQLSTATE 02000."""

    def analyze(
        self, ast: ProcedureAst, cfg: ControlFlowGraph
    ) -> tuple[tuple[HandlerCoverageFact, ...], tuple[SemanticFinding, ...]]:
        by_source = defaultdict(list)
        for binding in cfg.handler_bindings:
            normalized = " ".join(binding.handled_condition_text.upper().split())
            handler = next((node for node in ast.nodes if node.node_id == binding.handler_region_ref), None)
            resolved = handler.handler_region.resolved_sqlstate if handler and handler.handler_region else None
            if normalized == "NOT FOUND" or resolved == "02000":
                by_source[binding.source_ast_node_ref].append(binding)

        facts: list[HandlerCoverageFact] = []
        findings: list[SemanticFinding] = []
        for node in ast.nodes:
            if not self._may_raise_not_found(node):
                continue
            bindings = sorted(by_source.get(node.node_id, ()), key=lambda item: item.binding_id)
            binding = bindings[0] if bindings else None
            payload = f"{node.node_id}|NOT_FOUND|{binding.binding_id if binding else 'MISSING'}"
            coverage_id = "handler-coverage-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
            facts.append(
                HandlerCoverageFact(
                    coverage_id=coverage_id,
                    source_node_ref=node.node_id,
                    coverage_status="COVERED" if binding else "MISSING",
                    handler_region_ref=binding.handler_region_ref if binding else None,
                    handler_binding_ref=binding.binding_id if binding else None,
                    continuation_semantics=binding.continuation_semantics if binding else None,
                    evidence_refs=(node.node_id, binding.handler_region_ref) if binding else (node.node_id,),
                )
            )
            if binding is None:
                finding_payload = f"{SemanticFindingCode.MISSING_NOT_FOUND_HANDLER.value}|{node.node_id}"
                findings.append(
                    SemanticFinding(
                        finding_id="semantic-finding-" + hashlib.sha256(finding_payload.encode("utf-8")).hexdigest()[:20],
                        code=SemanticFindingCode.MISSING_NOT_FOUND_HANDLER,
                        message=f"{node.kind.value} may raise NOT FOUND (SQLSTATE 02000), but no applicable handler exists in its lexical scope.",
                        evidence_node_refs=(node.node_id,),
                        source_ranges=(node.source_range,),
                        consequence="The procedure may exit or continue with unassigned targets; affected behavior remains incomplete.",
                    )
                )
        return tuple(sorted(facts, key=lambda item: item.coverage_id)), tuple(sorted(findings, key=lambda item: item.finding_id))

    @classmethod
    def _may_raise_not_found(cls, node) -> bool:
        if node.kind == NodeKind.SELECT_INTO:
            binding = node.select_into_binding
            if binding is not None and cls._outer_select_is_global_aggregate(
                binding.residual_query_text
            ):
                # A global aggregate SELECT without GROUP BY returns exactly one
                # row even when its input relation is empty; it does not raise
                # SQLSTATE 02000.
                return False
            return True
        if node.kind == NodeKind.FETCH_CURSOR:
            return True
        return (
            node.kind == NodeKind.EXECUTE
            and node.dynamic_execute_binding is not None
            and bool(node.dynamic_execute_binding.into_target_names)
        )

    @classmethod
    def _outer_select_is_global_aggregate(cls, sql: str) -> bool:
        projection, remainder = cls._outer_select_parts(sql)
        if projection is None:
            return False
        without_subqueries = cls._remove_parenthesized_subqueries(projection)
        has_aggregate = bool(
            re.search(
                r"\b(?:COUNT|AVG|SUM|MIN|MAX|LISTAGG)\s*\(",
                without_subqueries,
                flags=re.IGNORECASE,
            )
        )
        if (
            has_aggregate
            and not cls._contains_top_level_group_by(remainder)
            and not cls._contains_top_level_having(remainder)
        ):
            return True

        # A CTE may encapsulate the scalar aggregate while the outer SELECT
        # merely projects its one row.  Preserve that exact-one cardinality
        # only when the outer query does not filter or regroup the CTE row.
        relation = cls._outer_from_relation(remainder)
        if relation is None:
            return False
        definitions = cls._cte_definitions(sql)
        body = definitions.get(relation.upper())
        return bool(
            body
            and not cls._contains_top_level_where(remainder)
            and not cls._contains_top_level_group_by(remainder)
            and not cls._contains_top_level_having(remainder)
            and cls._outer_select_is_global_aggregate(body)
        )

    @staticmethod
    def _outer_select_parts(sql: str) -> tuple[str | None, str]:
        # Find the outer SELECT at parenthesis depth zero.  With a CTE, the
        # first SELECT belongs to the CTE body and must not drive cardinality.
        depth = 0
        quote: str | None = None
        select_start: int | None = None
        index = 0
        while index < len(sql):
            char = sql[index]
            if quote:
                if char == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
                index += 1
                continue
            if char == "(":
                depth += 1
                index += 1
                continue
            if char == ")":
                depth = max(0, depth - 1)
                index += 1
                continue
            if depth == 0 and re.match(r"SELECT\b", sql[index:], flags=re.IGNORECASE):
                select_start = index
                break
            index += 1
        if select_start is None:
            return None, ""
        index = select_start + len("SELECT")
        depth = 0
        quote = None
        while index < len(sql):
            char = sql[index]
            if quote:
                if char == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth = max(0, depth - 1)
            elif depth == 0 and re.match(r"FROM\b", sql[index:], flags=re.IGNORECASE):
                return sql[select_start + len("SELECT") : index], sql[index:]
            index += 1
        return sql[select_start + len("SELECT") :], ""

    @staticmethod
    def _outer_from_relation(remainder: str) -> str | None:
        match = re.match(
            r"\s*FROM\s+([A-Za-z_][A-Za-z0-9_.$]*)",
            remainder,
            flags=re.IGNORECASE,
        )
        return match.group(1) if match else None

    @classmethod
    def _cte_definitions(cls, sql: str) -> dict[str, str]:
        text = sql.lstrip()
        if not re.match(r"WITH\b", text, flags=re.IGNORECASE):
            return {}
        index = re.match(r"WITH\b", text, flags=re.IGNORECASE).end()  # type: ignore[union-attr]
        result: dict[str, str] = {}
        while index < len(text):
            while index < len(text) and (text[index].isspace() or text[index] == ','):
                index += 1
            name_match = re.match(r"([A-Za-z_][A-Za-z0-9_$]*)", text[index:])
            if name_match is None:
                break
            name = name_match.group(1).upper()
            index += name_match.end()
            while index < len(text) and text[index].isspace():
                index += 1
            if index < len(text) and text[index] == '(':
                closing = cls._matching_parenthesis(text, index)
                if closing is None:
                    break
                index = closing + 1
                while index < len(text) and text[index].isspace():
                    index += 1
            as_match = re.match(r"AS\s*\(", text[index:], flags=re.IGNORECASE)
            if as_match is None:
                break
            opening = index + as_match.end() - 1
            closing = cls._matching_parenthesis(text, opening)
            if closing is None:
                break
            result[name] = text[opening + 1 : closing]
            index = closing + 1
            probe = index
            while probe < len(text) and text[probe].isspace():
                probe += 1
            if probe >= len(text) or text[probe] != ',':
                break
            index = probe + 1
        return result

    @staticmethod
    def _matching_parenthesis(text: str, opening: int) -> int | None:
        depth = 0
        quote: str | None = None
        index = opening
        while index < len(text):
            char = text[index]
            if quote:
                if char == quote:
                    if index + 1 < len(text) and text[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    return index
            index += 1
        return None

    @staticmethod
    def _remove_parenthesized_subqueries(text: str) -> str:
        chars = list(text)
        stack: list[int] = []
        quote: str | None = None
        index = 0
        while index < len(text):
            char = text[index]
            if quote:
                if char == quote:
                    if index + 1 < len(text) and text[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == "(":
                stack.append(index)
            elif char == ")" and stack:
                opening = stack.pop()
                inner = text[opening + 1 : index].lstrip()
                if re.match(r"(?:SELECT|WITH)\b", inner, flags=re.IGNORECASE):
                    for position in range(opening, index + 1):
                        chars[position] = " "
            index += 1
        return "".join(chars)

    @staticmethod
    def _contains_top_level_where(text: str) -> bool:
        depth = 0
        quote: str | None = None
        index = 0
        while index < len(text):
            char = text[index]
            if quote:
                if char == quote:
                    if index + 1 < len(text) and text[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == '(':
                depth += 1
            elif char == ')':
                depth = max(0, depth - 1)
            elif depth == 0 and re.match(r"WHERE\b", text[index:], flags=re.IGNORECASE):
                return True
            index += 1
        return False

    @staticmethod
    def _contains_top_level_group_by(text: str) -> bool:
        depth = 0
        quote: str | None = None
        index = 0
        while index < len(text):
            char = text[index]
            if quote:
                if char == quote:
                    if index + 1 < len(text) and text[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth = max(0, depth - 1)
            elif depth == 0 and re.match(
                r"GROUP\s+BY\b", text[index:], flags=re.IGNORECASE
            ):
                return True
            index += 1
        return False

    @staticmethod
    def _contains_top_level_having(text: str) -> bool:
        depth = 0
        quote: str | None = None
        index = 0
        while index < len(text):
            char = text[index]
            if quote:
                if char == quote:
                    if index + 1 < len(text) and text[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth = max(0, depth - 1)
            elif depth == 0 and re.match(r"HAVING\b", text[index:], flags=re.IGNORECASE):
                return True
            index += 1
        return False
