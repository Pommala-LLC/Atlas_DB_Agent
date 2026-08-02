from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Iterable

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.parsing.lexer import Db2LexicalScanner, Token
from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ProcedureAst
from ojas_reconciler.db2_behavior.analysis.models import (
    BehaviorEffectBundle,
    ConstraintAssessment,
    ConstraintAssessmentStatus,
    PredicateExpression,
    PredicateGraph,
    PredicateNodeKind,
    SemanticFinding,
    SemanticFindingCode,
)


@dataclass(frozen=True, slots=True)
class _Expr:
    kind: PredicateNodeKind
    text: str | None = None
    operands: tuple["_Expr", ...] = ()


class _BooleanExpressionParser:
    """Small deterministic Boolean shell parser.

    It intentionally treats DB2 scalar predicates as atomic expressions. It only
    structures Boolean AND/OR/NOT and parenthesized Boolean groups. This avoids
    claiming a full DB2 expression grammar while still supporting ordered IF-arm
    obligations and local contradiction checks.
    """

    def __init__(self, tokens: list[Token]) -> None:
        self._tokens = tokens
        self._index = 0

    def parse(self) -> _Expr:
        if not self._tokens:
            return _Expr(PredicateNodeKind.TRUE)
        result = self._parse_or()
        if self._index != len(self._tokens):
            # Preserve unconsumed text as one atomic node rather than guessing.
            return _Expr(PredicateNodeKind.ATOMIC, self._render(self._tokens))
        return result

    def _parse_or(self) -> _Expr:
        values = [self._parse_and()]
        while self._peek_upper() == "OR":
            self._index += 1
            values.append(self._parse_and())
        return self._combine(PredicateNodeKind.OR, values)

    def _parse_and(self) -> _Expr:
        values = [self._parse_not()]
        while self._peek_upper() == "AND":
            self._index += 1
            values.append(self._parse_not())
        return self._combine(PredicateNodeKind.AND, values)

    def _parse_not(self) -> _Expr:
        if self._peek_upper() == "NOT":
            self._index += 1
            return _Expr(PredicateNodeKind.NOT, operands=(self._parse_not(),))
        if self._peek_value() == "(" and self._is_boolean_group(self._index):
            self._index += 1
            value = self._parse_or()
            if self._peek_value() == ")":
                self._index += 1
            return value
        return self._parse_atom()

    def _parse_atom(self) -> _Expr:
        start = self._index
        depth = 0
        between_pending = False
        while self._index < len(self._tokens):
            token = self._tokens[self._index]
            if token.value == "(":
                depth += 1
            elif token.value == ")":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0:
                if token.upper == "BETWEEN":
                    between_pending = True
                elif token.upper == "AND" and between_pending:
                    between_pending = False
                elif token.upper in {"AND", "OR"}:
                    break
            self._index += 1
        atom_tokens = self._tokens[start : self._index]
        if not atom_tokens:
            return _Expr(PredicateNodeKind.UNKNOWN, text="")
        return _Expr(PredicateNodeKind.ATOMIC, self._render(atom_tokens))

    def _is_boolean_group(self, index: int) -> bool:
        depth = 0
        for token in self._tokens[index:]:
            if token.value == "(":
                depth += 1
            elif token.value == ")":
                depth -= 1
                if depth == 0:
                    return True
            elif depth == 1 and token.upper in {"AND", "OR"}:
                return True
        return False

    def _peek_upper(self) -> str | None:
        return self._tokens[self._index].upper if self._index < len(self._tokens) else None

    def _peek_value(self) -> str | None:
        return self._tokens[self._index].value if self._index < len(self._tokens) else None

    @staticmethod
    def _combine(kind: PredicateNodeKind, values: list[_Expr]) -> _Expr:
        flattened: list[_Expr] = []
        for value in values:
            if value.kind == kind:
                flattened.extend(value.operands)
            else:
                flattened.append(value)
        if len(flattened) == 1:
            return flattened[0]
        return _Expr(kind, operands=tuple(flattened))

    @staticmethod
    def _render(tokens: Iterable[Token]) -> str:
        values = [token.value for token in tokens]
        text = " ".join(values)
        text = re.sub(r"\s+([,.)])", r"\1", text)
        text = re.sub(r"([(])\s+", r"\1", text)
        text = re.sub(r"\s+\.\s+", ".", text)
        return " ".join(text.split())


class PredicateAnalysisBuilder:
    """Builds ordered IF/loop predicate DAGs and local assessments."""

    def __init__(self) -> None:
        self._scanner = Db2LexicalScanner()

    def build(
        self,
        ast: ProcedureAst,
        bundles: tuple[BehaviorEffectBundle, ...],
    ) -> tuple[
        tuple[PredicateGraph, ...],
        tuple[ConstraintAssessment, ...],
        tuple[SemanticFinding, ...],
    ]:
        self._node_by_id = {node.node_id: node for node in ast.nodes}
        graphs: list[PredicateGraph] = []
        assessments: list[ConstraintAssessment] = []
        findings: list[SemanticFinding] = []
        seen_regions: set[str] = set()

        candidate_regions = {bundle.controlling_region_ref for bundle in bundles}
        for node in ast.nodes:
            if node.if_region is not None:
                for index, arm in enumerate(node.if_region.arms):
                    candidate_regions.add(f"if-arm:{node.node_id}:{index}:{arm.arm_kind}")
            if node.loop_region is not None and node.loop_region.condition_text:
                candidate_regions.add(f"loop-region:{node.node_id}")

        for region in sorted(candidate_regions):
            if region in seen_regions:
                continue
            seen_regions.add(region)
            root, source_refs, complete = self._expression_for_region(region)
            if root is None:
                continue
            graph = self._graph(region, root, source_refs, complete)
            graphs.append(graph)
            assessment = LocalConstraintEvaluator().assess(graph)
            assessments.append(assessment)
            if graph.normalization_status == "PARTIAL":
                findings.append(
                    self._finding(
                        SemanticFindingCode.PREDICATE_NORMALIZATION_PARTIAL,
                        "Predicate was retained with a partial Boolean normalization.",
                        source_refs,
                        "The affected behavior slice cannot support ScenarioSpec generation.",
                    )
                )
            if assessment.status == ConstraintAssessmentStatus.UNSUPPORTED_CONSTRAINT_THEORY:
                findings.append(
                    self._finding(
                        SemanticFindingCode.UNSUPPORTED_CONSTRAINT_THEORY,
                        assessment.reason,
                        source_refs,
                        "The predicate remains a technical obligation without a consistency proof.",
                    )
                )
            if assessment.status == ConstraintAssessmentStatus.OBVIOUS_CONTRADICTION:
                findings.append(
                    self._finding(
                        SemanticFindingCode.OBVIOUS_PREDICATE_CONTRADICTION,
                        assessment.reason,
                        source_refs,
                        "The controlled effect region is locally unreachable under the admitted theory.",
                    )
                )
                findings.append(
                    self._finding(
                        SemanticFindingCode.UNREACHABLE_BRANCH,
                        "The ordered branch condition is unreachable under the admitted local theory.",
                        source_refs[-1:] if source_refs else source_refs,
                        "Effects in this branch cannot be promoted as implemented reachable behavior.",
                    )
                )

        return (
            tuple(sorted(graphs, key=lambda value: value.predicate_graph_id)),
            tuple(sorted(assessments, key=lambda value: value.assessment_id)),
            tuple(sorted(findings, key=lambda value: value.finding_id)),
        )

    def _expression_for_region(self, region: str) -> tuple[_Expr | None, tuple[str, ...], bool]:
        if region.startswith("if-arm:"):
            parts = region.split(":")
            if len(parts) < 4:
                return None, (), False
            node_ref = parts[1]
            try:
                arm_index = int(parts[2])
            except ValueError:
                return None, (node_ref,), False
            node = self._node_by_id.get(node_ref)
            if node is None or node.if_region is None or arm_index >= len(node.if_region.arms):
                return None, (node_ref,), False
            obligations: list[_Expr] = []
            for previous in node.if_region.arms[:arm_index]:
                if previous.condition_text:
                    obligations.append(_Expr(PredicateNodeKind.NOT, operands=(self._parse(previous.condition_text),)))
            current = node.if_region.arms[arm_index]
            if current.condition_text:
                obligations.append(self._parse(current.condition_text))
            root = _BooleanExpressionParser._combine(PredicateNodeKind.AND, obligations) if obligations else _Expr(PredicateNodeKind.TRUE)
            complete = node.if_region.analysis_completeness == "STRUCTURE_COMPLETE"
            return root, tuple(arm.arm_id for arm in node.if_region.arms[: arm_index + 1]), complete

        if region.startswith("loop-region:"):
            node_ref = region.split(":", 1)[1]
            node = self._node_by_id.get(node_ref)
            if node is None or node.loop_region is None or not node.loop_region.condition_text:
                return None, (node_ref,), node is not None
            return (
                self._parse(node.loop_region.condition_text),
                (node_ref,),
                node.loop_region.analysis_completeness == "STRUCTURE_COMPLETE",
            )
        return None, (), True

    def _parse(self, text: str) -> _Expr:
        return _BooleanExpressionParser(list(self._scanner.scan(text).tokens)).parse()

    def _graph(
        self,
        region: str,
        root: _Expr,
        source_refs: tuple[str, ...],
        complete: bool,
    ) -> PredicateGraph:
        expressions: dict[str, PredicateExpression] = {}

        def add(value: _Expr) -> str:
            operand_refs = tuple(add(operand) for operand in value.operands)
            payload = {
                "kind": value.kind.value,
                "text": value.text,
                "operand_refs": operand_refs,
            }
            expr_id = "predicate-expr-" + canonical_digest(payload).split(":", 1)[1][:20]
            expressions.setdefault(
                expr_id,
                PredicateExpression(
                    expression_id=expr_id,
                    node_kind=value.kind,
                    operand_refs=operand_refs,
                    technical_expression=value.text,
                ),
            )
            return expr_id

        root_ref = add(root)
        payload = f"{region}|{root_ref}|{'|'.join(sorted(expressions))}"
        graph_id = "predicate-graph-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
        return PredicateGraph(
            predicate_graph_id=graph_id,
            controlling_region_ref=region,
            root_ref=root_ref,
            expressions=tuple(sorted(expressions.values(), key=lambda value: value.expression_id)),
            source_node_refs=source_refs,
            normalization_status="COMPLETE" if complete else "PARTIAL",
        )

    def _finding(
        self,
        code: SemanticFindingCode,
        message: str,
        refs: tuple[str, ...],
        consequence: str,
    ) -> SemanticFinding:
        ranges = tuple(self._node_by_id[ref].source_range for ref in refs if ref in self._node_by_id)
        payload = f"{code.value}|{'|'.join(refs)}|{message}"
        return SemanticFinding(
            finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            code=code,
            message=message,
            evidence_node_refs=refs,
            source_ranges=ranges,
            consequence=consequence,
        )


class LocalConstraintEvaluator:
    """Bounded local evaluator for obvious contradictions and assumptions."""

    _max_branches = 32
    _comparison = re.compile(
        r"^([A-Z_][A-Z0-9_.$]*)\s*(<=|>=|=|<>|!=|<|>)\s*(-?\d+(?:\.\d+)?)$",
        re.IGNORECASE,
    )
    _string_equality = re.compile(
        r"^([A-Z_][A-Z0-9_.$]*)\s*(=|<>|!=)\s*('(?:''|[^'])*')$",
        re.IGNORECASE,
    )
    _null_test = re.compile(
        r"^([A-Z_][A-Z0-9_.$]*)\s+IS\s+(NOT\s+)?NULL$",
        re.IGNORECASE,
    )
    _literal_in = re.compile(
        r"^([A-Z_][A-Z0-9_.$]*)\s+(NOT\s+)?IN\s*\((?:\s*(?:'(?:''|[^'])*'|-?\d+(?:\.\d+)?)\s*,?)+\)$",
        re.IGNORECASE,
    )
    _literal_comparison = re.compile(
        r"^(-?\d+(?:\.\d+)?|'(?:''|[^'])*')\s*(<=|>=|=|<>|!=|<|>)\s*(-?\d+(?:\.\d+)?|'(?:''|[^'])*')$",
        re.IGNORECASE,
    )

    def assess(self, graph: PredicateGraph) -> ConstraintAssessment:
        expressions = {value.expression_id: value for value in graph.expressions}
        try:
            branches = self._branches(graph.root_ref, expressions, negated=False)
        except OverflowError:
            return self._result(
                graph,
                ConstraintAssessmentStatus.UNSUPPORTED_CONSTRAINT_THEORY,
                f"Predicate normalization exceeded the local {self._max_branches}-branch assessment budget.",
            )

        if not branches:
            return self._result(
                graph,
                ConstraintAssessmentStatus.OBVIOUS_CONTRADICTION,
                "Every Boolean branch is contradictory or literal FALSE.",
            )

        surviving: list[tuple[ConstraintAssessmentStatus, str]] = []
        contradictions: list[str] = []
        for atoms in branches:
            contradiction = self._contradiction(atoms)
            if contradiction is not None:
                contradictions.append(contradiction)
                continue
            surviving.append(self._classify_branch(atoms))

        if not surviving:
            reason = contradictions[0] if contradictions else "All Boolean branches are contradictory."
            return self._result(graph, ConstraintAssessmentStatus.OBVIOUS_CONTRADICTION, reason)

        precedence = {
            ConstraintAssessmentStatus.UNSUPPORTED_CONSTRAINT_THEORY: 5,
            ConstraintAssessmentStatus.CONFIGURATION_ASSUMPTION_REQUIRED: 4,
            ConstraintAssessmentStatus.DATA_STATE_ASSUMPTION_REQUIRED: 3,
            ConstraintAssessmentStatus.NOT_ASSESSED: 2,
            ConstraintAssessmentStatus.SYNTACTICALLY_CONSISTENT: 1,
        }
        status, reason = max(surviving, key=lambda item: precedence[item[0]])
        if contradictions:
            reason += f" {len(contradictions)} alternative branch(es) were locally contradictory."
        return self._result(graph, status, reason)

    def _branches(
        self,
        ref: str,
        expressions: dict[str, PredicateExpression],
        *,
        negated: bool,
    ) -> list[list[tuple[str, bool]]]:
        value = expressions[ref]
        if value.node_kind == PredicateNodeKind.NOT:
            if not value.operand_refs:
                return [[("", True)]]
            return self._branches(value.operand_refs[0], expressions, negated=not negated)
        if value.node_kind == PredicateNodeKind.TRUE:
            return [] if negated else [[]]
        if value.node_kind == PredicateNodeKind.FALSE:
            return [[]] if negated else []
        if value.node_kind in {PredicateNodeKind.ATOMIC, PredicateNodeKind.UNKNOWN}:
            return [[(" ".join((value.technical_expression or "").upper().split()), negated)]]

        operator = value.node_kind
        if negated:
            operator = PredicateNodeKind.OR if operator == PredicateNodeKind.AND else PredicateNodeKind.AND

        children = [self._branches(child, expressions, negated=negated) for child in value.operand_refs]
        if operator == PredicateNodeKind.OR:
            result = [branch for child in children for branch in child]
            if len(result) > self._max_branches:
                raise OverflowError
            return result

        result: list[list[tuple[str, bool]]] = [[]]
        for child in children:
            combined: list[list[tuple[str, bool]]] = []
            for left in result:
                for right in child:
                    combined.append([*left, *right])
                    if len(combined) > self._max_branches:
                        raise OverflowError
            result = combined
        return result

    def _classify_branch(self, atoms: list[tuple[str, bool]]) -> tuple[ConstraintAssessmentStatus, str]:
        has_data_assumption = False
        has_configuration = False
        unsupported: list[str] = []
        for text, _negated in atoms:
            if not text:
                unsupported.append("empty atomic predicate")
                continue
            if any(keyword in text for keyword in ("CURRENT TIMESTAMP", "CURRENT DATE", "CURRENT TIME", "SESSION_USER", "CURRENT_SCHEMA", "CURRENT_PATH")):
                has_configuration = True
            if "EXISTS" in text or "SELECT " in text:
                has_data_assumption = True
                continue
            if (
                self._comparison.match(text)
                or self._string_equality.match(text)
                or self._null_test.match(text)
                or self._literal_in.match(text)
                or self._literal_comparison.match(text)
            ):
                continue
            unsupported.append(text)

        if unsupported:
            return (
                ConstraintAssessmentStatus.UNSUPPORTED_CONSTRAINT_THEORY,
                f"The bounded local theory does not interpret: {unsupported[0]}.",
            )
        if has_configuration:
            return (
                ConstraintAssessmentStatus.CONFIGURATION_ASSUMPTION_REQUIRED,
                "The predicate depends on environment or special-register state.",
            )
        if has_data_assumption:
            return (
                ConstraintAssessmentStatus.DATA_STATE_ASSUMPTION_REQUIRED,
                "The predicate depends on database cardinality or row-state assumptions.",
            )
        return (
            ConstraintAssessmentStatus.SYNTACTICALLY_CONSISTENT,
            "No contradiction was found in the admitted local comparison theory.",
        )

    def _contradiction(self, atoms: list[tuple[str, bool]]) -> str | None:
        positive = {text for text, negated in atoms if not negated}
        negative = {text for text, negated in atoms if negated}
        overlap = positive & negative
        if overlap:
            return f"The predicate requires and rejects the same atomic condition: {sorted(overlap)[0]}."

        null_states: dict[str, set[bool]] = {}
        numeric: dict[str, dict[str, object]] = {}
        strings: dict[str, dict[str, object]] = {}
        for text, negated in atoms:
            literal_truth = self._literal_truth(text)
            if literal_truth is not None:
                effective_truth = not literal_truth if negated else literal_truth
                if not effective_truth:
                    return f"Literal predicate is always false: {text}."
                continue
            null = self._null_test.match(text)
            if null:
                symbol = null.group(1).upper()
                is_null = not bool(null.group(2))
                if negated:
                    is_null = not is_null
                null_states.setdefault(symbol, set()).add(is_null)
                continue

            match = self._comparison.match(text)
            if match and not negated:
                symbol, operator, raw = match.groups()
                try:
                    value = Decimal(raw)
                except InvalidOperation:
                    continue
                record = numeric.setdefault(symbol.upper(), {"not_equal": set(), "lowers": [], "uppers": []})
                if operator == "=":
                    prior = record.get("equal")
                    if isinstance(prior, Decimal) and prior != value:
                        return f"{symbol} is required to equal two distinct numeric literals."
                    record["equal"] = value
                elif operator in {"!=", "<>"}:
                    not_equal = record["not_equal"]
                    assert isinstance(not_equal, set)
                    not_equal.add(value)
                elif operator in {">", ">="}:
                    lowers = record["lowers"]
                    assert isinstance(lowers, list)
                    lowers.append((value, operator == ">="))
                elif operator in {"<", "<="}:
                    uppers = record["uppers"]
                    assert isinstance(uppers, list)
                    uppers.append((value, operator == "<="))
                continue

            string_match = self._string_equality.match(text)
            if string_match and not negated:
                symbol, operator, value = string_match.groups()
                record = strings.setdefault(symbol.upper(), {"not_equal": set()})
                if operator == "=":
                    prior = record.get("equal")
                    if isinstance(prior, str) and prior != value:
                        return f"{symbol} is required to equal two distinct string literals."
                    record["equal"] = value
                else:
                    not_equal = record["not_equal"]
                    assert isinstance(not_equal, set)
                    not_equal.add(value)

        for symbol, states in null_states.items():
            if len(states) > 1:
                return f"{symbol} is required to be both NULL and NOT NULL."
        for symbol, record in numeric.items():
            equal = record.get("equal")
            not_equal = record.get("not_equal")
            if isinstance(equal, Decimal) and isinstance(not_equal, set) and equal in not_equal:
                return f"{symbol} is required to equal and not equal {equal}."
            lowers = record.get("lowers", [])
            uppers = record.get("uppers", [])
            assert isinstance(lowers, list) and isinstance(uppers, list)
            if lowers:
                lower, lower_inc = max(lowers, key=lambda item: (item[0], not item[1]))
            else:
                lower = lower_inc = None
            if uppers:
                upper, upper_inc = min(uppers, key=lambda item: (item[0], item[1]))
            else:
                upper = upper_inc = None
            if isinstance(lower, Decimal) and isinstance(upper, Decimal):
                if lower > upper or (lower == upper and not (bool(lower_inc) and bool(upper_inc))):
                    return f"Numeric interval for {symbol} is empty."
            if isinstance(equal, Decimal):
                if isinstance(lower, Decimal) and (equal < lower or (equal == lower and not bool(lower_inc))):
                    return f"Equality for {symbol} violates its lower bound."
                if isinstance(upper, Decimal) and (equal > upper or (equal == upper and not bool(upper_inc))):
                    return f"Equality for {symbol} violates its upper bound."
        for symbol, record in strings.items():
            equal = record.get("equal")
            not_equal = record.get("not_equal")
            if isinstance(equal, str) and isinstance(not_equal, set) and equal in not_equal:
                return f"{symbol} is required to equal and not equal {equal}."
        return None

    def _literal_truth(self, text: str) -> bool | None:
        match = self._literal_comparison.match(text)
        if match is None:
            return None
        left_raw, operator, right_raw = match.groups()
        try:
            if left_raw.startswith("'") and right_raw.startswith("'"):
                left: object = left_raw[1:-1].replace("''", "'")
                right: object = right_raw[1:-1].replace("''", "'")
            elif not left_raw.startswith("'") and not right_raw.startswith("'"):
                left = Decimal(left_raw)
                right = Decimal(right_raw)
            else:
                return None
        except InvalidOperation:
            return None
        if operator == "=":
            return left == right
        if operator in {"<>", "!="}:
            return left != right
        if operator == "<":
            return bool(left < right)  # type: ignore[operator]
        if operator == "<=":
            return bool(left <= right)  # type: ignore[operator]
        if operator == ">":
            return bool(left > right)  # type: ignore[operator]
        if operator == ">=":
            return bool(left >= right)  # type: ignore[operator]
        return None

    @staticmethod
    def _result(
        graph: PredicateGraph,
        status: ConstraintAssessmentStatus,
        reason: str,
    ) -> ConstraintAssessment:
        payload = f"{graph.predicate_graph_id}|{status.value}|{reason}"
        return ConstraintAssessment(
            assessment_id="constraint-assessment-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            predicate_graph_ref=graph.predicate_graph_id,
            status=status,
            reason=reason,
            evidence_refs=graph.source_node_refs,
        )
