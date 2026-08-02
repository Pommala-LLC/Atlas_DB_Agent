from __future__ import annotations

import hashlib
from pathlib import Path

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.parsing.lexer import Db2LexicalScanner, TokenKind
from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ProcedureAst
from ojas_reconciler.db2_behavior.analysis.models import (
    SemanticFinding,
    SemanticFindingCode,
    TenantIsolationCatalog,
    TenantIsolationRule,
    QuerySourceSummary,
)


def validate_tenant_isolation_catalog(catalog: TenantIsolationCatalog) -> None:
    payload = catalog.model_dump(mode="python", exclude={"content_digest"})
    expected = canonical_digest(payload)
    if catalog.content_digest != expected:
        raise ValueError(
            f"Tenant isolation catalog digest mismatch: expected {expected}, got {catalog.content_digest}."
        )


def load_tenant_isolation_catalog(path: Path | None) -> TenantIsolationCatalog | None:
    if path is None:
        return None
    catalog = TenantIsolationCatalog.model_validate_json(path.read_text(encoding="utf-8"))
    validate_tenant_isolation_catalog(catalog)
    return catalog


class TenantIsolationAnalyzer:
    """Evaluates catalog-declared tenant isolation for reads and writes.

    Missing catalog coverage is emitted explicitly. A missing rule is never
    interpreted as clearance.
    """

    def __init__(self, catalog: TenantIsolationCatalog | None) -> None:
        self._catalog = catalog
        self._scanner = Db2LexicalScanner()

    def analyze(
        self,
        ast: ProcedureAst,
        query_summaries: tuple[QuerySourceSummary, ...] = (),
    ) -> tuple[SemanticFinding, ...]:
        findings: list[SemanticFinding] = []
        rules_by_relation = {
            self._normalize_relation(rule.relation_name): rule
            for rule in (self._catalog.rules if self._catalog is not None else ())
        }
        node_by_id = {node.node_id: node for node in ast.nodes}
        seen: set[tuple[str, str, str]] = set()

        for node in ast.nodes:
            if node.kind != NodeKind.DML:
                continue
            tokens = list(self._scanner.scan(node.text).tokens)
            relation = self._target_relation(tokens)
            if relation is None:
                continue
            normalized = self._normalize_relation(relation)
            rule = rules_by_relation.get(normalized)
            key = (node.node_id, normalized, "WRITE")
            if key in seen:
                continue
            seen.add(key)
            if rule is None:
                findings.append(self._not_evaluated(node, relation, "WRITE"))
                continue
            if rule.required_scope not in {"WRITE", "BOTH"}:
                continue
            if not self._has_tenant_binding(tokens, rule, relation):
                findings.append(self._missing(node, rule, "WRITE"))

        for summary in query_summaries:
            node = node_by_id.get(summary.source_node_ref)
            if node is None:
                continue
            ctes = {name.upper() for name in summary.cte_names}
            for relation in summary.relation_refs:
                normalized = self._normalize_relation(relation)
                if normalized in ctes or normalized in {"SYSDUMMY1"}:
                    continue
                key = (node.node_id, normalized, "READ")
                if key in seen:
                    continue
                seen.add(key)
                rule = rules_by_relation.get(normalized)
                if rule is None:
                    findings.append(self._not_evaluated(node, relation, "READ"))
                    continue
                if rule.required_scope not in {"READ", "BOTH"}:
                    continue
                tokens = list(self._scanner.scan(node.text).tokens)
                if not self._has_tenant_binding(tokens, rule, relation):
                    findings.append(self._missing(node, rule, "READ"))

        return tuple(sorted(findings, key=lambda item: item.finding_id))

    def _missing(self, node, rule: TenantIsolationRule, scope: str) -> SemanticFinding:
        payload = (
            f"{SemanticFindingCode.TENANT_ISOLATION_MISSING.value}|"
            f"{node.node_id}|{rule.relation_name}|{rule.tenant_column}|{scope}"
        )
        return SemanticFinding(
            finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            code=SemanticFindingCode.TENANT_ISOLATION_MISSING,
            message=(
                f"{scope} access on {rule.relation_name} does not contain the catalog-required "
                f"tenant predicate for {rule.tenant_column}."
            ),
            evidence_node_refs=(node.node_id,),
            source_ranges=(node.source_range,),
            consequence=(
                "The access remains a technical finding and cannot be treated as tenant-isolated "
                "without correction or an authoritative exception."
            ),
        )

    def _not_evaluated(self, node, relation: str, scope: str) -> SemanticFinding:
        reason = "no tenant-isolation catalog was supplied" if self._catalog is None else "the supplied catalog has no rule for this relation"
        payload = f"{SemanticFindingCode.TENANT_ISOLATION_NOT_EVALUATED.value}|{node.node_id}|{relation}|{scope}|{reason}"
        return SemanticFinding(
            finding_id="semantic-finding-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
            code=SemanticFindingCode.TENANT_ISOLATION_NOT_EVALUATED,
            message=f"Tenant isolation was not evaluated for {scope} access on {relation}: {reason}.",
            evidence_node_refs=(node.node_id,),
            source_ranges=(node.source_range,),
            consequence="Absence of TENANT_ISOLATION_MISSING is not evidence that the access is tenant-safe.",
        )

    @staticmethod
    def _normalize_relation(value: str) -> str:
        return value.strip().strip('"').upper().split(".")[-1]

    @staticmethod
    def _target_relation(tokens) -> str | None:
        if not tokens:
            return None
        first = tokens[0].upper
        if first not in {"UPDATE", "DELETE", "INSERT", "MERGE"}:
            return None
        index = 1
        if first == "DELETE" and index < len(tokens) and tokens[index].upper == "FROM":
            index += 1
        elif first == "INSERT" and index < len(tokens) and tokens[index].upper == "INTO":
            index += 1
        elif first == "MERGE" and index < len(tokens) and tokens[index].upper == "INTO":
            index += 1
        if index >= len(tokens):
            return None
        parts: list[str] = []
        while index < len(tokens):
            token = tokens[index]
            if token.upper in {"SET", "WHERE", "AS", "USING", "("}:
                break
            if token.kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER} or token.value == ".":
                parts.append(token.value)
                index += 1
                if token.value != "." and (index >= len(tokens) or tokens[index].value != "."):
                    break
                continue
            break
        return "".join(parts) if parts else None

    def _has_tenant_binding(self, tokens, rule: TenantIsolationRule, relation: str) -> bool:
        """Prove that every alias of the relation's tenant column reaches an accepted parameter.

        Equality propagation supports qualified join chains such as
        C.TENANT_ID = CU.TENANT_ID and C.TENANT_ID = P_TENANT_ID. A literal,
        inequality, or unrelated tenant column does not establish isolation.
        """
        aliases = self._relation_aliases(tokens).get(self._normalize_relation(relation), set())
        if not aliases:
            aliases = {self._normalize_relation(relation)}
        graph: dict[str, set[str]] = {}
        for index, token in enumerate(tokens):
            if token.value != "=":
                continue
            left = self._operand_before(tokens, index)
            right = self._operand_after(tokens, index)
            if left is None or right is None:
                continue
            graph.setdefault(left, set()).add(right)
            graph.setdefault(right, set()).add(left)

        accepted = {name.upper() for name in rule.accepted_parameter_names}
        tenant = rule.tenant_column.upper()
        if not accepted:
            # An empty accepted set means any equality involving the tenant column is sufficient.
            accepted = {neighbor for values in graph.values() for neighbor in values}
        for alias in aliases:
            candidates = {f"{alias}.{tenant}"}
            if len(aliases) == 1:
                candidates.add(tenant)
            if not any(self._connected(candidate, accepted, graph) for candidate in candidates):
                return False
        return True

    @staticmethod
    def _connected(start: str, accepted: set[str], graph: dict[str, set[str]]) -> bool:
        if start in accepted:
            return True
        queue = [start]
        seen: set[str] = set()
        while queue:
            current = queue.pop()
            if current in seen:
                continue
            seen.add(current)
            for neighbor in graph.get(current, set()):
                if neighbor in accepted:
                    return True
                if neighbor not in seen:
                    queue.append(neighbor)
        return False

    @classmethod
    def _relation_aliases(cls, tokens) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
        reserved = {
            "ON", "WHERE", "INNER", "LEFT", "RIGHT", "FULL", "CROSS", "JOIN",
            "GROUP", "ORDER", "HAVING", "FETCH", "UNION", "EXCEPT", "INTERSECT",
            "SET", "USING", "WHEN", "VALUES", "RETURNING", "WITH",
        }
        for index, token in enumerate(tokens):
            if token.upper not in {"FROM", "JOIN", "UPDATE"}:
                continue
            cursor = index + 1
            if cursor >= len(tokens) or tokens[cursor].value == "(":
                continue
            parts: list[str] = []
            while cursor < len(tokens):
                current = tokens[cursor]
                if current.kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER} or current.value == ".":
                    parts.append(current.value.strip('"'))
                    cursor += 1
                    if current.value != "." and (cursor >= len(tokens) or tokens[cursor].value != "."):
                        break
                    continue
                break
            if not parts:
                continue
            relation = cls._normalize_relation("".join(parts))
            if cursor < len(tokens) and tokens[cursor].upper == "AS":
                cursor += 1
            alias = relation
            if cursor < len(tokens):
                candidate = tokens[cursor]
                if (
                    candidate.kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}
                    and candidate.upper not in reserved
                ):
                    alias = candidate.value.strip('"').upper()
            result.setdefault(relation, set()).add(alias)
        # INSERT/MERGE targets are introduced by INTO rather than FROM/JOIN.
        if tokens and tokens[0].upper in {"INSERT", "MERGE"}:
            try:
                into = next(i for i, token in enumerate(tokens) if token.upper == "INTO")
            except StopIteration:
                into = -1
            if into >= 0 and into + 1 < len(tokens):
                relation = cls._normalize_relation(tokens[into + 1].value)
                result.setdefault(relation, set()).add(relation)
        return result

    @staticmethod
    def _operand_before(tokens, equals_index: int) -> str | None:
        index = equals_index - 1
        if index < 0:
            return None
        if (
            index >= 2
            and tokens[index - 1].value == "."
            and tokens[index].kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}
            and tokens[index - 2].kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}
        ):
            return f"{tokens[index - 2].value.strip('"').upper()}.{tokens[index].value.strip('"').upper()}"
        if tokens[index].kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}:
            return tokens[index].value.strip('"').upper()
        return None

    @staticmethod
    def _operand_after(tokens, equals_index: int) -> str | None:
        index = equals_index + 1
        if index >= len(tokens):
            return None
        if (
            index + 2 < len(tokens)
            and tokens[index + 1].value == "."
            and tokens[index].kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}
            and tokens[index + 2].kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}
        ):
            return f"{tokens[index].value.strip('"').upper()}.{tokens[index + 2].value.strip('"').upper()}"
        if tokens[index].kind in {TokenKind.WORD, TokenKind.QUOTED_IDENTIFIER}:
            return tokens[index].value.strip('"').upper()
        return None

