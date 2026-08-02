from __future__ import annotations

import hashlib
from collections import deque
from typing import Iterable

from ..core.canonical_json import canonical_digest
from .models import CatalogSnapshot, LineageEdge, LineageNode, RelationKind, RelationLineageReport


class CatalogLineageError(RuntimeError):
    pass


def _tokenize(sql: str) -> list[str]:
    """Tokenize enough SQL to find source relation references.

    Strings and comments are removed, quoted identifiers are preserved, and no
    expression or predicate semantics are inferred here. Unsupported forms are
    reported as unresolved by the caller rather than guessed.
    """
    tokens: list[str] = []
    current: list[str] = []
    i = 0
    quote: str | None = None
    while i < len(sql):
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < len(sql) else ""
        if quote == "'":
            if ch == "'":
                if nxt == "'":
                    i += 1
                else:
                    quote = None
            i += 1
            continue
        if quote == '"':
            current.append(ch)
            if ch == '"':
                if nxt == '"':
                    current.append(nxt)
                    i += 1
                else:
                    quote = None
                    tokens.append("".join(current))
                    current = []
            i += 1
            continue
        if ch == "'":
            if current:
                tokens.append("".join(current))
                current = []
            quote = "'"
            i += 1
            continue
        if ch == '"':
            if current:
                tokens.append("".join(current))
                current = []
            quote = '"'
            current.append(ch)
            i += 1
            continue
        if ch == "-" and nxt == "-":
            if current:
                tokens.append("".join(current))
                current = []
            i += 2
            while i < len(sql) and sql[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and nxt == "*":
            if current:
                tokens.append("".join(current))
                current = []
            i += 2
            while i + 1 < len(sql) and not (sql[i] == "*" and sql[i + 1] == "/"):
                i += 1
            i += 2
            continue
        if ch.isalnum() or ch in "_$#.@":
            current.append(ch)
        else:
            if current:
                tokens.append("".join(current))
                current = []
            if ch in "(),":
                tokens.append(ch)
        i += 1
    if current:
        tokens.append("".join(current))
    return tokens


def _clean_identifier(value: str) -> str:
    parts = []
    for part in value.split("."):
        parts.append(part.strip().strip('"').upper())
    return ".".join(part for part in parts if part)


def _source_refs(sql: str, default_schema: str) -> tuple[str, ...]:
    tokens = _tokenize(sql)
    refs: list[str] = []
    # CTE names are local and must not be treated as catalog relations.
    ctes: set[str] = set()
    for i, token in enumerate(tokens[:-1]):
        if token.upper() == "WITH" or (i > 0 and tokens[i - 1] == ","):
            nxt = tokens[i + 1]
            if nxt not in {"(", ")", ","} and i + 2 < len(tokens) and tokens[i + 2].upper() == "AS":
                ctes.add(_clean_identifier(nxt).split(".")[-1])
    keywords = {"FROM", "JOIN", "UPDATE", "INTO"}
    i = 0
    while i < len(tokens):
        upper = tokens[i].upper()
        expecting = False
        if upper in keywords:
            expecting = True
        elif upper == "MERGE" and i + 1 < len(tokens) and tokens[i + 1].upper() == "INTO":
            i += 1
            expecting = True
        elif upper == "DELETE" and i + 1 < len(tokens) and tokens[i + 1].upper() == "FROM":
            i += 1
            expecting = True
        if expecting:
            j = i + 1
            while j < len(tokens) and tokens[j] in {"(", ","}:
                if tokens[j] == "(":
                    # Derived table or table function. Do not infer a catalog ref.
                    break
                j += 1
            if j < len(tokens) and tokens[j] != "(":
                raw = _clean_identifier(tokens[j])
                if raw and raw.split(".")[-1] not in ctes and raw.upper() not in {"SELECT", "TABLE", "VALUES"}:
                    refs.append(raw if "." in raw else f"{default_schema.upper()}.{raw}")
        i += 1
    return tuple(dict.fromkeys(refs))


class CatalogLineageResolver:
    def __init__(self, snapshot: CatalogSnapshot, *, max_depth: int = 8) -> None:
        if max_depth < 1:
            raise ValueError("max_depth must be positive.")
        self.snapshot = snapshot
        self.max_depth = max_depth
        self._relations = {item.relation_ref.upper(): item for item in snapshot.relations}

    def resolve(self, root_relation_refs: Iterable[str]) -> RelationLineageReport:
        roots = tuple(dict.fromkeys(value.strip().upper() for value in root_relation_refs if value.strip()))
        nodes: dict[str, LineageNode] = {}
        edges: dict[str, LineageEdge] = {}
        unresolved: set[str] = set()
        base: set[str] = set()
        cycles: set[tuple[str, ...]] = set()
        max_depth_reached = False
        queue: deque[tuple[str, int, tuple[str, ...]]] = deque((root, 0, ()) for root in roots)

        while queue:
            ref, depth, lineage = queue.popleft()
            relation = self._relations.get(ref)
            if relation is None:
                unresolved.add(ref)
                nodes.setdefault(
                    ref,
                    LineageNode(
                        node_id=f"relation:{ref}",
                        relation_ref=ref,
                        relation_kind=RelationKind.UNKNOWN,
                        status="SOURCE_UNAVAILABLE",
                        depth=depth,
                    ),
                )
                continue
            nodes.setdefault(
                ref,
                LineageNode(
                    node_id=f"relation:{ref}",
                    relation_ref=ref,
                    relation_kind=relation.relation_kind,
                    status=relation.resolution_status,
                    depth=depth,
                    attributes={
                        "provider_ref": relation.definition.provider_ref,
                        "column_count": len(relation.definition.columns),
                        "primary_key": list(relation.definition.primary_key),
                    },
                ),
            )
            if ref in lineage:
                start = lineage.index(ref)
                cycles.add(lineage[start:] + (ref,))
                unresolved.add(f"VIEW_RECURSION_DETECTED:{ref}")
                continue
            if depth >= self.max_depth:
                max_depth_reached = True
                unresolved.add(f"VIEW_EXPANSION_DEPTH_LIMIT:{ref}")
                continue
            targets: tuple[str, ...] = ()
            edge_kind = "DEPENDS_ON"
            if relation.relation_kind is RelationKind.SYNONYM:
                targets = (relation.synonym_target_ref.upper(),) if relation.synonym_target_ref else ()
                edge_kind = "SYNONYM_OF"
            elif relation.relation_kind in {RelationKind.VIEW, RelationKind.MATERIALIZED_QUERY_TABLE}:
                if not relation.view_definition_text:
                    unresolved.add(f"VIEW_DEFINITION_UNAVAILABLE:{ref}")
                else:
                    targets = _source_refs(relation.view_definition_text, relation.definition.schema_name)
                    edge_kind = "DERIVED_FROM"
            elif relation.relation_kind in {RelationKind.TABLE, RelationKind.NICKNAME, RelationKind.TEMPORARY_TABLE}:
                base.add(ref)
                if relation.relation_kind is RelationKind.NICKNAME and not relation.remote_source_ref:
                    unresolved.add(f"REMOTE_METADATA_UNAVAILABLE:{ref}")
            elif relation.relation_kind is RelationKind.TABLE_FUNCTION:
                unresolved.add(f"TABLE_FUNCTION_BODY_UNAVAILABLE:{ref}")

            for target in targets:
                edge_id = f"edge:{hashlib.sha256((ref+'|'+edge_kind+'|'+target).encode()).hexdigest()[:20]}"
                edges[edge_id] = LineageEdge(
                    edge_id=edge_id,
                    source_ref=ref,
                    target_ref=target,
                    edge_kind=edge_kind,
                    evidence_refs=relation.evidence_refs,
                )
                queue.append((target, depth + 1, lineage + (ref,)))

        payload = {
            "schema_version": "relation-lineage-report-1.0",
            "report_id": f"lineage-{hashlib.sha256('|'.join(roots).encode()).hexdigest()[:16]}",
            "root_relation_refs": roots,
            "nodes": tuple(sorted(nodes.values(), key=lambda item: item.relation_ref)),
            "edges": tuple(sorted(edges.values(), key=lambda item: item.edge_id)),
            "base_relation_refs": tuple(sorted(base)),
            "unresolved_boundaries": tuple(sorted(unresolved)),
            "cycles": tuple(sorted(cycles)),
            "max_depth_reached": max_depth_reached,
        }
        return RelationLineageReport(**payload, content_digest=canonical_digest(payload))
