from __future__ import annotations

import hashlib
import re
from pathlib import Path

from atlas.core.canonical import canonical_digest
from atlas.core.models import (
    DialectId,
    EdgeKind,
    EffectModality,
    RoutineIR,
    SemanticEdge,
    SemanticFinding,
    SemanticNode,
    SemanticNodeKind,
    SourceSpan,
)
from .base import DialectSemanticPolicy, DialectStatementClassifier, ProceduralDialectProfile
from .normalization import DialectNormalizer
from .classifier import CommonStatementClassifier, _WORD, _assignment, _condition_text, _relations, _variables
from .control_flow import refine_control_flow
from .scanner import _expand_inline_control_statements, _logical_statements, _span
from .structure import RegionFrame, StructuredRegionTracker
from .syntax import _extract_body, _extract_header


class UniversalProceduralAdapter:
    """Deterministic dialect adapter into Atlas's database-neutral routine IR.

    Every logical statement becomes a semantic node. Unsupported vendor extensions
    are retained as OPAQUE nodes and never disappear from evidence.
    """

    def __init__(
        self,
        profile: ProceduralDialectProfile,
        atlas_version: str,
        *,
        classifier: DialectStatementClassifier | None = None,
        semantic_policy: DialectSemanticPolicy | None = None,
        normalizer: DialectNormalizer | None = None,
    ) -> None:
        self.profile = profile
        self.adapter_id = profile.adapter_id
        self.dialect = profile.dialect
        self.atlas_version = atlas_version
        self.normalizer = normalizer or DialectNormalizer(
            dialect=profile.dialect,
            quote_pairs=profile.identifier_quotes,
            unquoted_server_case="UPPER",
        )
        self.classifier = classifier or CommonStatementClassifier(profile.dialect)
        if semantic_policy is None:
            from .semantics import POLICIES

            semantic_policy = POLICIES[profile.dialect]
        self.semantic_policy = semantic_policy

    def parse(self, source: Path) -> RoutineIR:
        return self.parse_text(source.read_text(encoding="utf-8"), source.name)

    def parse_text(self, text: str, source_name: str = "inline.sql") -> RoutineIR:
        header = _extract_header(text, self.profile, self.normalizer)
        body, body_start = _extract_body(text, header, self.profile)
        source_digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        body_digest = "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()
        statements = _expand_inline_control_statements(
            _logical_statements(body, body_start, text),
            self.profile.dialect,
        )

        nodes: list[SemanticNode] = []
        edges: list[SemanticEdge] = []
        findings: list[SemanticFinding] = []
        entry_id = "node-entry"
        exit_id = "node-exit"
        nodes.append(
            SemanticNode(
                node_id=entry_id,
                kind=SemanticNodeKind.ENTRY,
                text=f"ENTRY {header.routine_name}",
                source_span=SourceSpan(
                    start_line=1,
                    start_column=1,
                    end_line=1,
                    end_column=1,
                    start_offset=0,
                    end_offset=0,
                ),
            )
        )

        tracker = StructuredRegionTracker(self.profile.dialect)
        previous = entry_id
        pending_edge = EdgeKind.NEXT
        pending_condition: str | None = None
        in_declare_section = self.profile.initial_declare_section

        normalized = [re.sub(r"\s+", " ", item.text.upper()).strip().rstrip(";") for item in statements]
        for position, statement in enumerate(statements):
            index = position + 1
            upper = normalized[position]
            next_upper = normalized[position + 1] if position + 1 < len(normalized) else None
            if upper == "BEGIN" or upper.startswith("BEGIN "):
                in_declare_section = False

            kind, attrs = self.classifier.classify(statement, self.profile, in_declare_section)
            # Oracle/PLpgSQL WHEN clauses inside EXCEPTION sections are handlers,
            # while CASE WHEN remains a decision branch.
            if upper.startswith("WHEN ") and tracker.nearest("HANDLER") and not tracker.nearest("CASE"):
                kind = SemanticNodeKind.ERROR_HANDLER
                attrs = {"handler_kind": "WHEN", "condition_text": _condition_text(statement.text)}

            node_id = f"node-{index:04d}"
            parent_ref = tracker.parent_for(kind, attrs, upper)
            override_source, override_edge, override_condition = tracker.branch_edge(kind, attrs, upper)
            edge_source = override_source or previous
            edge_kind = override_edge if override_source else pending_edge
            edge_condition = override_condition if override_source else pending_condition

            condition_text = attrs.get("condition_text") if isinstance(attrs.get("condition_text"), str) else None
            assignment = _assignment(statement.text, self.profile.dialect)
            relation_refs = _relations(statement.text, self.normalizer)
            reads = list(_variables(statement.text, self.normalizer))
            writes: list[str] = []
            if assignment:
                target = self.normalizer.normalize_variable(assignment[0])
                writes.append(target)
                reads = list(_variables(assignment[1], self.normalizer))
            if kind is SemanticNodeKind.SELECT_INTO:
                into = re.search(r"(?is)\bINTO\s+(.+?)(?:\bFROM\b|;|$)", statement.text)
                if into:
                    writes.extend(self.normalizer.normalize_variable(value) for value in _WORD.findall(into.group(1)))

            conditional_regions = {"IF", "CASE", "LOOP", "HANDLER", "TRY_CATCH"}
            modality = (
                EffectModality.CONDITIONAL
                if any(frame.kind in conditional_regions for frame in tracker.frames)
                else EffectModality.MUST
            )
            node = SemanticNode(
                node_id=node_id,
                kind=kind,
                text=statement.text.strip(),
                source_span=_span(statement, text),
                parent_ref=parent_ref,
                condition_text=condition_text,
                target_name=(
                    self.normalizer.normalize_variable(attrs["target_name"])
                    if isinstance(attrs.get("target_name"), str)
                    else None
                ),
                expression_text=attrs.get("expression_text") if isinstance(attrs.get("expression_text"), str) else None,
                relation_refs=relation_refs,
                variable_reads=tuple(reads),
                variable_writes=tuple(dict.fromkeys(writes)),
                call_target=(
                    self.normalizer.normalize_identifier(attrs["call_target"])
                    if isinstance(attrs.get("call_target"), str)
                    else None
                ),
                cursor_name=(
                    self.normalizer.normalize_identifier(attrs["cursor_name"])
                    if isinstance(attrs.get("cursor_name"), str)
                    else None
                ),
                error_code=attrs.get("error_code") if isinstance(attrs.get("error_code"), str) else None,
                modality=modality,
                attributes={
                    key: value
                    for key, value in attrs.items()
                    if key
                    not in {
                        "condition_text",
                        "target_name",
                        "expression_text",
                        "call_target",
                        "cursor_name",
                        "error_code",
                    }
                },
            )
            nodes.append(node)
            edges.append(
                SemanticEdge(
                    edge_id=f"edge-{len(edges) + 1:04d}",
                    source_ref=edge_source,
                    target_ref=node_id,
                    kind=edge_kind,
                    condition_text=edge_condition,
                )
            )

            if kind is SemanticNodeKind.OPAQUE:
                findings.append(
                    SemanticFinding(
                        code="DIALECT_STATEMENT_OPAQUE",
                        severity="WARNING",
                        message=f"{self.profile.dialect.value} statement was retained as an opaque semantic node.",
                        source_span=node.source_span,
                        consequence="Effects depending on this statement remain conditional or unknown.",
                    )
                )

            pending_edge, pending_condition, closed = tracker.after_node(
                node_id=node_id,
                kind=kind,
                attrs=attrs,
                upper=upper,
                next_upper=next_upper,
            )
            self._add_loop_back_edges(edges, node_id, closed)
            previous = node_id

        exit_offset = len(text)
        nodes.append(
            SemanticNode(
                node_id=exit_id,
                kind=SemanticNodeKind.EXIT,
                text=f"EXIT {header.routine_name}",
                source_span=SourceSpan(
                    start_line=text.count("\n") + 1,
                    start_column=max(1, len(text.rsplit("\n", 1)[-1]) + 1),
                    end_line=text.count("\n") + 1,
                    end_column=max(1, len(text.rsplit("\n", 1)[-1]) + 1),
                    start_offset=exit_offset,
                    end_offset=exit_offset,
                ),
            )
        )
        edges.append(
            SemanticEdge(
                edge_id=f"edge-{len(edges) + 1:04d}",
                source_ref=previous,
                target_ref=exit_id,
                kind=EdgeKind.NEXT,
            )
        )
        remaining = tracker.drain()
        if remaining:
            findings.append(
                SemanticFinding(
                    code="UNCLOSED_PROCEDURAL_REGION",
                    severity="ERROR",
                    message=f"{len(remaining)} procedural region(s) remained open after parsing.",
                    consequence="Control-flow completeness is partial.",
                )
            )

        nodes, edges, findings = refine_control_flow(
            nodes,
            edges,
            findings,
            entry_id=entry_id,
            exit_id=exit_id,
        )

        payload = {
            "schema_version": "atlas-routine-ir-1.0",
            "atlas_version": self.atlas_version,
            "dialect": self.profile.dialect,
            "adapter_id": self.adapter_id,
            "routine_kind": header.routine_kind,
            "schema_name": header.schema_name,
            "routine_name": header.routine_name,
            "parameters": header.parameters,
            "routine_attributes": header.routine_attributes,
            "source_name": source_name,
            "source_digest": source_digest,
            "body_digest": body_digest,
            "nodes": tuple(nodes),
            "edges": tuple(edges),
            "findings": tuple(findings),
            "entry_node_ref": entry_id,
            "exit_node_ref": exit_id,
        }
        ir = RoutineIR(**payload, content_digest=canonical_digest(payload))
        enriched = self.semantic_policy.enrich(ir)
        enriched_payload = enriched.model_dump(mode="json", exclude={"content_digest"})
        return enriched.model_copy(update={"content_digest": canonical_digest(enriched_payload)})

    @staticmethod
    def _add_loop_back_edges(edges: list[SemanticEdge], closing_node: str, closed: list[RegionFrame]) -> None:
        for frame in closed:
            if frame.kind != "LOOP":
                continue
            edges.append(
                SemanticEdge(
                    edge_id=f"edge-{len(edges) + 1:04d}",
                    source_ref=closing_node,
                    target_ref=frame.root_ref,
                    kind=EdgeKind.LOOP_BACK,
                    condition_text=frame.condition_text,
                )
            )
