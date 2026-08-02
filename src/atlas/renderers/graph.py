from __future__ import annotations

from atlas.core.canonical import canonical_digest
from atlas.core.models import RoutineIR


def render_graph(ir: RoutineIR) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": "atlas-routine-graph-1.0",
        "routine_ref": f"{ir.schema_name + '.' if ir.schema_name else ''}{ir.routine_name}",
        "dialect": ir.dialect.value,
        "source_ir_digest": ir.content_digest,
        "nodes": [
            {
                "node_id": node.node_id,
                "kind": node.kind.value,
                "label": node.text[:160],
                "relations": list(node.relation_refs),
                "source_span": node.source_span.model_dump(mode="json"),
            }
            for node in ir.nodes
        ],
        "edges": [edge.model_dump(mode="json") for edge in ir.edges],
    }
    payload["content_digest"] = canonical_digest(payload)
    return payload
