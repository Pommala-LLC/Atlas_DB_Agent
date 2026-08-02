from __future__ import annotations

import hashlib

from ojas_reconciler.db2_behavior.parsing.models import ProcedureAst
from ojas_reconciler.db2_behavior.analysis.models import OrderedDecisionReduction, PredicateGraph


class OrderedDecisionReducer:
    """Creates deterministic technical reductions for ordered IF ladders."""

    def build(
        self,
        ast: ProcedureAst,
        graphs: tuple[PredicateGraph, ...],
    ) -> tuple[OrderedDecisionReduction, ...]:
        by_id = {node.node_id: node for node in ast.nodes}
        result: list[OrderedDecisionReduction] = []
        for graph in graphs:
            region = graph.controlling_region_ref
            if not region.startswith("if-arm:"):
                continue
            parts = region.split(":")
            if len(parts) < 4:
                continue
            node = by_id.get(parts[1])
            if node is None or node.if_region is None:
                continue
            try:
                index = int(parts[2])
            except ValueError:
                continue
            if index <= 0 or index >= len(node.if_region.arms):
                continue
            current = node.if_region.arms[index]
            preceding = tuple(arm.arm_id for arm in node.if_region.arms[:index])
            payload = f"{region}|{'|'.join(preceding)}|{current.arm_id}"
            result.append(
                OrderedDecisionReduction(
                    reduction_id="decision-reduction-"
                    + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
                    controlling_region_ref=region,
                    preceding_arm_refs=preceding,
                    current_arm_ref=current.arm_id,
                    evidence_refs=tuple((*preceding, current.arm_id)),
                )
            )
        return tuple(sorted(result, key=lambda value: value.reduction_id))
