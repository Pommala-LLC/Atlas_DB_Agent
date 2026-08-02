from __future__ import annotations

from collections import Counter
from pathlib import Path

from atlas.core.canonical import canonical_digest
from atlas.core.models import (
    DecisionArm,
    DialectId,
    EffectSummary,
    RoutineIR,
    RoutineSemanticReport,
    ScenarioCandidate,
    ScenarioCandidateBatch,
    SemanticNode,
    SemanticNodeKind,
)
from atlas.dialects.registry import AtlasDialectRegistry




def routine_reference(ir: RoutineIR) -> str:
    """Return an overload-safe routine identity for dialects that support it."""
    base = f"{ir.schema_name + '.' if ir.schema_name else ''}{ir.routine_name}"
    if ir.dialect is DialectId.POSTGRESQL_PLPGSQL:
        identity = [p.type_text for p in ir.parameters if p.mode not in {"OUT", "RETURN"}]
        return f"{base}({','.join(identity)})"
    if ir.dialect is DialectId.ORACLE_PLSQL:
        identity = [f"{p.mode}:{p.type_text}" for p in ir.parameters if p.mode != "RETURN"]
        return f"{base}({','.join(identity)})"
    return base


_EFFECT_KINDS = {
    SemanticNodeKind.ASSIGNMENT,
    SemanticNodeKind.INSERT,
    SemanticNodeKind.UPDATE,
    SemanticNodeKind.DELETE,
    SemanticNodeKind.MERGE,
    SemanticNodeKind.UPSERT,
    SemanticNodeKind.CALL,
    SemanticNodeKind.DYNAMIC_SQL,
    SemanticNodeKind.ERROR_RAISE,
    SemanticNodeKind.RESULT_SET,
    SemanticNodeKind.TRANSACTION_BEGIN,
    SemanticNodeKind.COMMIT,
    SemanticNodeKind.ROLLBACK,
    SemanticNodeKind.SAVEPOINT,
    SemanticNodeKind.RETURN,
    SemanticNodeKind.TEMP_OBJECT,
    SemanticNodeKind.SECURITY_CONTEXT,
}


class AtlasSemanticService:
    def __init__(self, atlas_version: str) -> None:
        self.atlas_version = atlas_version
        self.registry = AtlasDialectRegistry.default(atlas_version)

    def analyze(self, source: Path, dialect: DialectId) -> tuple[RoutineIR, RoutineSemanticReport, ScenarioCandidateBatch]:
        ir = self.registry.adapter(dialect).parse(source)
        report = self.report(ir)
        scenarios = self.scenarios(ir, report)
        return ir, report, scenarios

    def report(self, ir: RoutineIR) -> RoutineSemanticReport:
        nodes = list(ir.nodes)
        decision_arms: list[DecisionArm] = []
        effects: list[EffectSummary] = []
        relations: list[str] = []
        calls: list[str] = []
        dynamic: list[str] = []
        results: list[str] = []
        transactions: list[str] = []
        handlers: list[str] = []
        opaque: list[str] = []
        for node in nodes:
            for relation in node.relation_refs:
                if relation not in relations:
                    relations.append(relation)
            if node.call_target and node.call_target not in calls:
                calls.append(node.call_target)
            if node.kind is SemanticNodeKind.DYNAMIC_SQL:
                dynamic.append(node.node_id)
            if node.kind is SemanticNodeKind.RESULT_SET:
                results.append(node.node_id)
            if node.kind in {SemanticNodeKind.TRANSACTION_BEGIN, SemanticNodeKind.COMMIT, SemanticNodeKind.ROLLBACK, SemanticNodeKind.SAVEPOINT}:
                transactions.append(node.node_id)
            if node.kind is SemanticNodeKind.ERROR_HANDLER:
                handlers.append(node.node_id)
            if node.kind is SemanticNodeKind.OPAQUE:
                opaque.append(node.node_id)
            if node.kind in _EFFECT_KINDS:
                conditions: list[str] = []
                parent = node.parent_ref
                seen: set[str] = set()
                by_id = {value.node_id: value for value in nodes}
                while parent and parent not in seen:
                    seen.add(parent)
                    parent_node = by_id.get(parent)
                    if parent_node is None:
                        break
                    if parent_node.condition_text:
                        conditions.append(parent_node.node_id)
                    parent = parent_node.parent_ref
                effects.append(EffectSummary(
                    effect_id=f"effect-{len(effects)+1:04d}",
                    node_ref=node.node_id,
                    kind=node.kind,
                    target=node.target_name or (node.relation_refs[0] if node.relation_refs else node.call_target),
                    expression=node.expression_text or node.text,
                    modality=node.modality,
                    condition_refs=tuple(reversed(conditions)),
                    relation_refs=node.relation_refs,
                ))
        condition_nodes = [node for node in nodes if node.kind is SemanticNodeKind.CONDITION and node.condition_text]
        for precedence, condition in enumerate(condition_nodes, start=1):
            descendants = [
                effect.node_ref
                for effect in effects
                if condition.node_id in effect.condition_refs
            ]
            if not descendants:
                # Retain the arm even when its effect is opaque; this is useful for review.
                descendants = tuple(
                    node.node_id for node in nodes if node.parent_ref == condition.node_id and node.kind is not SemanticNodeKind.CONDITION
                )
            decision_arms.append(DecisionArm(
                arm_id=f"arm-{precedence:04d}",
                precedence=precedence,
                predicate_node_ref=condition.node_id,
                condition_text=condition.condition_text,
                effect_node_refs=tuple(descendants),
                terminal=any(
                    node.node_id in descendants and node.kind in {SemanticNodeKind.RETURN, SemanticNodeKind.ERROR_RAISE, SemanticNodeKind.ROLLBACK}
                    for node in nodes
                ),
            ))
        finding_counts = Counter(finding.code for finding in ir.findings)
        status = "COMPLETE"
        if any(finding.severity in {"WARNING", "ERROR"} for finding in ir.findings) or opaque:
            status = "PARTIAL"
        if not ir.nodes:
            status = "BLOCKED"
        payload = {
            "schema_version": "atlas-routine-semantic-report-1.0",
            "atlas_version": self.atlas_version,
            "dialect": ir.dialect,
            "routine_ref": routine_reference(ir),
            "routine_ir_digest": ir.content_digest,
            "parse_status": status,
            "decision_arms": tuple(decision_arms),
            "effects": tuple(effects),
            "call_targets": tuple(calls),
            "relation_refs": tuple(relations),
            "dynamic_sql_node_refs": tuple(dynamic),
            "result_set_node_refs": tuple(results),
            "transaction_node_refs": tuple(transactions),
            "handler_node_refs": tuple(handlers),
            "opaque_node_refs": tuple(opaque),
            "finding_counts": dict(sorted(finding_counts.items())),
        }
        return RoutineSemanticReport(**payload, content_digest=canonical_digest(payload))

    def scenarios(self, ir: RoutineIR, report: RoutineSemanticReport) -> ScenarioCandidateBatch:
        by_id = {node.node_id: node for node in ir.nodes}
        scenarios: list[ScenarioCandidate] = []
        for arm in report.decision_arms:
            effect_nodes = [by_id[node_id] for node_id in arm.effect_node_refs if node_id in by_id]
            then = tuple(self._effect_text(node) for node in effect_nodes) or ("the branch completes without a classified observable effect",)
            scenarios.append(ScenarioCandidate(
                scenario_id=f"scenario-{len(scenarios)+1:04d}",
                name=f"Apply ordered condition {arm.precedence}: {arm.condition_text[:80]}",
                given=(f'the technical condition "{arm.condition_text}" evaluates true',),
                when=f"{report.routine_ref} is invoked",
                then=then,
                evidence_refs=(arm.predicate_node_ref, *arm.effect_node_refs),
            ))
        if not scenarios:
            for effect in report.effects:
                node = by_id[effect.node_ref]
                scenarios.append(ScenarioCandidate(
                    scenario_id=f"scenario-{len(scenarios)+1:04d}",
                    name=f"Observe {node.kind.value.lower().replace('_', ' ')}",
                    given=("the preceding statements complete successfully",),
                    when=f"{report.routine_ref} is invoked",
                    then=(self._effect_text(node),),
                    evidence_refs=(node.node_id,),
                ))
        payload = {
            "schema_version": "atlas-scenario-candidate-batch-1.0",
            "routine_ref": report.routine_ref,
            "dialect": ir.dialect,
            "scenarios": tuple(scenarios),
            "source_ir_digest": ir.content_digest,
        }
        return ScenarioCandidateBatch(**payload, content_digest=canonical_digest(payload))

    @staticmethod
    def _effect_text(node: SemanticNode) -> str:
        if node.kind is SemanticNodeKind.ASSIGNMENT:
            return f"{node.target_name} is set to {node.expression_text}"
        if node.kind in {SemanticNodeKind.INSERT, SemanticNodeKind.UPDATE, SemanticNodeKind.DELETE, SemanticNodeKind.MERGE, SemanticNodeKind.UPSERT}:
            target = node.relation_refs[0] if node.relation_refs else "an unresolved relation"
            return f"the {node.kind.value.lower()} effect on {target} occurs"
        if node.kind is SemanticNodeKind.CALL:
            return f"the routine {node.call_target} is called"
        if node.kind is SemanticNodeKind.ERROR_RAISE:
            return f"an error is raised{f' with code {node.error_code}' if node.error_code else ''}"
        if node.kind is SemanticNodeKind.RESULT_SET:
            return "a result set is returned or opened"
        if node.kind is SemanticNodeKind.RETURN:
            return f"the routine returns {node.expression_text or 'control'}"
        return node.text.rstrip(";")
