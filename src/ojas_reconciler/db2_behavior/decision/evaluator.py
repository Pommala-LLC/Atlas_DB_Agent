from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..core.canonical_json import canonical_digest
from .models import (
    DecisionEvaluationRequest,
    DecisionEvaluationResult,
    DecisionOutput,
    DecisionPredicate,
    DecisionRule,
    ExtractedDecisionModel,
    TruthValue,
)


class DecisionModelError(RuntimeError):
    pass


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _artifact(run_dir: Path, relative: str) -> Path:
    candidates = [run_dir / relative, run_dir / "extraction" / relative]
    if relative == "03-semantic-phase2-4.json":
        candidates.append(run_dir / "03-semantic.json")
    for value in candidates:
        if value.is_file():
            return value
    raise DecisionModelError(f"Required decision artifact is missing: {relative}")


class ExtractedDecisionModelBuilder:
    """Build a first-match model from semantic slices and parser evidence.

    The builder does not translate SQL into a second implementation. Each input
    is an extracted predicate evidence node, and evaluation accepts explicit
    TRUE/FALSE/UNKNOWN assignments for those predicate IDs.
    """

    def build(self, run_dir: Path) -> ExtractedDecisionModel:
        run_dir = run_dir.resolve()
        semantic_path = _artifact(run_dir, "03-semantic-phase2-4.json")
        parse_path = _artifact(run_dir, "02-parse.json")
        semantic = _load(semantic_path)
        parsed = _load(parse_path)
        ast = parsed.get("ast") or {}
        nodes = {str(item.get("node_id")): item for item in ast.get("nodes", [])}
        effects = {str(item.get("effect_id")): item for item in semantic.get("effects", [])}
        bundles = {str(item.get("bundle_id")): item for item in semantic.get("behavior_bundles", [])}

        procedure_ref = ".".join(
            value for value in [str(ast.get("schema_name") or ""), str(ast.get("procedure_name") or "")] if value
        ) or "UNKNOWN_PROCEDURE"
        semantic_digest = str(semantic.get("content_digest") or canonical_digest(semantic))
        predicates: dict[str, DecisionPredicate] = {}
        candidate_rules: list[tuple[int, DecisionRule]] = []

        for slice_item in semantic.get("behavior_slices", []):
            predicate_refs = tuple(str(value) for value in slice_item.get("control_predicate_node_refs", []))
            outputs: list[DecisionOutput] = []
            for obligation in slice_item.get("effect_obligations", []):
                effect = effects.get(str(obligation.get("effect_ref")))
                if not effect:
                    continue
                target = str(effect.get("target") or "")
                kind = str(effect.get("effect_kind") or "UNKNOWN")
                # A decision row must have an observable output/effect, not only
                # local state. OUT parameters conventionally begin with P_.
                if kind not in {"ASSIGNMENT", "SIGNAL", "CALL", "MUTATION", "RESULT_SET"} and not target:
                    continue
                outputs.append(
                    DecisionOutput(
                        target=target or kind,
                        value_expression=(str(effect.get("value_expression")) if effect.get("value_expression") is not None else None),
                        effect_kind=kind,
                        evidence_refs=tuple(str(value) for value in effect.get("evidence_refs", [])),
                    )
                )
            if not outputs:
                continue
            predicate_ids: list[str] = []
            source_lines: list[int] = []
            for ref in predicate_refs:
                node = nodes.get(ref)
                text = str((node or {}).get("text") or ref)
                source_range = (node or {}).get("source_range") or {}
                line = source_range.get("start_line")
                predicate_id = "predicate-" + hashlib.sha256((ref + "|" + text).encode()).hexdigest()[:20]
                predicates.setdefault(
                    predicate_id,
                    DecisionPredicate(
                        predicate_id=predicate_id,
                        expression_text=text,
                        evidence_refs=(ref,),
                        source_line=(int(line) if line is not None else None),
                    ),
                )
                predicate_ids.append(predicate_id)
                if line is not None:
                    source_lines.append(int(line))
            # Effects without a control predicate are not decision arms and stay
            # outside What-If evaluation.
            if not predicate_ids:
                continue
            bundle_ref = str(slice_item.get("bundle_ref") or "")
            bundle = bundles.get(bundle_ref) or {}
            evidence_lines = []
            for ref in bundle.get("evidence_refs", []):
                node = nodes.get(str(ref))
                if node and (node.get("source_range") or {}).get("start_line"):
                    evidence_lines.append(int(node["source_range"]["start_line"]))
            order_line = min(source_lines + evidence_lines) if source_lines or evidence_lines else 10**9
            rule_id = "rule-" + hashlib.sha256((str(slice_item.get("slice_id")) + "|" + bundle_ref).encode()).hexdigest()[:20]
            candidate_rules.append(
                (
                    order_line,
                    DecisionRule(
                        rule_id=rule_id,
                        priority=0,
                        predicate_ids=tuple(predicate_ids),
                        outputs=tuple(outputs),
                        source_behavior_ref=str(slice_item.get("slice_id") or bundle_ref),
                        completeness=str(slice_item.get("analysis_completeness") or "UNKNOWN"),
                    ),
                )
            )

        ordered_rules: list[DecisionRule] = []
        for priority, (_, rule) in enumerate(sorted(candidate_rules, key=lambda value: (value[0], value[1].rule_id)), start=1):
            ordered_rules.append(rule.model_copy(update={"priority": priority}))
        limitations: list[str] = []
        if any(rule.completeness != "COMPLETE" for rule in ordered_rules):
            limitations.append("Some decision rules are partial and results remain technical candidates.")
        if not ordered_rules:
            limitations.append("No predicate-controlled observable decision rules were extracted.")
        payload = {
            "schema_version": "extracted-decision-model-1.0",
            "model_id": f"decision-model-{hashlib.sha256((procedure_ref+'|'+semantic_digest).encode()).hexdigest()[:18]}",
            "procedure_ref": procedure_ref,
            "semantic_digest": semantic_digest,
            "predicates": tuple(sorted(predicates.values(), key=lambda item: ((item.source_line or 10**9), item.predicate_id))),
            "rules": tuple(ordered_rules),
            "evaluation_semantics": "FIRST_MATCH_ALL_PREDICATES_TRUE",
            "limitations": tuple(limitations),
        }
        return ExtractedDecisionModel(**payload, content_digest=canonical_digest(payload))


class ModelDrivenDecisionEvaluator:
    def evaluate(
        self,
        *,
        model: ExtractedDecisionModel,
        request: DecisionEvaluationRequest,
    ) -> DecisionEvaluationResult:
        if request.model_digest != model.content_digest:
            raise DecisionModelError("Decision request model_digest does not match the extracted model.")
        valid_ids = {item.predicate_id for item in model.predicates}
        unknown_ids = set(request.predicate_values) - valid_ids
        if unknown_ids:
            raise DecisionModelError(f"Unknown predicate IDs: {sorted(unknown_ids)}")
        evaluated: list[dict[str, object]] = []
        blockers: set[str] = set()
        matched: DecisionRule | None = None
        for rule in sorted(model.rules, key=lambda item: item.priority):
            values = [request.predicate_values.get(pid, TruthValue.UNKNOWN) for pid in rule.predicate_ids]
            if any(value is TruthValue.FALSE for value in values):
                status = "NOT_MATCHED"
            elif all(value is TruthValue.TRUE for value in values):
                status = "MATCHED"
                matched = rule
            else:
                status = "INCONCLUSIVE"
                blockers.update(pid for pid, value in zip(rule.predicate_ids, values) if value is TruthValue.UNKNOWN)
            evaluated.append(
                {
                    "rule_id": rule.rule_id,
                    "priority": rule.priority,
                    "status": status,
                    "predicate_values": {pid: value.value for pid, value in zip(rule.predicate_ids, values)},
                }
            )
            if matched:
                break
        if matched:
            status = "MATCHED"
            outputs = matched.outputs
            matched_rule_id = matched.rule_id
        elif blockers:
            status = "INCONCLUSIVE"
            outputs = ()
            matched_rule_id = None
        else:
            status = "NO_MATCH"
            outputs = ()
            matched_rule_id = None
        payload = {
            "schema_version": "decision-evaluation-result-1.0",
            "model_digest": model.content_digest,
            "status": status,
            "matched_rule_id": matched_rule_id,
            "outputs": outputs,
            "evaluated_rules": tuple(evaluated),
            "blockers": tuple(sorted(blockers)),
        }
        return DecisionEvaluationResult(**payload, content_digest=canonical_digest(payload))
