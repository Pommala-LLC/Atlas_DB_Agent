from __future__ import annotations

from enum import StrEnum
from pydantic import model_validator

from ..core.models import CanonicalModel


class TruthValue(StrEnum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


class DecisionPredicate(CanonicalModel):
    predicate_id: str
    expression_text: str
    evidence_refs: tuple[str, ...]
    source_line: int | None = None


class DecisionOutput(CanonicalModel):
    target: str
    value_expression: str | None = None
    effect_kind: str
    evidence_refs: tuple[str, ...]


class DecisionRule(CanonicalModel):
    rule_id: str
    priority: int
    predicate_ids: tuple[str, ...]
    outputs: tuple[DecisionOutput, ...]
    source_behavior_ref: str
    authority: str = "EXTRACTED_TECHNICAL_EVIDENCE"
    completeness: str = "COMPLETE"


class ExtractedDecisionModel(CanonicalModel):
    schema_version: str = "extracted-decision-model-1.0"
    model_id: str
    procedure_ref: str
    semantic_digest: str
    predicates: tuple[DecisionPredicate, ...]
    rules: tuple[DecisionRule, ...]
    evaluation_semantics: str = "FIRST_MATCH_ALL_PREDICATES_TRUE"
    limitations: tuple[str, ...] = ()
    content_digest: str

    @model_validator(mode="after")
    def validate_refs(self) -> "ExtractedDecisionModel":
        predicate_ids = {item.predicate_id for item in self.predicates}
        priorities = [item.priority for item in self.rules]
        if len(priorities) != len(set(priorities)):
            raise ValueError("Decision rule priorities must be unique.")
        for rule in self.rules:
            missing = set(rule.predicate_ids) - predicate_ids
            if missing:
                raise ValueError(f"Decision rule references missing predicates: {sorted(missing)}")
        return self


class DecisionEvaluationRequest(CanonicalModel):
    schema_version: str = "decision-evaluation-request-1.0"
    model_digest: str
    predicate_values: dict[str, TruthValue]


class DecisionEvaluationResult(CanonicalModel):
    schema_version: str = "decision-evaluation-result-1.0"
    model_digest: str
    status: str
    matched_rule_id: str | None = None
    outputs: tuple[DecisionOutput, ...] = ()
    evaluated_rules: tuple[dict[str, object], ...] = ()
    blockers: tuple[str, ...] = ()
    content_digest: str
