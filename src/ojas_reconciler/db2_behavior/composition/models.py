from __future__ import annotations

from enum import StrEnum
from pydantic import model_validator

from ..core.models import CanonicalModel
from ..commercial.models import CompositionKind, CompositionTransactionRelationship, ParameterMapping


class CompositionCandidateStatus(StrEnum):
    SOURCE_CALL_RESOLVED = "SOURCE_CALL_RESOLVED"
    TARGET_SOURCE_UNAVAILABLE = "TARGET_SOURCE_UNAVAILABLE"
    TARGET_AMBIGUOUS = "TARGET_AMBIGUOUS"
    DYNAMIC_TARGET = "DYNAMIC_TARGET"


class ProcedureCompositionCandidate(CanonicalModel):
    candidate_id: str
    composition_kind: CompositionKind
    upstream_procedure_ref: str
    downstream_procedure_ref: str
    upstream_semantic_digest: str
    downstream_semantic_digest: str | None = None
    invocation_site_ref: str
    invocation_text: str
    parameter_mappings: tuple[ParameterMapping, ...] = ()
    transaction_relationship: CompositionTransactionRelationship
    status: CompositionCandidateStatus
    blockers: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...]


class CompositionCandidateBatch(CanonicalModel):
    schema_version: str = "composition-candidate-batch-1.0"
    batch_id: str
    candidates: tuple[ProcedureCompositionCandidate, ...]
    content_digest: str

    @model_validator(mode="after")
    def validate_ids(self) -> "CompositionCandidateBatch":
        values = [item.candidate_id for item in self.candidates]
        if len(values) != len(set(values)):
            raise ValueError("Composition candidate IDs must be unique.")
        return self
