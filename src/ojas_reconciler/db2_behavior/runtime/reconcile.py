from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from pydantic import model_validator

from ..core.canonical_json import canonical_digest
from ..core.models import CanonicalModel
from .models import (
    RuntimeExecutionRecord,
    RuntimeVerificationBatch,
    RuntimeVerificationPlanBatch,
    RuntimeVerificationStatus,
)
from .verify import RuntimeVerifier


class RuntimeReconciliationError(RuntimeError):
    pass


class RuntimeFalsificationCandidate(CanonicalModel):
    candidate_id: str
    classification: str = "STATIC_RUNTIME_CONTRADICTION_CANDIDATE"
    verification_result_ref: str
    verification_result_digest: str
    scenario_spec_ref: str
    finding_refs: tuple[str, ...]
    authority_scope: str = "RUNTIME_EVIDENCE_ONLY"
    promotion_status: str = "HUMAN_GOVERNANCE_REQUIRED"
    content_digest: str


class RuntimeReconciliationReport(CanonicalModel):
    schema_version: str = "runtime-reconciliation-report-1.0"
    plan_batch_digest: str
    verification_batch_digest: str
    counts_by_status: dict[str, int]
    unmatched_execution_refs: tuple[str, ...] = ()
    falsification_candidates: tuple[RuntimeFalsificationCandidate, ...] = ()
    automatic_promotion: bool = False
    content_digest: str

    @model_validator(mode="after")
    def validate_authority_boundary(self) -> "RuntimeReconciliationReport":
        if self.automatic_promotion:
            raise ValueError("Runtime reconciliation cannot automatically promote contradictions.")
        return self


class RuntimeReconciliationService:
    """Reconcile a plan batch against supplied execution records.

    Live execution remains a separate adapter concern. This service is the
    production comparison boundary for scripted, imported, watcher, IFCID, or
    live-sandbox execution records.
    """

    def reconcile(
        self,
        *,
        plan_batch: RuntimeVerificationPlanBatch,
        execution_records: Iterable[RuntimeExecutionRecord],
    ) -> tuple[RuntimeVerificationBatch, RuntimeReconciliationReport]:
        if canonical_digest(plan_batch.model_dump(exclude={"content_digest"})) != plan_batch.content_digest:
            raise RuntimeReconciliationError("Runtime plan batch digest is invalid.")
        plans = {item.plan_id: item for item in plan_batch.plans}
        pairs = []
        unmatched: list[str] = []
        for execution in execution_records:
            plan = plans.get(execution.plan_ref)
            if plan is None:
                unmatched.append(execution.execution_id)
                continue
            pairs.append((plan, execution))
        batch = RuntimeVerifier().verify_batch(
            plan_batch_digest=plan_batch.content_digest,
            pairs=tuple(pairs),
        )
        counts = Counter(item.verification_status.value for item in batch.verification_results)
        candidates = []
        for result in batch.verification_results:
            if result.verification_status is not RuntimeVerificationStatus.MISMATCH:
                continue
            payload = {
                "candidate_id": "falsification-candidate-" + hashlib.sha256(result.content_digest.encode()).hexdigest()[:20],
                "classification": "STATIC_RUNTIME_CONTRADICTION_CANDIDATE",
                "verification_result_ref": result.verification_result_id,
                "verification_result_digest": result.content_digest,
                "scenario_spec_ref": result.scenario_spec_ref,
                "finding_refs": tuple(item.finding_id for item in result.findings),
                "authority_scope": "RUNTIME_EVIDENCE_ONLY",
                "promotion_status": "HUMAN_GOVERNANCE_REQUIRED",
            }
            candidates.append(RuntimeFalsificationCandidate(**payload, content_digest=canonical_digest(payload)))
        without = {
            "schema_version": "runtime-reconciliation-report-1.0",
            "plan_batch_digest": plan_batch.content_digest,
            "verification_batch_digest": batch.content_digest,
            "counts_by_status": dict(sorted(counts.items())),
            "unmatched_execution_refs": tuple(sorted(unmatched)),
            "falsification_candidates": tuple(candidates),
            "automatic_promotion": False,
        }
        return batch, RuntimeReconciliationReport(**without, content_digest=canonical_digest(without))

    def load_plan_batch(self, path: Path) -> RuntimeVerificationPlanBatch:
        return RuntimeVerificationPlanBatch.model_validate_json(path.read_text(encoding="utf-8"))

    def load_execution_records(self, paths: Iterable[Path]) -> tuple[RuntimeExecutionRecord, ...]:
        records: list[RuntimeExecutionRecord] = []
        for path in paths:
            payload: Any = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, dict) and "execution_records" in payload:
                records.extend(RuntimeExecutionRecord.model_validate(item) for item in payload["execution_records"])
            else:
                records.append(RuntimeExecutionRecord.model_validate(payload))
        return tuple(records)
