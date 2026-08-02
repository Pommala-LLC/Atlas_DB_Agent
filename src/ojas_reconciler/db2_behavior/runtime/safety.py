from __future__ import annotations

import hashlib

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.parsing.models import ParseOutcome, ProcedureParseResult
from ojas_reconciler.db2_behavior.runtime.models import (
    LiveVerificationEligibility,
    RollbackContainment,
    RuntimeSafetyAssessment,
    TransactionOwnership,
)
from ojas_reconciler.db2_behavior.analysis.models import (
    DynamicSqlResolutionStatus,
    EffectKind,
    EffectObservability,
    Phase1SemanticResult,
)


class RuntimeSafetyAssessor:
    VERSION = "runtime-safety-1.0"

    def assess(
        self,
        parse_result: ProcedureParseResult,
        semantic_result: Phase1SemanticResult,
        procedure_identity_ref: str,
    ) -> RuntimeSafetyAssessment:
        if parse_result.ast is None:
            raise ValueError("Runtime safety assessment requires a procedure AST.")
        ast = parse_result.ast
        internal_commit_refs = tuple(
            sorted(value.source_node_ref for value in semantic_result.effects if value.effect_kind == EffectKind.COMMIT)
        )
        rollback_refs = tuple(
            sorted(value.source_node_ref for value in semantic_result.effects if value.effect_kind == EffectKind.ROLLBACK)
        )
        unresolved_calls = tuple(
            sorted(
                value.effect_id
                for value in semantic_result.effects
                if value.effect_kind == EffectKind.CALL
                and value.observability == EffectObservability.UNRESOLVED_EFFECT_BOUNDARY
            )
        )
        unresolved_dynamic = tuple(
            sorted(
                value.site_id
                for value in semantic_result.dynamic_sql_sites
                if value.resolution_status
                in {
                    DynamicSqlResolutionStatus.PARTIALLY_RECONSTRUCTED,
                    DynamicSqlResolutionStatus.RUNTIME_CAPTURE_REQUIRED,
                    DynamicSqlResolutionStatus.UNRESOLVED_DYNAMIC_SQL,
                    DynamicSqlResolutionStatus.DYNAMIC_VARIANT_BUDGET_EXCEEDED,
                }
            )
        )
        commit_on_return = (ast.commit_on_return or "UNKNOWN").upper()
        if commit_on_return not in {"YES", "NO"}:
            commit_on_return = "UNKNOWN"

        reasons: list[str] = []
        if parse_result.outcome != ParseOutcome.PARSES_COMPLETE:
            reasons.append("PARSER_RESULT_INCOMPLETE")
        if internal_commit_refs:
            reasons.append("INTERNAL_COMMIT_PRESENT")
        if commit_on_return == "YES":
            reasons.append("COMMIT_ON_RETURN_PRESENT")
        if unresolved_calls:
            reasons.append("UNRESOLVED_CALL_BOUNDARY")
        if unresolved_dynamic:
            reasons.append("UNRESOLVED_DYNAMIC_SQL_BOUNDARY")

        if internal_commit_refs or commit_on_return == "YES":
            eligibility = LiveVerificationEligibility.PROHIBITED
        elif parse_result.outcome != ParseOutcome.PARSES_COMPLETE:
            eligibility = LiveVerificationEligibility.PROHIBITED
        elif unresolved_calls or unresolved_dynamic:
            eligibility = LiveVerificationEligibility.MANUAL_APPROVAL_REQUIRED
        else:
            eligibility = LiveVerificationEligibility.DB2_SANDBOX_ALLOWED

        if internal_commit_refs and rollback_refs:
            ownership = TransactionOwnership.MIXED
        elif internal_commit_refs or commit_on_return == "YES":
            ownership = TransactionOwnership.PROCEDURE_CONTROLLED
        elif commit_on_return == "NO" and not unresolved_calls and not unresolved_dynamic:
            # The live adapter owns the connection and disables autocommit. When the
            # procedure cannot commit internally and no unresolved boundary may escape,
            # the executor owns the unit of work.
            ownership = TransactionOwnership.EXECUTOR_OWNED
        elif commit_on_return == "NO":
            ownership = TransactionOwnership.CALLER_CONTROLLED
        else:
            ownership = TransactionOwnership.UNKNOWN

        if internal_commit_refs or commit_on_return == "YES":
            containment = RollbackContainment.NOT_GUARANTEED
        elif unresolved_calls or unresolved_dynamic:
            containment = RollbackContainment.UNKNOWN
        elif ownership == TransactionOwnership.EXECUTOR_OWNED:
            containment = RollbackContainment.ROLLBACK_SAFE
        else:
            containment = RollbackContainment.CALLER_ROLLBACK_POSSIBLE

        external_status = "POSSIBLE" if unresolved_calls or unresolved_dynamic else "ABSENT"
        evidence_refs = tuple(sorted(set((*internal_commit_refs, *rollback_refs, *unresolved_calls, *unresolved_dynamic))))
        payload = {
            "procedure_identity_ref": procedure_identity_ref,
            "internal_commit_present": bool(internal_commit_refs),
            "explicit_rollback_present": bool(rollback_refs),
            "commit_on_return": commit_on_return,
            "unresolved_call_boundaries": unresolved_calls,
            "unresolved_dynamic_boundaries": unresolved_dynamic,
            "external_side_effects_status": external_status,
            "transaction_ownership": ownership,
            "rollback_containment": containment,
            "live_eligibility": eligibility,
            "reason_codes": tuple(sorted(reasons)),
            "evidence_refs": evidence_refs,
        }
        assessment_id = "runtime-safety-" + hashlib.sha256(canonical_digest(payload).encode("utf-8")).hexdigest()[:20]
        final_payload = {"assessment_id": assessment_id, **payload}
        return RuntimeSafetyAssessment(
            **final_payload,
            content_digest=canonical_digest(final_payload),
        )
