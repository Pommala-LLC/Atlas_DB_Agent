from __future__ import annotations

import hashlib
from collections.abc import Iterable

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.parsing.models import ParseOutcome, ProcedureAst, ProcedureParseResult
from ojas_reconciler.db2_behavior.bdd.scenario_models import (
    ClassificationAuthorityStatus,
    ClassificationObservation,
    EffectClosureArtifact,
    EffectClosureCompleteness,
    ResolutionStatus,
    ResolutionVectorArtifact,
    ScenarioAction,
    ScenarioBlockerCode,
    ScenarioCompilationStatus,
    ScenarioCompilerBudgetReport,
    ScenarioEffect,
    ScenarioPrecondition,
    ScenarioSpec,
    ScenarioSpecBatchResult,
    ScenarioSpecCompilationResult,
)
from ojas_reconciler.db2_behavior.analysis.models import (
    BehaviorEffectBundle,
    BehaviorSlice,
    ConstraintAssessment,
    ConstraintAssessmentStatus,
    EffectCandidate,
    EffectKind,
    EffectModality,
    EffectObservability,
    EffectObligation,
    Phase1SemanticResult,
    SemanticFindingCode,
    PredicateGraph,
    DynamicIdentifierResolutionStatus,
    DynamicObjectVerificationStatus,
    DynamicSqlStatementKind,
)


class ScenarioSpecCompiler:
    """Compiles eligible technical behavior facts into immutable ScenarioSpec 1.1 artifacts."""

    VERSION = "scenario-compiler-1.5"
    CONFIGURATION = {
        "max_preconditions": 64,
        "max_effects": 32,
        "max_evidence_refs": 512,
        "allow_may_effects": True,
    }

    def compile_all(
        self,
        parse_result: ProcedureParseResult,
        semantic_result: Phase1SemanticResult,
    ) -> ScenarioSpecBatchResult:
        if parse_result.ast is None:
            raise ValueError("ScenarioSpec compilation requires a parsed procedure AST.")

        ast = parse_result.ast
        procedure_identity_ref, source_symbol_id, symbol_lineage_id = self._identity_refs(
            parse_result,
            ast,
        )
        compiler_configuration_digest = canonical_digest(self.CONFIGURATION)

        effects = {value.effect_id: value for value in semantic_result.effects}
        slices = {value.bundle_ref: value for value in semantic_result.behavior_slices}
        predicates = {value.predicate_graph_id: value for value in semantic_result.predicate_graphs}
        constraints = {value.assessment_id: value for value in semantic_result.constraint_assessments}
        reductions_by_region = {value.controlling_region_ref: value for value in semantic_result.ordered_decision_reductions}
        obligations_by_bundle = self._obligations_by_bundle(semantic_result.effect_obligations)
        finding_refs_by_bundle = self._finding_refs_by_bundle(semantic_result)

        observations: list[ClassificationObservation] = []
        closures: list[EffectClosureArtifact] = []
        resolutions: list[ResolutionVectorArtifact] = []
        budgets: list[ScenarioCompilerBudgetReport] = []
        specs: list[ScenarioSpec] = []
        results: list[ScenarioSpecCompilationResult] = []

        for bundle in sorted(semantic_result.behavior_bundles, key=lambda value: value.bundle_id):
            behavior_slice = slices.get(bundle.bundle_id)
            bundle_obligations = obligations_by_bundle.get(bundle.bundle_id, ())
            blockers = self._blockers(
                parse_result=parse_result,
                bundle=bundle,
                behavior_slice=behavior_slice,
                obligations=bundle_obligations,
                effects=effects,
                predicates=predicates,
                constraints=constraints,
                semantic_result=semantic_result,
            )

            budget = self._budget_report(bundle, behavior_slice, bundle_obligations)
            budgets.append(budget)
            if budget.exceeded_limits:
                blockers.add(ScenarioBlockerCode.COMPILATION_BUDGET_EXCEEDED)

            finding_refs = finding_refs_by_bundle.get(bundle.bundle_id, ())
            input_digests = (
                canonical_digest(parse_result),
                semantic_result.content_digest,
                canonical_digest(bundle),
                canonical_digest(behavior_slice) if behavior_slice is not None else "sha256:missing-slice",
                compiler_configuration_digest,
            )
            blocker_details = tuple(
                influence.detail
                for influence in (
                    behavior_slice.unresolved_influences if behavior_slice is not None else ()
                )
            )

            if blockers:
                results.append(
                    ScenarioSpecCompilationResult(
                        compilation_status=ScenarioCompilationStatus.BLOCKED,
                        behavior_effect_bundle_ref=bundle.bundle_id,
                        behavior_slice_ref=behavior_slice.slice_id if behavior_slice is not None else None,
                        blockers=tuple(sorted(blockers, key=lambda value: value.value)),
                        finding_refs=finding_refs,
                        blocker_details=blocker_details,
                        input_digest_set=input_digests,
                        compiler_configuration_digest=compiler_configuration_digest,
                    )
                )
                continue

            assert behavior_slice is not None
            predicate = predicates.get(behavior_slice.predicate_graph_ref or "")
            classification, preconditions, classification_slots = self._preconditions(
                bundle=bundle,
                behavior_slice=behavior_slice,
                predicate=predicate,
                constraints=constraints,
                reduction=reductions_by_region.get(bundle.controlling_region_ref),
                caller_transaction_contract_ref=semantic_result.caller_transaction_contract_ref,
            )
            observations.extend(classification)

            expected_effects, alternatives = self._scenario_effects(
                bundle_obligations, effects, semantic_result.caller_transaction_contract_ref
            )
            closure = self._effect_closure(bundle, effects)
            resolution = self._resolution_vector(bundle, behavior_slice, effects, semantic_result)
            closures.append(closure)
            resolutions.append(resolution)

            behavior_id = self._behavior_id(
                symbol_lineage_id=symbol_lineage_id,
                bundle=bundle,
                effects=effects,
                predicate=predicate,
            )
            scenario_spec_id = self._stable_id(
                "scenario-spec",
                behavior_id,
                parse_result.artifact_revision_id,
                bundle.bundle_id,
            )
            invocation_contract_ref = self._stable_id(
                "invocation-contract",
                procedure_identity_ref,
            )
            vocabulary_slots = self._vocabulary_slots(
                scenario_spec_id=scenario_spec_id,
                preconditions=preconditions,
                expected_effects=expected_effects,
                alternatives=alternatives,
            )
            evidence_refs = tuple(
                sorted(
                    set(bundle.evidence_refs)
                    | set(behavior_slice.evidence_refs)
                    | {effect.source_node_ref for effect in self._bundle_effects(bundle, effects)}
                )
            )

            spec_without_digest = {
                "scenario_spec_id": scenario_spec_id,
                "schema_version": "1.1",
                "behavior_id": behavior_id,
                "source_symbol_id": source_symbol_id,
                "symbol_lineage_id": symbol_lineage_id,
                "procedure_identity_ref": procedure_identity_ref,
                "artifact_revision_id": parse_result.artifact_revision_id,
                "behavior_effect_bundle_ref": bundle.bundle_id,
                "behavior_slice_ref": behavior_slice.slice_id,
                "predicate_graph_ref": behavior_slice.predicate_graph_ref,
                "action": ScenarioAction(
                    action_kind=bundle.action_scope.value,
                    procedure_identity_ref=procedure_identity_ref,
                    invocation_contract_ref=invocation_contract_ref,
                    action_scope_ref=bundle.action_scope_ref,
                    evidence_refs=(ast.node_id,),
                ),
                "preconditions": preconditions,
                "expected_effects": expected_effects,
                "alternative_or_conditional_effects": alternatives,
                "effect_closure_ref": closure.effect_closure_id,
                "resolution_vector_ref": resolution.resolution_vector_id,
                "summary_refs": self._summary_refs(bundle, semantic_result),
                "ordered_decision_reduction_refs": (
                    (reductions_by_region[bundle.controlling_region_ref].reduction_id,)
                    if bundle.controlling_region_ref in reductions_by_region else ()
                ),
                "caller_transaction_contract_refs": (
                    (semantic_result.caller_transaction_contract_ref,)
                    if semantic_result.caller_transaction_contract_ref is not None else ()
                ),
                "analysis_budget_report_ref": budget.budget_report_id,
                "finding_refs": finding_refs,
                "evidence_refs": evidence_refs,
                "required_classification_slots": classification_slots,
                "required_vocabulary_slots": vocabulary_slots,
                "platform_governance_ref": None,
                "created_by_compiler_version": self.VERSION,
            }
            spec = ScenarioSpec(
                **spec_without_digest,
                content_digest=canonical_digest(spec_without_digest),
            )
            specs.append(spec)
            results.append(
                ScenarioSpecCompilationResult(
                    compilation_status=ScenarioCompilationStatus.SUCCEEDED,
                    behavior_effect_bundle_ref=bundle.bundle_id,
                    behavior_slice_ref=behavior_slice.slice_id,
                    scenario_spec_ref=spec.scenario_spec_id,
                    finding_refs=finding_refs,
                    blocker_details=(),
                    input_digest_set=input_digests,
                    compiler_configuration_digest=compiler_configuration_digest,
                    output_digest=spec.content_digest,
                )
            )

        batch_without_digest = {
            "schema_version": "scenario-spec-batch-0.1",
            "parser_result_digest": canonical_digest(parse_result),
            "semantic_result_digest": semantic_result.content_digest,
            "procedure_identity_ref": procedure_identity_ref,
            "source_symbol_id": source_symbol_id,
            "symbol_lineage_id": symbol_lineage_id,
            "classification_observations": tuple(
                sorted(observations, key=lambda value: value.classification_observation_id)
            ),
            "effect_closures": tuple(sorted(closures, key=lambda value: value.effect_closure_id)),
            "resolution_vectors": tuple(
                sorted(resolutions, key=lambda value: value.resolution_vector_id)
            ),
            "budget_reports": tuple(sorted(budgets, key=lambda value: value.budget_report_id)),
            "scenario_specs": tuple(sorted(specs, key=lambda value: value.scenario_spec_id)),
            "compilation_results": tuple(
                sorted(results, key=lambda value: value.behavior_effect_bundle_ref)
            ),
        }
        return ScenarioSpecBatchResult(
            **batch_without_digest,
            content_digest=canonical_digest(batch_without_digest),
        )

    def _blockers(
        self,
        *,
        parse_result: ProcedureParseResult,
        bundle: BehaviorEffectBundle,
        behavior_slice: BehaviorSlice | None,
        obligations: tuple[EffectObligation, ...],
        effects: dict[str, EffectCandidate],
        predicates: dict[str, PredicateGraph],
        constraints: dict[str, ConstraintAssessment],
        semantic_result: Phase1SemanticResult,
    ) -> set[ScenarioBlockerCode]:
        blockers: set[ScenarioBlockerCode] = set()
        semantic_payload = semantic_result.model_dump(mode="python", exclude={"content_digest"})
        if canonical_digest(semantic_payload) != semantic_result.content_digest:
            blockers.add(ScenarioBlockerCode.SEMANTIC_RESULT_DIGEST_INVALID)
        if parse_result.outcome != ParseOutcome.PARSES_COMPLETE:
            blockers.add(ScenarioBlockerCode.PARSER_RESULT_INCOMPLETE)
        if bundle.bundle_completeness != "COMPLETE":
            blockers.add(ScenarioBlockerCode.BEHAVIOR_BUNDLE_PARTIAL)
        if behavior_slice is None or behavior_slice.analysis_completeness != "COMPLETE":
            blockers.add(ScenarioBlockerCode.BEHAVIOR_SLICE_PARTIAL)
        if behavior_slice is not None and any(
            influence.code == SemanticFindingCode.ORDERED_DECISION_NEGATED_ARM_DEPENDENCY_PARTIAL.value
            for influence in behavior_slice.unresolved_influences
        ):
            blockers.add(ScenarioBlockerCode.ORDERED_DECISION_NEGATED_ARM_DEPENDENCY_PARTIAL)
        if behavior_slice is not None and any(
            influence.code == SemanticFindingCode.UNDECLARED_SYMBOL_REFERENCE.value
            for influence in behavior_slice.unresolved_influences
        ):
            blockers.add(ScenarioBlockerCode.UNDECLARED_SYMBOL_REFERENCE)
        if behavior_slice is not None and behavior_slice.predicate_graph_ref is not None:
            predicate = predicates.get(behavior_slice.predicate_graph_ref)
            if predicate is None or predicate.normalization_status != "COMPLETE":
                blockers.add(ScenarioBlockerCode.PREDICATE_NORMALIZATION_PARTIAL)
        if behavior_slice is not None:
            for assessment_ref in behavior_slice.constraint_assessment_refs:
                assessment = constraints.get(assessment_ref)
                if assessment is not None and assessment.status == ConstraintAssessmentStatus.OBVIOUS_CONTRADICTION:
                    blockers.add(ScenarioBlockerCode.OBVIOUS_PREDICATE_CONTRADICTION)
        if not obligations:
            blockers.add(ScenarioBlockerCode.MISSING_PRIMARY_EFFECT_OBLIGATION)
        if any(value.modality == EffectModality.UNKNOWN for value in obligations):
            blockers.add(ScenarioBlockerCode.UNKNOWN_EFFECT_MODALITY)
        primary_effect_refs = {
            member.effect_ref for member in bundle.effect_members if member.relationship.value == "PRIMARY"
        }
        if not any(value.effect_ref in primary_effect_refs for value in obligations):
            blockers.add(ScenarioBlockerCode.MISSING_PRIMARY_EFFECT_OBLIGATION)
        for obligation in obligations:
            effect = effects[obligation.effect_ref]
            if effect.observability in {
                EffectObservability.UNRESOLVED_EFFECT_BOUNDARY,
                EffectObservability.TRANSACTION_SURVIVAL_UNRESOLVED,
            }:
                blockers.add(ScenarioBlockerCode.UNRESOLVED_EFFECT_OBSERVABILITY)
            if effect.effect_kind in {EffectKind.DML, EffectKind.DYNAMIC_SQL} and (
                effect.observability == EffectObservability.TRANSACTION_SURVIVAL_UNRESOLVED
                and effect.transaction_analysis_ref is None
            ):
                blockers.add(ScenarioBlockerCode.TRANSACTION_SURVIVAL_UNRESOLVED)
        if not parse_result.artifact_revision_id or not parse_result.source_digest:
            blockers.add(ScenarioBlockerCode.EVIDENCE_BINDING_INCOMPLETE)
        return blockers

    def _preconditions(
        self,
        *,
        bundle: BehaviorEffectBundle,
        behavior_slice: BehaviorSlice,
        predicate: PredicateGraph | None,
        constraints: dict[str, ConstraintAssessment],
        reduction: object | None,
        caller_transaction_contract_ref: str | None,
    ) -> tuple[
        tuple[ClassificationObservation, ...],
        tuple[ScenarioPrecondition, ...],
        tuple[str, ...],
    ]:
        observations: list[ClassificationObservation] = []
        preconditions: list[ScenarioPrecondition] = []
        slots: list[str] = []
        if predicate is not None:
            assessment_ref = behavior_slice.constraint_assessment_refs[0] if behavior_slice.constraint_assessment_refs else None
            observation_id = self._stable_id(
                "classification-observation", predicate.predicate_graph_id, "unclassified"
            )
            observations.append(ClassificationObservation(
                classification_observation_id=observation_id,
                candidate="UNCLASSIFIED_TECHNICAL_PREDICATE",
                method="NO_CLASSIFIER_EXECUTED",
                method_version="classification-observation-0.1",
                classification_evidence_refs=predicate.source_node_refs,
                authority_status=ClassificationAuthorityStatus.UNAPPROVED,
            ))
            precondition_id = self._stable_id("precondition", bundle.bundle_id, predicate.predicate_graph_id)
            preconditions.append(ScenarioPrecondition(
                precondition_id=precondition_id,
                technical_fact_ref=predicate.predicate_graph_id,
                constraint_assessment_ref=assessment_ref,
                classification_observation_ref=observation_id,
                evidence_refs=predicate.source_node_refs,
            ))
            slots.append(precondition_id)
        if reduction is not None:
            reduction_id = str(getattr(reduction, "reduction_id"))
            evidence_refs = tuple(getattr(reduction, "evidence_refs"))
            observation_id = self._stable_id("classification-observation", reduction_id, "ordered-decision")
            observations.append(ClassificationObservation(
                classification_observation_id=observation_id,
                candidate="ORDERED_DECISION_PRECEDENCE",
                method="DETERMINISTIC_ORDERED_DECISION_REDUCTION",
                method_version="ordered-decision-reducer-1.0",
                classification_evidence_refs=evidence_refs,
                authority_status=ClassificationAuthorityStatus.UNAPPROVED,
            ))
            precondition_id = self._stable_id("precondition", bundle.bundle_id, reduction_id)
            preconditions.append(ScenarioPrecondition(
                precondition_id=precondition_id,
                technical_fact_ref=reduction_id,
                classification_observation_ref=observation_id,
                evidence_refs=evidence_refs,
            ))
            slots.append(precondition_id)
        if caller_transaction_contract_ref is not None:
            observation_id = self._stable_id("classification-observation", caller_transaction_contract_ref, "caller-contract")
            observations.append(ClassificationObservation(
                classification_observation_id=observation_id,
                candidate="CALLER_TRANSACTION_CONTRACT",
                method="AUTHORITY_BOUND_INPUT_FACT",
                method_version="caller-transaction-contract-1.0",
                classification_evidence_refs=(caller_transaction_contract_ref,),
                authority_ref=caller_transaction_contract_ref,
                authority_status=ClassificationAuthorityStatus.APPROVED,
            ))
            precondition_id = self._stable_id("precondition", bundle.bundle_id, caller_transaction_contract_ref)
            preconditions.append(ScenarioPrecondition(
                precondition_id=precondition_id,
                technical_fact_ref=caller_transaction_contract_ref,
                classification_observation_ref=observation_id,
                evidence_refs=(caller_transaction_contract_ref,),
            ))
            slots.append(precondition_id)
        return tuple(observations), tuple(preconditions), tuple(slots)

    @staticmethod
    def _scenario_effects(
        obligations: tuple[EffectObligation, ...],
        effects: dict[str, EffectCandidate],
        caller_transaction_contract_ref: str | None,
    ) -> tuple[tuple[ScenarioEffect, ...], tuple[ScenarioEffect, ...]]:
        expected: list[ScenarioEffect] = []
        alternatives: list[ScenarioEffect] = []
        for value in sorted(obligations, key=lambda item: item.obligation_id):
            effect = effects[value.effect_ref]
            scenario_effect = ScenarioEffect(
                effect_ref=value.effect_ref,
                modality=value.modality,
                evidence_refs=effect.evidence_refs or (effect.source_node_ref,),
                caller_transaction_contract_ref=(
                    caller_transaction_contract_ref
                    if value.modality == EffectModality.MUST_IF_CALLER_CONTRACT_HOLDS
                    else None
                ),
            )
            if value.modality in {
                EffectModality.MUST,
                EffectModality.MUST_NOT,
                EffectModality.MUST_IF_CALLER_CONTRACT_HOLDS,
            }:
                expected.append(scenario_effect)
            else:
                alternatives.append(scenario_effect)
        return tuple(expected), tuple(alternatives)

    def _effect_closure(
        self,
        bundle: BehaviorEffectBundle,
        effects: dict[str, EffectCandidate],
    ) -> EffectClosureArtifact:
        included = tuple(sorted(member.effect_ref for member in bundle.effect_members))
        unresolved = tuple(
            sorted(
                effect.effect_id
                for effect in self._bundle_effects(bundle, effects)
                if effect.observability in {
                    EffectObservability.UNRESOLVED_EFFECT_BOUNDARY,
                    EffectObservability.TRANSACTION_SURVIVAL_UNRESOLVED,
                }
            )
        )
        completeness = (
            EffectClosureCompleteness.CLOSED_WITHIN_SCOPE
            if not unresolved
            else EffectClosureCompleteness.PARTIAL_TRANSITIVE_CLOSURE
        )
        closure_id = self._stable_id("effect-closure", bundle.bundle_id, *included)
        without_digest = {
            "effect_closure_id": closure_id,
            "scope": "ANALYZED_DEPENDENCIES",
            "completeness": completeness,
            "included_effect_refs": included,
            "unresolved_effect_refs": unresolved,
            "evidence_refs": bundle.evidence_refs,
        }
        return EffectClosureArtifact(
            **without_digest,
            content_digest=canonical_digest(without_digest),
        )

    def _resolution_vector(
        self,
        bundle: BehaviorEffectBundle,
        behavior_slice: BehaviorSlice,
        effects: dict[str, EffectCandidate],
        semantic_result: Phase1SemanticResult,
    ) -> ResolutionVectorArtifact:
        bundle_effects = self._bundle_effects(bundle, effects)
        dynamic_effects = [value for value in bundle_effects if value.effect_kind == EffectKind.DYNAMIC_SQL]
        dynamic_site_by_node = {site.execute_node_ref: site for site in semantic_result.dynamic_sql_sites}
        dynamic_call_sites = [
            dynamic_site_by_node[value.source_node_ref]
            for value in dynamic_effects
            if value.source_node_ref in dynamic_site_by_node
            and DynamicSqlStatementKind.CALL in dynamic_site_by_node[value.source_node_ref].statement_kinds
        ]
        has_call = any(value.effect_kind == EffectKind.CALL for value in bundle_effects) or bool(dynamic_call_sites)
        has_dynamic = bool(dynamic_effects)
        has_dml = any(value.effect_kind == EffectKind.DML for value in bundle_effects) or any(
            value.target is not None for value in dynamic_effects
        )
        dynamic_statuses = [
            dynamic_site_by_node[value.source_node_ref].relation_resolution_status
            for value in dynamic_effects
            if value.source_node_ref in dynamic_site_by_node
        ]
        if not has_dynamic:
            dynamic_resolution = ResolutionStatus.NOT_APPLICABLE
        elif dynamic_statuses and all(
            status in {
                DynamicIdentifierResolutionStatus.RESOLVED_LITERAL,
                DynamicIdentifierResolutionStatus.RESOLVED_ENUMERATED,
                DynamicIdentifierResolutionStatus.NOT_APPLICABLE,
            }
            for status in dynamic_statuses
        ):
            dynamic_resolution = ResolutionStatus.RESOLVED_SOURCE_ONLY
        else:
            dynamic_resolution = ResolutionStatus.UNRESOLVED
        dynamic_call_records = [
            record
            for record in semantic_result.dynamic_call_resolutions
            if any(record.site_ref == site.site_id for site in dynamic_call_sites)
        ]
        if any(value.effect_kind == EffectKind.CALL for value in bundle_effects):
            routine_resolution = ResolutionStatus.UNRESOLVED
        elif not dynamic_call_sites:
            routine_resolution = ResolutionStatus.NOT_APPLICABLE
        elif any(
            site.call_resolution_status == DynamicIdentifierResolutionStatus.UNRESOLVED_DYNAMIC_IDENTIFIER
            for site in dynamic_call_sites
        ):
            routine_resolution = ResolutionStatus.UNRESOLVED
        elif dynamic_call_records and all(
            record.verification_status in {
                DynamicObjectVerificationStatus.VERIFIED_CATALOG,
                DynamicObjectVerificationStatus.VERIFIED_SOURCE,
            }
            for record in dynamic_call_records
        ):
            routine_resolution = ResolutionStatus.RESOLVED
        else:
            routine_resolution = ResolutionStatus.RESOLVED_SOURCE_ONLY
        resolution_id = self._stable_id("resolution-vector", bundle.bundle_id)
        without_digest = {
            "resolution_vector_id": resolution_id,
            "routine_resolution": routine_resolution,
            "view_resolution": (
                ResolutionStatus.RESOLVED_SOURCE_ONLY
                if behavior_slice.query_summary_refs
                else ResolutionStatus.NOT_APPLICABLE
            ),
            "udf_resolution": ResolutionStatus.NOT_APPLICABLE,
            "trigger_resolution": ResolutionStatus.NOT_ASSESSED if has_dml else ResolutionStatus.NOT_APPLICABLE,
            "constraint_resolution": ResolutionStatus.NOT_ASSESSED if has_dml else ResolutionStatus.NOT_APPLICABLE,
            "dynamic_relation_resolution": dynamic_resolution,
            "evidence_refs": bundle.evidence_refs,
        }
        return ResolutionVectorArtifact(
            **without_digest,
            content_digest=canonical_digest(without_digest),
        )

    def _budget_report(
        self,
        bundle: BehaviorEffectBundle,
        behavior_slice: BehaviorSlice | None,
        obligations: tuple[EffectObligation, ...],
    ) -> ScenarioCompilerBudgetReport:
        preconditions = 1 if behavior_slice is not None and behavior_slice.predicate_graph_ref is not None else 0
        evidence_count = len(set(bundle.evidence_refs) | set(behavior_slice.evidence_refs if behavior_slice else ()))
        consumed = {
            "preconditions": preconditions,
            "effects": len(obligations),
            "evidence_refs": evidence_count,
        }
        limits = {
            "preconditions": int(self.CONFIGURATION["max_preconditions"]),
            "effects": int(self.CONFIGURATION["max_effects"]),
            "evidence_refs": int(self.CONFIGURATION["max_evidence_refs"]),
        }
        exceeded = tuple(sorted(key for key, value in consumed.items() if value > limits[key]))
        report_id = self._stable_id("scenario-budget", bundle.bundle_id)
        without_digest = {
            "budget_report_id": report_id,
            "configured_limits": limits,
            "consumed": consumed,
            "exceeded_limits": exceeded,
            "reporting_integrity": "COMPLETE",
            "analysis_result": "PARTIAL" if exceeded else "COMPLETE",
        }
        return ScenarioCompilerBudgetReport(
            **without_digest,
            content_digest=canonical_digest(without_digest),
        )

    def _identity_refs(
        self,
        parse_result: ProcedureParseResult,
        ast: ProcedureAst,
    ) -> tuple[str, str, str]:
        schema = ast.schema_name or "<UNQUALIFIED>"
        signature = "|".join(f"{value.mode}:{value.type_text.upper()}" for value in ast.parameters)
        source_symbol_id = self._stable_id(
            "source-symbol",
            schema.upper(),
            ast.procedure_name.upper(),
            signature,
        )
        symbol_lineage_id = self._stable_id(
            "symbol-lineage",
            schema.upper(),
            ast.procedure_name.upper(),
        )
        procedure_identity_ref = self._stable_id(
            "procedure-identity",
            source_symbol_id,
            ast.specific_name or "",
            ast.routine_version_id or "",
            parse_result.artifact_revision_id,
        )
        return procedure_identity_ref, source_symbol_id, symbol_lineage_id

    def _behavior_id(
        self,
        *,
        symbol_lineage_id: str,
        bundle: BehaviorEffectBundle,
        effects: dict[str, EffectCandidate],
        predicate: PredicateGraph | None,
    ) -> str:
        signatures = []
        for effect in self._bundle_effects(bundle, effects):
            signatures.append(
                "|".join(
                    [
                        effect.effect_kind.value,
                        effect.target or "",
                        effect.value_expression or "",
                        effect.observability.value,
                    ]
                )
            )
        predicate_digest = canonical_digest(predicate) if predicate is not None else "sha256:no-predicate"
        return self._stable_id(
            "behavior",
            symbol_lineage_id,
            *sorted(signatures),
            predicate_digest,
        )

    @staticmethod
    def _vocabulary_slots(
        *,
        scenario_spec_id: str,
        preconditions: tuple[ScenarioPrecondition, ...],
        expected_effects: tuple[ScenarioEffect, ...],
        alternatives: tuple[ScenarioEffect, ...],
    ) -> tuple[str, ...]:
        slots = [f"{scenario_spec_id}:ACTION", f"{scenario_spec_id}:SCENARIO_NAME"]
        slots.extend(f"{scenario_spec_id}:PRECONDITION:{value.precondition_id}" for value in preconditions)
        slots.extend(f"{scenario_spec_id}:EFFECT:{value.effect_ref}" for value in expected_effects)
        return tuple(sorted(slots))

    @staticmethod
    def _summary_refs(
        bundle: BehaviorEffectBundle,
        semantic_result: Phase1SemanticResult,
    ) -> tuple[str, ...]:
        effect_refs = {member.effect_ref for member in bundle.effect_members}
        source_refs = {
            effect.source_node_ref
            for effect in semantic_result.effects
            if effect.effect_id in effect_refs
        }
        result = []
        for summary in semantic_result.loop_summaries:
            if set(summary.evidence_refs) & source_refs:
                result.append(summary.loop_summary_id)
        return tuple(sorted(result))

    @staticmethod
    def _obligations_by_bundle(
        obligations: tuple[EffectObligation, ...],
    ) -> dict[str, tuple[EffectObligation, ...]]:
        result: dict[str, list[EffectObligation]] = {}
        for value in obligations:
            result.setdefault(value.bundle_ref, []).append(value)
        return {
            key: tuple(sorted(values, key=lambda value: value.obligation_id))
            for key, values in result.items()
        }

    @staticmethod
    def _finding_refs_by_bundle(
        semantic_result: Phase1SemanticResult,
    ) -> dict[str, tuple[str, ...]]:
        slices = {value.bundle_ref: value for value in semantic_result.behavior_slices}
        result: dict[str, tuple[str, ...]] = {}
        for bundle in semantic_result.behavior_bundles:
            evidence = set(bundle.evidence_refs)
            behavior_slice = slices.get(bundle.bundle_id)
            if behavior_slice is not None:
                evidence.update(behavior_slice.evidence_refs)
            refs = [
                finding.finding_id
                for finding in semantic_result.findings
                if set(finding.evidence_node_refs) & evidence
            ]
            result[bundle.bundle_id] = tuple(sorted(refs))
        return result

    @staticmethod
    def _bundle_effects(
        bundle: BehaviorEffectBundle,
        effects: dict[str, EffectCandidate],
    ) -> tuple[EffectCandidate, ...]:
        return tuple(effects[member.effect_ref] for member in bundle.effect_members)

    @staticmethod
    def _stable_id(prefix: str, *parts: str) -> str:
        payload = "|".join((prefix, *parts)).encode("utf-8")
        return f"{prefix}-" + hashlib.sha256(payload).hexdigest()[:20]
