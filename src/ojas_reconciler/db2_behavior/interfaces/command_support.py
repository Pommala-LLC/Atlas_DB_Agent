"""Shared presentation and loading helpers for CLI command groups."""
from __future__ import annotations

import argparse
from pathlib import Path

from ojas_reconciler.db2_behavior.analysis.caller_contract import load_caller_transaction_contract
from ojas_reconciler.db2_behavior.analysis.dynamic_sql import validate_dynamic_resolution_catalog
from ojas_reconciler.db2_behavior.analysis.models import DynamicResolutionCatalog
from ojas_reconciler.db2_behavior.analysis.query_semantics import load_query_semantics_catalog
from ojas_reconciler.db2_behavior.analysis.service import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.analysis.tenant_isolation import load_tenant_isolation_catalog
from ojas_reconciler.db2_behavior.bdd.models import ClassificationSnapshot, VocabularySnapshot


def _print_explanation(result: object) -> None:
    from ojas_reconciler.db2_behavior.parsing.models import ExplainRecord

    assert isinstance(result, ExplainRecord)
    print(f"Result: {result.result}")
    if result.failed_gate:
        print(f"Gate: {result.failed_gate}")
    if result.finding_codes:
        print("Findings:")
        for code in result.finding_codes:
            print(f"  - {code}")
    print(f"Consequence: {result.consequence}")
    if result.withheld_outputs:
        print("Withheld:")
        for output in result.withheld_outputs:
            print(f"  - {output}")
    print(f"Recommended action: {result.recommended_action}")


def _print_bdd_explanations(batch: object) -> None:
    from ojas_reconciler.db2_behavior.bdd.authority_models import BddExplanationBatch

    assert isinstance(batch, BddExplanationBatch)
    for explanation in batch.explanations:
        print(f"ScenarioSpec: {explanation.scenario_spec_ref}")
        print(f"Result: {explanation.result}")
        if explanation.blocker_codes:
            print("Blockers:")
            for blocker in explanation.blocker_codes:
                print(f"  - {blocker.value}")
        if explanation.missing_vocabulary_slots:
            print("Missing vocabulary slots:")
            for slot in explanation.missing_vocabulary_slots:
                print(f"  - {slot}")
        if explanation.missing_classification_observation_refs:
            print("Missing classification approvals:")
            for ref in explanation.missing_classification_observation_refs:
                print(f"  - {ref}")
        print(f"Consequence: {explanation.consequence}")
        print("Recommended actions:")
        for action in explanation.recommended_actions:
            print(f"  - {action}")
        print()


def _print_dynamic_sql_explanation(result: object) -> None:
    from ojas_reconciler.db2_behavior.analysis.models import Phase1SemanticResult

    assert isinstance(result, Phase1SemanticResult)
    variants = {value.variant_id: value for value in result.dynamic_sql_variants}
    relation_by_site: dict[str, list[object]] = {}
    for value in result.dynamic_relation_resolutions:
        relation_by_site.setdefault(value.site_ref, []).append(value)
    call_by_site: dict[str, list[object]] = {}
    for value in result.dynamic_call_resolutions:
        call_by_site.setdefault(value.site_ref, []).append(value)
    for site in result.dynamic_sql_sites:
        print(f"Dynamic site: {site.site_id}")
        print(f"  Execute node: {site.execute_node_ref}")
        print(f"  Status: {site.resolution_status.value}")
        print(f"  Statement kinds: {', '.join(value.value for value in site.statement_kinds) or 'UNKNOWN'}")
        for ref in site.variant_refs:
            variant = variants.get(ref)
            if variant is None:
                continue
            print(f"  Variant: {variant.template_text}")
            if variant.placeholder_names:
                print(f"    Runtime placeholders: {', '.join(variant.placeholder_names)}")
        for relation in relation_by_site.get(site.site_id, []):
            print(
                f"  Relation: {getattr(relation, 'relation_name')} "
                f"[{getattr(relation, 'role')}] "
                f"identifier={getattr(relation, 'status').value} "
                f"verification={getattr(relation, 'verification_status').value}"
            )
        for call in call_by_site.get(site.site_id, []):
            print(
                f"  Call: {getattr(call, 'call_target')} "
                f"identifier={getattr(call, 'status').value} "
                f"verification={getattr(call, 'verification_status').value}"
            )
        captures = [value for value in result.runtime_capture_contracts if value.site_ref == site.site_id]
        if captures:
            print("  Runtime capture: CONTRACT_ONLY_DEFERRED")
        print()


def _print_runtime_plans(batch: object) -> None:
    from ojas_reconciler.db2_behavior.runtime.models import RuntimeVerificationPlanBatch

    assert isinstance(batch, RuntimeVerificationPlanBatch)
    safety = batch.safety_assessment
    print(f"Live eligibility: {safety.live_eligibility.value}")
    if safety.reason_codes:
        print("Safety reasons:")
        for reason in safety.reason_codes:
            print(f"  - {reason}")
    for plan in batch.plans:
        print(f"Plan: {plan.plan_id}")
        print(f"  ScenarioSpec: {plan.scenario_spec_ref}")
        print(f"  Status: {plan.plan_status.value}")
        for blocker in plan.blockers:
            print(f"  Blocker: {blocker}")
        for expectation in plan.expected_observations:
            target = f" target={expectation.target}" if expectation.target else ""
            print(
                f"  Expectation: {expectation.modality.value} "
                f"{expectation.observation_kind.value}{target}"
            )


def _print_runtime_verification(batch: object) -> None:
    from ojas_reconciler.db2_behavior.runtime.models import RuntimeVerificationBatch

    assert isinstance(batch, RuntimeVerificationBatch)
    for result in batch.verification_results:
        print(f"ScenarioSpec: {result.scenario_spec_ref}")
        print(f"Result: {result.verification_status.value}")
        print(f"Static/runtime conflict: {result.static_runtime_conflict}")
        for finding in result.findings:
            print(f"  Finding: {finding.code.value} — {finding.message}")


def _load_dynamic_resolution_catalog(path: Path | None) -> DynamicResolutionCatalog | None:
    if path is None:
        return None
    catalog = DynamicResolutionCatalog.model_validate_json(path.read_text(encoding="utf-8"))
    validate_dynamic_resolution_catalog(catalog)
    return catalog


def _semantic_analyzer(args: argparse.Namespace) -> Phase1SemanticAnalyzer:
    return Phase1SemanticAnalyzer(
        _load_dynamic_resolution_catalog(getattr(args, "dynamic_resolution_catalog", None)),
        load_tenant_isolation_catalog(getattr(args, "tenant_isolation_catalog", None)),
        load_query_semantics_catalog(getattr(args, "query_semantics_catalog", None)),
        load_caller_transaction_contract(getattr(args, "caller_transaction_contract", None)),
    )


def _load_snapshots(
    vocabulary_path: Path,
    classification_path: Path,
) -> tuple[VocabularySnapshot, ClassificationSnapshot]:
    vocabulary = VocabularySnapshot.model_validate_json(vocabulary_path.read_text(encoding="utf-8"))
    classification = ClassificationSnapshot.model_validate_json(
        classification_path.read_text(encoding="utf-8")
    )
    return vocabulary, classification
