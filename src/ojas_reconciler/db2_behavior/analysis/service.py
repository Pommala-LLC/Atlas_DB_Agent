from __future__ import annotations

import hashlib

from ojas_reconciler.db2_behavior.analysis.bundles import BehaviorEffectBundleBuilder
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.analysis.cfg import ControlFlowGraphBuilder
from ojas_reconciler.db2_behavior.analysis.effects import DirectEffectAnalyzer
from ojas_reconciler.db2_behavior.analysis.dynamic_sql import DynamicSqlAnalyzer
from ojas_reconciler.db2_behavior.analysis.loop_summaries import LoopSummaryAnalyzer
from ojas_reconciler.db2_behavior.analysis.query_summaries import QuerySourceSummaryBuilder
from ojas_reconciler.db2_behavior.analysis.window_reachability import WindowReachabilityAnalyzer
from ojas_reconciler.db2_behavior.analysis.decision_reduction import OrderedDecisionReducer
from ojas_reconciler.db2_behavior.analysis.predicates import PredicateAnalysisBuilder
from ojas_reconciler.db2_behavior.analysis.modalities import EffectModalityAnalyzer
from ojas_reconciler.db2_behavior.analysis.slicing import LocalBackwardSlicer
from ojas_reconciler.db2_behavior.parsing.models import ProcedureParseResult
from ojas_reconciler.db2_behavior.analysis.models import (
    Phase1SemanticResult,
    SemanticFinding,
    SemanticFindingCode,
    DynamicResolutionCatalog,
    TenantIsolationCatalog,
    QuerySemanticsCatalog,
    CallerTransactionContract,
)
from ojas_reconciler.db2_behavior.analysis.transaction import TransactionSurvivalAnalyzer
from ojas_reconciler.db2_behavior.analysis.tenant_isolation import TenantIsolationAnalyzer
from ojas_reconciler.db2_behavior.analysis.handler_coverage import HandlerCoverageAnalyzer
from ojas_reconciler.db2_behavior.analysis.handler_semantics import HandlerSemanticsAnalyzer
from ojas_reconciler.db2_behavior.analysis.symbol_usage import SymbolUsageAnalyzer
from ojas_reconciler.db2_behavior.analysis.type_safety import AssignmentTypeSafetyAnalyzer
from ojas_reconciler.db2_behavior.analysis.symbol_resolution import ProceduralSymbolValidator
from ojas_reconciler.db2_behavior.analysis.nullability import DefiniteNullabilityAnalyzer
from ojas_reconciler.db2_behavior.analysis.path_semantics import PathStateReconciliationAnalyzer


class Phase1SemanticAnalyzer:
    def __init__(
        self,
        dynamic_resolution_catalog: DynamicResolutionCatalog | None = None,
        tenant_isolation_catalog: TenantIsolationCatalog | None = None,
        query_semantics_catalog: QuerySemanticsCatalog | None = None,
        caller_transaction_contract: CallerTransactionContract | None = None,
    ) -> None:
        self._dynamic_resolution_catalog = dynamic_resolution_catalog
        self._tenant_isolation_catalog = tenant_isolation_catalog
        self._query_semantics_catalog = query_semantics_catalog
        self._caller_transaction_contract = caller_transaction_contract

    def analyze(self, parse_result: ProcedureParseResult) -> Phase1SemanticResult:
        if parse_result.ast is None:
            raise ValueError("A procedural AST is required for Phase 1 semantic analysis.")
        ast = parse_result.ast
        if self._caller_transaction_contract is not None:
            if self._caller_transaction_contract.procedure_name.upper() != ast.procedure_name.upper():
                raise ValueError("Caller transaction contract procedure name does not match the analyzed procedure.")
            if (
                self._caller_transaction_contract.schema_name is not None
                and (ast.schema_name or "").upper() != self._caller_transaction_contract.schema_name.upper()
            ):
                raise ValueError("Caller transaction contract schema does not match the analyzed procedure.")
        cfg = ControlFlowGraphBuilder().build(ast)
        handler_coverage, handler_coverage_findings = HandlerCoverageAnalyzer().analyze(ast, cfg)
        handler_semantics, handler_semantics_findings = HandlerSemanticsAnalyzer().analyze(ast, cfg)
        dynamic_analysis = DynamicSqlAnalyzer(self._dynamic_resolution_catalog).analyze(ast, cfg)
        effects, direct_findings = DirectEffectAnalyzer().analyze(
            ast,
            cfg,
            dynamic_sites=dynamic_analysis.sites,
            dynamic_variants=dynamic_analysis.variants,
        )
        (
            effects,
            transaction_regions,
            transaction_analyses,
            transaction_findings,
        ) = TransactionSurvivalAnalyzer().analyze(
            ast, cfg, effects, caller_transaction_contract=self._caller_transaction_contract
        )
        bundles = BehaviorEffectBundleBuilder().build(
            ast,
            cfg,
            effects,
            transaction_regions,
            transaction_analyses,
        )
        loop_summaries, loop_findings = LoopSummaryAnalyzer().analyze(ast, cfg)
        static_query_summaries, static_query_bindings, query_findings = QuerySourceSummaryBuilder(
            self._query_semantics_catalog
        ).build(ast)
        query_summaries = tuple(sorted(
            [*static_query_summaries, *dynamic_analysis.query_summaries],
            key=lambda item: item.query_summary_id,
        ))
        query_bindings = tuple(sorted(
            [*static_query_bindings, *dynamic_analysis.query_bindings],
            key=lambda item: item.binding_id,
        ))
        symbol_nullability, nullability_findings = DefiniteNullabilityAnalyzer().analyze(
            ast, query_bindings
        )
        path_state_findings = PathStateReconciliationAnalyzer().analyze(ast)
        predicate_graphs, constraint_assessments, predicate_findings = PredicateAnalysisBuilder().build(ast, bundles)
        constraint_assessments, window_reachability_findings = WindowReachabilityAnalyzer().analyze(
            ast, query_summaries, query_bindings, predicate_graphs, constraint_assessments
        )
        ordered_decision_reductions = OrderedDecisionReducer().build(ast, predicate_graphs)
        effect_obligations = EffectModalityAnalyzer().analyze(
            ast,
            effects,
            bundles,
            transaction_analyses,
            loop_summaries,
        )
        symbol_reference_findings = ProceduralSymbolValidator().analyze(ast)
        behavior_slices, slice_findings = LocalBackwardSlicer().build(
            ast,
            cfg,
            effects,
            bundles,
            query_summaries,
            query_bindings,
            predicate_graphs,
            constraint_assessments,
            effect_obligations,
        )
        bundle_findings = self._bundle_findings(parse_result, bundles)
        tenant_findings = TenantIsolationAnalyzer(self._tenant_isolation_catalog).analyze(ast, query_summaries)
        symbol_usage_findings = SymbolUsageAnalyzer().analyze(ast)
        type_safety_findings = AssignmentTypeSafetyAnalyzer().analyze(ast)
        findings = tuple(
            sorted(
                [
                    *direct_findings,
                    *transaction_findings,
                    *loop_findings,
                    *query_findings,
                    *dynamic_analysis.findings,
                    *predicate_findings,
                    *window_reachability_findings,
                    *slice_findings,
                    *bundle_findings,
                    *tenant_findings,
                    *handler_coverage_findings,
                    *handler_semantics_findings,
                    *symbol_usage_findings,
                    *type_safety_findings,
                    *symbol_reference_findings,
                    *nullability_findings,
                    *path_state_findings,
                ],
                key=lambda finding: finding.finding_id,
            )
        )
        without_digest = {
            "schema_version": "phase1-semantic-0.9",
            "parser_result_digest": canonical_digest(parse_result),
            "tenant_isolation_catalog_digest": (
                self._tenant_isolation_catalog.content_digest
                if self._tenant_isolation_catalog is not None
                else None
            ),
            "query_semantics_catalog_digest": (
                self._query_semantics_catalog.content_digest
                if self._query_semantics_catalog is not None
                else None
            ),
            "caller_transaction_contract_ref": (
                self._caller_transaction_contract.contract_id
                if self._caller_transaction_contract is not None
                else None
            ),
            "caller_transaction_contract_digest": (
                self._caller_transaction_contract.content_digest
                if self._caller_transaction_contract is not None
                else None
            ),
            "cfg": cfg,
            "effects": effects,
            "transaction_regions": transaction_regions,
            "transaction_analyses": transaction_analyses,
            "behavior_bundles": bundles,
            "loop_summaries": loop_summaries,
            "query_summaries": query_summaries,
            "query_bindings": query_bindings,
            "dynamic_sql_variants": dynamic_analysis.variants,
            "dynamic_sql_sites": dynamic_analysis.sites,
            "dynamic_query_bindings": dynamic_analysis.dynamic_query_bindings,
            "dynamic_relation_resolutions": dynamic_analysis.relation_resolutions,
            "dynamic_call_resolutions": dynamic_analysis.call_resolutions,
            "runtime_capture_contracts": dynamic_analysis.runtime_capture_contracts,
            "predicate_graphs": predicate_graphs,
            "constraint_assessments": constraint_assessments,
            "ordered_decision_reductions": ordered_decision_reductions,
            "effect_obligations": effect_obligations,
            "behavior_slices": behavior_slices,
            "handler_coverage": handler_coverage,
            "handler_semantics": handler_semantics,
            "symbol_nullability": symbol_nullability,
            "findings": findings,
            "parser_findings": parse_result.findings,
        }
        return Phase1SemanticResult(**without_digest, content_digest=canonical_digest(without_digest))

    def _bundle_findings(
        self,
        parse_result: ProcedureParseResult,
        bundles: tuple[object, ...],
    ) -> tuple[SemanticFinding, ...]:
        assert parse_result.ast is not None
        by_id = {node.node_id: node for node in parse_result.ast.nodes}
        result: list[SemanticFinding] = []
        for value in bundles:
            completeness = getattr(value, "bundle_completeness")
            if completeness != "PARTIAL":
                continue
            evidence_refs = tuple(getattr(value, "evidence_refs"))
            ranges = tuple(by_id[ref].source_range for ref in evidence_refs if ref in by_id)
            bundle_id = str(getattr(value, "bundle_id"))
            payload = f"{SemanticFindingCode.BEHAVIOR_BUNDLE_PARTIAL.value}|{bundle_id}"
            result.append(
                SemanticFinding(
                    finding_id="semantic-finding-"
                    + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20],
                    code=SemanticFindingCode.BEHAVIOR_BUNDLE_PARTIAL,
                    message="Behavior-effect bundle contains unresolved transaction or dependency boundaries.",
                    evidence_node_refs=evidence_refs,
                    source_ranges=ranges,
                    consequence="The bundle remains technical and cannot support ScenarioSpec generation.",
                )
            )
        return tuple(result)
