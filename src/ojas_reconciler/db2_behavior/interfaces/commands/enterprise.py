from __future__ import annotations

import argparse
import json
import os

from ...catalog import CatalogLineageResolver, Db2CatalogProvider, DdlCatalogProvider, JsonCatalogProvider
from ...composition import DirectCallCompositionInferenceService
from ...core.canonical_json import canonical_json_bytes
from ...decision import DecisionEvaluationRequest, ExtractedDecisionModel, ExtractedDecisionModelBuilder, ModelDrivenDecisionEvaluator
from ...dialects import DialectAdapterRegistry, DialectId
from ...graph import PersistentKnowledgeGraphStore
from ...commercial.models import ProcedureKnowledgeGraph
from ...runtime.reconcile import RuntimeReconciliationService
from ...testkit.fixture_compiler import ExecutableRelationalFixtureCompiler


def _emit(args: argparse.Namespace, value: object, *, output_name: str = "output") -> None:
    output = getattr(args, output_name, None)
    payload = canonical_json_bytes(value) + b"\n"
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(payload)
        print(f"Artifact: {output}")
    else:
        print(payload.decode("utf-8"), end="")


def handle(args: argparse.Namespace) -> int | None:
    if args.command == "catalog-build-from-ddl":
        _emit(args, DdlCatalogProvider(args.ddl, platform=args.platform, provider_ref=args.provider_ref).load())
        return 0
    if args.command == "catalog-capture-db2":
        connection = os.environ.get(args.connection_env)
        if not connection:
            raise SystemExit(f"Missing connection environment variable: {args.connection_env}")
        _emit(args, Db2CatalogProvider(connection_string=connection, platform=args.platform, schemas=args.schema, provider_ref=args.provider_ref).load())
        return 0
    if args.command == "catalog-resolve-lineage":
        snapshot = JsonCatalogProvider(args.catalog).load()
        _emit(args, CatalogLineageResolver(snapshot, max_depth=args.max_depth).resolve(args.relation_ref))
        return 0
    if args.command == "commercial-compile-executable-fixtures":
        snapshot = JsonCatalogProvider(args.catalog).load()
        values = ExecutableRelationalFixtureCompiler.load_approved_values(args.approved_values) if args.approved_values else ()
        artifact = ExecutableRelationalFixtureCompiler().compile(
            procedure_ref=args.procedure_ref,
            catalog=snapshot,
            relation_refs=args.relation_ref,
            approved_values=values,
            acknowledged_check_constraints=args.acknowledge_check,
        )
        _emit(args, artifact)
        return 0 if artifact.status.value == "EXECUTABLE" else 14
    if args.command == "commercial-infer-composition":
        _emit(args, DirectCallCompositionInferenceService().infer(args.run_dir))
        return 0
    if args.command == "commercial-build-decision-model":
        _emit(args, ExtractedDecisionModelBuilder().build(args.run_dir))
        return 0
    if args.command == "commercial-evaluate-decision":
        model = ExtractedDecisionModel.model_validate_json(args.model.read_text(encoding="utf-8"))
        request = DecisionEvaluationRequest.model_validate_json(args.request.read_text(encoding="utf-8"))
        _emit(args, ModelDrivenDecisionEvaluator().evaluate(model=model, request=request))
        return 0
    if args.command == "runtime-reconcile":
        service = RuntimeReconciliationService()
        plan_batch = service.load_plan_batch(args.plan_batch)
        records = service.load_execution_records(args.execution_record)
        batch, report = service.reconcile(plan_batch=plan_batch, execution_records=records)
        _emit(args, batch, output_name="batch_output")
        _emit(args, report, output_name="report_output")
        return 0 if not report.falsification_candidates else 15
    if args.command == "graph-ingest":
        graph = ProcedureKnowledgeGraph.model_validate_json(args.graph.read_text(encoding="utf-8"))
        result = PersistentKnowledgeGraphStore(args.db, tenant_ref=args.tenant_ref).ingest(graph)
        _emit(args, result)
        return 0
    if args.command == "graph-search":
        result = PersistentKnowledgeGraphStore(args.db, tenant_ref=args.tenant_ref).search_nodes(args.query, limit=args.limit)
        _emit(args, {"nodes": result})
        return 0
    if args.command == "graph-neighborhood":
        result = PersistentKnowledgeGraphStore(args.db, tenant_ref=args.tenant_ref).neighborhood(
            args.node_id, depth=args.depth, limit=args.limit
        )
        _emit(args, result)
        return 0
    if args.command == "dialect-registry":
        _emit(args, DialectAdapterRegistry.default().snapshot())
        return 0
    if args.command == "dialect-inventory":
        registry = DialectAdapterRegistry.default()
        _emit(args, registry.adapter(DialectId(args.dialect)).inventory(args.source))
        return 0
    return None
