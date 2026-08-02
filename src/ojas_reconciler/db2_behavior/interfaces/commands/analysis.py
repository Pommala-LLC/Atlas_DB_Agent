from __future__ import annotations

import argparse

from ojas_reconciler.db2_behavior.application.explain import explain_parse_result
from ojas_reconciler.db2_behavior.bdd.authority import AuthorityRequirementsExporter, AuthoritySnapshotValidator
from ojas_reconciler.db2_behavior.bdd.authority_models import AuthorityValidationStatus
from ojas_reconciler.db2_behavior.bdd.explain import BddExplanationBuilder
from ojas_reconciler.db2_behavior.bdd.fixture_authority import FixtureAuthorityBuilder
from ojas_reconciler.db2_behavior.compiler import BddCompiler, ScenarioSpecCompiler
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_json_bytes
from ojas_reconciler.db2_behavior.parsing.adapters.lark_sqlpl.parser import LarkSqlPlSpikeParser

from ..command_support import (
    _load_snapshots,
    _print_bdd_explanations,
    _print_dynamic_sql_explanation,
    _print_explanation,
    _semantic_analyzer,
)

def handle(args: argparse.Namespace) -> int | None:
    if args.command == "parse-db2-script":
        result = LarkSqlPlSpikeParser().parse_script_file(args.source)
        payload = canonical_json_bytes(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(payload + b"\n")
            print(f"Db2 script parse result: {args.output}")
        else:
            print(payload.decode("utf-8"))
        return 0 if result.blocked_count == 0 and result.source_unit_count_matches else 2

    if args.command == "parse-spike":
        result = LarkSqlPlSpikeParser().parse_file(args.source)
        payload = canonical_json_bytes(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(payload + b"\n")
            print(f"Parse result: {args.output}")
        else:
            print(payload.decode("utf-8"))
        explanation = explain_parse_result(result)
        if args.explain_json:
            print(canonical_json_bytes(explanation).decode("utf-8"))
        elif args.explain:
            _print_explanation(explanation)
        return 0 if result.outcome.value.startswith("PARSES") else 2

    if args.command in {"analyze-phase1", "analyze-phase4"}:
        parse_result = LarkSqlPlSpikeParser().parse_file(args.source)
        if parse_result.ast is None:
            print(canonical_json_bytes(parse_result).decode("utf-8"))
            return 2
        result = _semantic_analyzer(args).analyze(parse_result)
        payload = canonical_json_bytes(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(payload + b"\n")
            print(f"Static semantic result: {args.output}")
        else:
            print(payload.decode("utf-8"))
        if args.command == "analyze-phase4" and args.explain:
            _print_dynamic_sql_explanation(result)
        return 0

    if args.command == "compile-scenarios":
        parse_result = LarkSqlPlSpikeParser().parse_file(args.source)
        if parse_result.ast is None:
            print(canonical_json_bytes(parse_result).decode("utf-8"))
            return 2
        semantic_result = _semantic_analyzer(args).analyze(parse_result)
        result = ScenarioSpecCompiler().compile_all(parse_result, semantic_result)
        payload = canonical_json_bytes(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(payload + b"\n")
            print(f"ScenarioSpec batch result: {args.output}")
        else:
            print(payload.decode("utf-8"))
        return 0

    if args.command == "export-authority-requirements":
        parse_result = LarkSqlPlSpikeParser().parse_file(args.source)
        if parse_result.ast is None:
            print(canonical_json_bytes(parse_result).decode("utf-8"))
            return 2
        semantic_result = _semantic_analyzer(args).analyze(parse_result)
        scenario_batch = ScenarioSpecCompiler().compile_all(parse_result, semantic_result)
        result = AuthorityRequirementsExporter().export(scenario_batch)
        payload = canonical_json_bytes(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(payload + b"\n")
            print(f"Authority requirements: {args.output}")
        else:
            print(payload.decode("utf-8"))
        return 0

    if args.command == "validate-authority":
        vocabulary, classification = _load_snapshots(
            args.vocabulary_snapshot,
            args.classification_snapshot,
        )
        result = AuthoritySnapshotValidator().validate(vocabulary, classification)
        payload = canonical_json_bytes(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(payload + b"\n")
            print(f"Authority validation: {args.output}")
        else:
            print(payload.decode("utf-8"))
        return 0 if result.validation_status == AuthorityValidationStatus.VALID else 4

    if args.command == "compile-bdd":
        parse_result = LarkSqlPlSpikeParser().parse_file(args.source)
        if parse_result.ast is None:
            print(canonical_json_bytes(parse_result).decode("utf-8"))
            return 2
        semantic_result = _semantic_analyzer(args).analyze(parse_result)
        scenario_batch = ScenarioSpecCompiler().compile_all(parse_result, semantic_result)
        if args.fixture_authority:
            if args.vocabulary_snapshot or args.classification_snapshot:
                raise SystemExit("--fixture-authority cannot be combined with explicit snapshots.")
            vocabulary, classification = FixtureAuthorityBuilder().build(scenario_batch)
        else:
            if args.vocabulary_snapshot is None or args.classification_snapshot is None:
                raise SystemExit(
                    "compile-bdd requires --fixture-authority or both --vocabulary-snapshot and "
                    "--classification-snapshot."
                )
            vocabulary, classification = _load_snapshots(
                args.vocabulary_snapshot,
                args.classification_snapshot,
            )
        authority_validation = AuthoritySnapshotValidator().validate(vocabulary, classification)
        if args.authority_validation_output:
            args.authority_validation_output.parent.mkdir(parents=True, exist_ok=True)
            args.authority_validation_output.write_bytes(
                canonical_json_bytes(authority_validation) + b"\n"
            )
            print(f"Authority validation: {args.authority_validation_output}")
        if authority_validation.validation_status != AuthorityValidationStatus.VALID:
            print(canonical_json_bytes(authority_validation).decode("utf-8"))
            return 4
        result = BddCompiler().compile_all(scenario_batch, vocabulary, classification)
        explanation = BddExplanationBuilder().build(
            scenario_batch, result, vocabulary, classification
        )
        if args.explain_output:
            args.explain_output.parent.mkdir(parents=True, exist_ok=True)
            args.explain_output.write_bytes(canonical_json_bytes(explanation) + b"\n")
            print(f"BDD explanation: {args.explain_output}")
        if args.explain:
            _print_bdd_explanations(explanation)
        payload = canonical_json_bytes(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(payload + b"\n")
            print(f"BDD compilation batch: {args.output}")
        else:
            print(payload.decode("utf-8"))
        if args.gherkin_dir:
            args.gherkin_dir.mkdir(parents=True, exist_ok=True)
            for artifact in result.gherkin_artifacts:
                path = args.gherkin_dir / f"{artifact.artifact_id}.feature"
                path.write_text(artifact.text, encoding="utf-8", newline="\n")
                print(f"Gherkin: {path}")
        return 0 if result.candidate_bdds else 3
    return None
