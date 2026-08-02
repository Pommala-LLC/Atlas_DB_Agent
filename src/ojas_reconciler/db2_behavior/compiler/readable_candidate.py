"""Deterministic reviewer-facing Gherkin proposals.

Readable proposals are a presentation layer over technical evidence. They may
include blocked behavior slices so reviewers can see the complete extracted
decision surface, but they never change ScenarioSpec admission or authority.
Stable technical identifiers remain in the proposal manifest rather than being
printed into reviewer-facing Gherkin.
"""
from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable
from decimal import Decimal, InvalidOperation
from typing import Any

import networkx as nx

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.bdd.readable_quality import (
    ReadableBddQualityGate,
    build_readable_document,
)


class ReadableCandidateRenderer:
    """Render complete, explicitly non-authoritative technical candidates."""

    VERSION = "readable-candidate-renderer-1.5.0"
    AUTHORITY_SCOPE = "NON_AUTHORITATIVE_PROPOSAL"
    FEATURE_TAGS = "@technical_candidate @non_authoritative @requires_vocabulary_approval"

    def render(
        self,
        *,
        parse_payload: dict[str, Any],
        semantic_payload: dict[str, Any],
        scenario_payload: dict[str, Any],
        bdd_payload: dict[str, Any],
        warning_policy: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ast = parse_payload["ast"]
        procedure_name = ast["procedure_name"]
        schema_name = ast.get("schema_name")
        qualified = f"{schema_name}.{procedure_name}" if schema_name else procedure_name
        nodes = {item["node_id"]: item for item in ast.get("nodes", [])}
        effects = {item["effect_id"]: item for item in semantic_payload.get("effects", [])}
        self._nodes = nodes
        self._effects = effects
        self._symbol_types = {
            item.get("symbol_name", "").upper(): item.get("sql_type", {})
            for item in ast.get("declared_symbol_types", [])
        }
        self._nullability = {
            item.get("symbol_name", "").upper(): item.get("status", "UNKNOWN")
            for item in semantic_payload.get("symbol_nullability", [])
        }
        self._findings = semantic_payload.get("findings", [])
        self._finding_codes_by_ref: dict[str, set[str]] = defaultdict(set)
        for finding in self._findings:
            for ref in finding.get("evidence_node_refs", []):
                self._finding_codes_by_ref[ref].add(str(finding.get("code")))
        self._parent_by_child = self._parent_relations(nodes)
        self._initialization_refs = self._initialization_only_refs(ast, effects, nodes)
        cfg_payload = semantic_payload.get("cfg", {})
        self._cfg_graph, self._cfg_dominators, self._cfg_postdominators = self._cfg_analysis(
            cfg_payload
        )
        self._handler_bindings_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in cfg_payload.get("handler_bindings", []):
            source = str(item.get("source_ast_node_ref") or "")
            if source:
                self._handler_bindings_by_source[source].append(item)
        self._handler_semantics_by_region = {
            str(item.get("handler_region_ref") or ""): item
            for item in semantic_payload.get("handler_semantics", [])
        }
        self._suppressed_composed_candidates = 0
        bundles = {
            item["bundle_id"]: item for item in semantic_payload.get("behavior_bundles", [])
        }
        slices = {
            item["bundle_ref"]: item for item in semantic_payload.get("behavior_slices", [])
        }
        query_summaries = {
            item["query_summary_id"]: item
            for item in semantic_payload.get("query_summaries", [])
        }
        query_bindings = {
            item["target_symbol"].upper(): {
                **item,
                "query_summary": query_summaries.get(item.get("query_summary_ref")),
            }
            for item in semantic_payload.get("query_bindings", [])
        }
        results = {
            item["behavior_effect_bundle_ref"]: item
            for item in scenario_payload.get("compilation_results", [])
        }
        specs_by_bundle = {
            item["behavior_effect_bundle_ref"]: item
            for item in scenario_payload.get("scenario_specs", [])
            if item.get("behavior_effect_bundle_ref")
        }
        technical_by_behavior = {
            item["behavior_id"]: item for item in bdd_payload.get("gherkin_artifacts", [])
        }

        source_symbol_id = scenario_payload.get("source_symbol_id") or self._stable_id(
            "source-symbol", qualified, parse_payload.get("source_digest", "")
        )
        symbol_lineage_id = scenario_payload.get("symbol_lineage_id") or self._stable_id(
            "symbol-lineage", qualified
        )
        artifact_revision_id = parse_payload.get("artifact_revision_id") or parse_payload.get(
            "source_digest", "UNKNOWN"
        )

        scenario_entries: list[dict[str, Any]] = []
        ordered_bundles = sorted(
            bundles.values(),
            key=lambda bundle: self._bundle_source_order(bundle, effects, nodes),
        )
        for bundle in ordered_bundles:
            primary = effects.get(bundle.get("primary_effect_ref"))
            if primary is None:
                continue
            if primary.get("source_node_ref") in self._initialization_refs:
                continue
            if (
                primary.get("effect_kind") == "OUT_PARAMETER_ASSIGNMENT"
                and str(primary.get("value_expression") or "").startswith(
                    ("SELECT_INTO_PROJECTION_", "EXECUTE_INTO_PROJECTION_")
                )
            ):
                continue
            variants = self._behavior_variants(
                qualified=qualified,
                bundle=bundle,
                primary=primary,
                effects=effects,
                nodes=nodes,
                query_bindings=query_bindings,
            )
            variants = [
                self._compose_variant_context_and_path(
                    variant, bundle=bundle, primary=primary, effects=effects, nodes=nodes,
                    query_bindings=query_bindings
                )
                for variant in variants
            ]
            variants = [variant for variant in variants if variant is not None]
            result = results.get(bundle["bundle_id"], {})
            spec = specs_by_bundle.get(bundle["bundle_id"])
            technical = (
                technical_by_behavior.get(spec["behavior_id"]) if spec is not None else None
            )
            admitted = spec is not None and technical is not None
            for variant in variants:
                scenario_entries.append(
                    self._behavior_artifact(
                        qualified=qualified,
                        variant=variant,
                        bundle=bundle,
                        primary=primary,
                        behavior_slice=slices.get(bundle["bundle_id"]),
                        result=result,
                        spec=spec,
                        technical=technical,
                        admitted=admitted,
                        source_symbol_id=source_symbol_id,
                        symbol_lineage_id=symbol_lineage_id,
                        artifact_revision_id=artifact_revision_id,
                    )
                )

        for fact in semantic_payload.get("handler_coverage", []):
            if fact.get("coverage_status") != "MISSING":
                continue
            node = nodes.get(fact.get("source_node_ref"))
            if node is None:
                continue
            scenario_entries.append(
                self._unhandled_not_found_artifact(
                    qualified=qualified,
                    node=node,
                    fact=fact,
                    source_symbol_id=source_symbol_id,
                    symbol_lineage_id=symbol_lineage_id,
                    artifact_revision_id=artifact_revision_id,
                    effects=effects,
                    nodes=nodes,
                )
            )

        warning_codes = {
            "CURSOR_PREDICATE_CONFLICTS_WITH_PRIOR_STATE_TRANSITION",
            "SHARED_HANDLER_STATE_INTERFERENCE_CANDIDATE",
            "STALE_HANDLER_STATE_BEFORE_LOOP_CANDIDATE",
            "HANDLER_REFERENCES_CONDITIONALLY_ESTABLISHED_SAVEPOINT",
            "HANDLER_BODY_FAILURE_PROPAGATES",
            "DIALECT_PROFILE_UNVERIFIED_DIAGNOSTIC_ITEM",
        }
        for finding in self._findings:
            if str(finding.get("code")) not in warning_codes:
                continue
            scenario_entries.append(
                self._analysis_warning_artifact(
                    qualified=qualified,
                    finding=finding,
                    source_symbol_id=source_symbol_id,
                    symbol_lineage_id=symbol_lineage_id,
                    artifact_revision_id=artifact_revision_id,
                )
            )

        scenario_entries = self._consolidate_validation_signal_entries(
            qualified, scenario_entries
        )
        scenario_entries = self._suppress_fully_composed_standalone_entries(
            scenario_entries
        )
        scenario_entries.sort(key=lambda item: (item["display_order"], item["proposal_id"]))
        artifacts = tuple(self._without_display_order(item) for item in scenario_entries)
        combined_text = self._combined_feature_text(qualified, scenario_entries)
        readable_document = build_readable_document(
            qualified=qualified,
            feature_tags=self.FEATURE_TAGS.split(),
            entries=scenario_entries,
        )
        if warning_policy is not None:
            policy_procedure = str(warning_policy.get("procedure") or "")
            if policy_procedure and policy_procedure != qualified:
                from ojas_reconciler.db2_behavior.bdd.readable_quality import (
                    ReadableBddQualityError,
                )
                raise ReadableBddQualityError(
                    "Readable BDD warning policy is bound to a different procedure."
                )

        quality_gate = ReadableBddQualityGate()
        quality = quality_gate.validate(
            readable_document=readable_document,
            feature_text=combined_text,
            warning_policy=warning_policy,
        )
        feature_files: list[tuple[str, str]] = [
            ("bdd/READABLE_CANDIDATES.feature", combined_text),
        ]
        feature_files.extend(
            (f"bdd/readable-candidates/{item['proposal_id']}.feature", item["text"])
            for item in artifacts
        )
        for index, technical_artifact in enumerate(
            bdd_payload.get("gherkin_artifacts", []), start=1
        ):
            feature_files.append(
                (
                    f"bdd/technical/{technical_artifact['artifact_id']}.feature",
                    technical_artifact["text"],
                )
            )
            feature_files.append(
                (
                    f"test-package/features/generated-{index:03d}.feature",
                    technical_artifact["text"],
                )
            )
        feature_validation = quality_gate.validate_feature_collection(
            feature_files=feature_files
        )
        accounting = {
            "semantic_behavior_bundles": len(bundles),
            "scenario_admitted": sum(
                1
                for item in scenario_payload.get("compilation_results", [])
                if item.get("compilation_status") == "SUCCEEDED"
            ),
            "scenario_blocked": sum(
                1
                for item in scenario_payload.get("compilation_results", [])
                if item.get("compilation_status") == "BLOCKED"
            ),
            "readable_behavior_candidates": sum(
                1 for item in artifacts if item["proposal_kind"] == "BEHAVIOR"
            ),
            "readable_unhandled_condition_candidates": sum(
                1
                for item in artifacts
                if item["proposal_kind"] == "UNHANDLED_CONDITION"
            ),
            "readable_analysis_warning_candidates": sum(
                1
                for item in artifacts
                if item["proposal_kind"] == "ANALYSIS_WARNING"
            ),
            "readable_total": len(artifacts),
            "readable_suppressed_composed_candidates": self._suppressed_composed_candidates,
            "omitted_semantic_behavior_bundles": max(
                0,
                len(bundles)
                - len(
                    {
                        ref
                        for item in artifacts
                        for ref in (
                            item.get("source_bundle_refs")
                            or (
                                (item["behavior_effect_bundle_ref"],)
                                if item["behavior_effect_bundle_ref"] is not None
                                else ()
                            )
                        )
                    }
                ),
            ),
        }
        without_manifest_digest = {
            "schema_version": "readable-bdd-proposal-batch-1.5",
            "authority_scope": self.AUTHORITY_SCOPE,
            "review_required": True,
            "renderer_version": self.VERSION,
            "quality_gate_version": ReadableBddQualityGate.VERSION,
            "procedure": qualified,
            "accounting": accounting,
            "artifacts": artifacts,
            "combined_text": combined_text,
            "semantic_digest": quality["semantic_digest"],
            "gherkin_content_digest": quality["gherkin_content_digest"],
            "gherkin_structure_digest": quality["gherkin_structure_digest"],
            "lint_report_digest": quality["lint_report_digest"],
            "quality": {
                "status": quality["lint_report"]["status"],
                "parser_name": quality["lint_report"]["parser_name"],
                "parser_version": quality["lint_report"]["parser_version"],
                "error_count": quality["lint_report"]["error_count"],
                "warning_count": quality["lint_report"]["warning_count"],
                "warning_governance": quality["lint_report"]["warning_governance"],
                "readable_document_ref": "bdd/readable-bdd-document.json",
                "gherkin_document_ref": "bdd/gherkin-document.json",
                "lint_report_ref": "bdd/lint-report.json",
                "feature_validation_report_ref": "bdd/feature-validation-report.json",
                "quality_artifact_digests": {
                    "feature_text": quality["gherkin_content_digest"],
                    "readable_bdd_document": canonical_digest(quality["readable_document"]),
                    "gherkin_document": canonical_digest(quality["gherkin_document"]),
                    "lint_report": canonical_digest(quality["lint_report"]),
                    "feature_validation_report": canonical_digest(feature_validation),
                },
            },
        }
        return {
            **without_manifest_digest,
            "manifest_digest": canonical_digest(without_manifest_digest),
            "_readable_document": quality["readable_document"],
            "_gherkin_document": quality["gherkin_document"],
            "_lint_report": quality["lint_report"],
            "_feature_validation_report": feature_validation,
        }

    def _behavior_artifact(
        self,
        *,
        qualified: str,
        variant: dict[str, Any],
        bundle: dict[str, Any],
        primary: dict[str, Any],
        behavior_slice: dict[str, Any] | None,
        result: dict[str, Any],
        spec: dict[str, Any] | None,
        technical: dict[str, Any] | None,
        admitted: bool,
        source_symbol_id: str,
        symbol_lineage_id: str,
        artifact_revision_id: str,
    ) -> dict[str, Any]:
        behavior_id = (
            spec["behavior_id"]
            if spec is not None
            else self._stable_id(
                "behavior-candidate",
                source_symbol_id,
                bundle["bundle_id"],
            )
        )
        proposal_id = self._stable_id(
            "readable-proposal", behavior_id, variant["variant_key"]
        )
        evidence_for_status = set(bundle.get("evidence_refs", [])) | set(
            (behavior_slice or {}).get("evidence_refs", [])
        )
        status = self._analysis_status(
            admitted=admitted,
            evidence_refs=evidence_for_status,
            variant_status=variant.get("analysis_status"),
        )
        body = self._scenario_body(
            scenario_name=variant["scenario_name"],
            given_lines=variant["given_lines"],
            action_line=variant.get("action_line") or f"{qualified} is invoked",
            then_lines=variant["then_lines"],
            indent=4,
            scenario_tags=[self._status_tag(status)],
        )
        text = self._single_feature_text(
            qualified, variant["rule_name"], body
        )
        evidence_refs = self._dedupe(
            [
                *bundle.get("evidence_refs", []),
                *(behavior_slice or {}).get("evidence_refs", []),
                *(spec or {}).get("evidence_refs", []),
            ]
        )
        without_digest = {
            "proposal_id": proposal_id,
            "schema_version": "readable-bdd-proposal-1.5",
            "authority_scope": self.AUTHORITY_SCOPE,
            "review_required": True,
            "renderer_version": self.VERSION,
            "proposal_kind": "BEHAVIOR",
            "analysis_status": status,
            "confidence_class": self._confidence_class(status),
            "variant_key": variant["variant_key"],
            "behavior_id": behavior_id,
            "behavior_effect_bundle_ref": bundle["bundle_id"],
            "behavior_slice_ref": result.get("behavior_slice_ref")
            or (behavior_slice or {}).get("slice_id"),
            "scenario_spec_ref": spec.get("scenario_spec_id") if spec else None,
            "technical_gherkin_artifact_ref": (
                technical.get("artifact_id") if technical else None
            ),
            "source_symbol_id": source_symbol_id,
            "symbol_lineage_id": symbol_lineage_id,
            "artifact_revision_id": artifact_revision_id,
            "evidence_refs": tuple(evidence_refs),
            "finding_refs": tuple(result.get("finding_refs", [])),
            "blocker_codes": tuple(result.get("blockers", [])),
            "blocker_details": tuple(result.get("blocker_details", [])),
            "rule_name": variant["rule_name"],
            "scenario_name": variant["scenario_name"],
            "text": text,
            "source_behavior_refs": (behavior_id,),
            "source_bundle_refs": (bundle["bundle_id"],),
        }
        return {
            **without_digest,
            "content_digest": canonical_digest(without_digest),
            "display_order": variant["display_order"],
            "scenario_body": body,
            "_primary_kind": str(primary.get("effect_kind") or ""),
            "_source_ref": str(primary.get("source_node_ref") or ""),
            "_given_lines": tuple(variant["given_lines"]),
            "_then_lines": tuple(variant["then_lines"]),
            "_action_line": variant.get("action_line") or f"{qualified} is invoked",
            "_scenario_kind": "Scenario",
            "_scenario_tags": (self._status_tag(status),),
            "_examples": (),
        }

    def _unhandled_not_found_artifact(
        self,
        *,
        qualified: str,
        node: dict[str, Any],
        fact: dict[str, Any],
        source_symbol_id: str,
        symbol_lineage_id: str,
        artifact_revision_id: str,
        effects: dict[str, dict[str, Any]],
        nodes: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        text = self._one_line(node.get("text", ""))
        line = int(node.get("source_range", {}).get("start_line", 0))
        relations = self._query_relation_names(text)
        if node.get("kind") == "FETCH_CURSOR":
            scenario_name = f"Missing cursor row at source line {line} terminates the procedure"
            given = ["the cursor fetch produces no row"]
        elif relations:
            relation_label = " and ".join(relations[:2])
            scenario_name = f"Missing required {relation_label} row terminates the procedure"
            given = [
                f"the SELECT INTO query over {relation_label} produces no row"
            ]
        else:
            scenario_name = f"Unhandled NOT FOUND at source line {line}"
            given = ["the referenced SELECT INTO or FETCH produces no row"]

        node_offset = int(node.get("source_range", {}).get("start_offset", 0))
        prior_out = [
            effect
            for effect in effects.values()
            if effect.get("effect_kind") == "OUT_PARAMETER_ASSIGNMENT"
            and int(
                nodes.get(effect.get("source_node_ref"), {})
                .get("source_range", {})
                .get("start_offset", 10**18)
            )
            < node_offset
        ]
        output_consequence = (
            "no subsequent output assignments are executed"
            if prior_out
            else "the output parameters remain unassigned"
        )
        then = [
            "the procedure terminates with an unhandled NOT FOUND condition",
            output_consequence,
        ]
        body = self._scenario_body(
            scenario_name=scenario_name,
            given_lines=given,
            action_line=f"{qualified} is invoked",
            then_lines=then,
            indent=4,
            scenario_tags=["@unhandled_condition_candidate"],
        )
        proposal_id = self._stable_id(
            "readable-proposal", "NOT_FOUND", fact["coverage_id"]
        )
        feature_text = self._single_feature_text(
            qualified, "Required query data", body
        )
        without_digest = {
            "proposal_id": proposal_id,
            "schema_version": "readable-bdd-proposal-1.5",
            "authority_scope": self.AUTHORITY_SCOPE,
            "review_required": True,
            "renderer_version": self.VERSION,
            "proposal_kind": "UNHANDLED_CONDITION",
            "analysis_status": "UNHANDLED_CONDITION_CANDIDATE",
            "confidence_class": "UNHANDLED_CONDITION_REQUIRES_REVIEW",
            "variant_key": f"not-found-line-{line}",
            "behavior_id": None,
            "behavior_effect_bundle_ref": None,
            "behavior_slice_ref": None,
            "scenario_spec_ref": None,
            "technical_gherkin_artifact_ref": None,
            "source_symbol_id": source_symbol_id,
            "symbol_lineage_id": symbol_lineage_id,
            "artifact_revision_id": artifact_revision_id,
            "evidence_refs": tuple(fact.get("evidence_refs", [node["node_id"]])),
            "finding_refs": (),
            "blocker_codes": ("MISSING_NOT_FOUND_HANDLER",),
            "blocker_details": (
                "No applicable NOT FOUND handler exists in the statement's lexical scope.",
            ),
            "rule_name": "Required query data",
            "scenario_name": scenario_name,
            "text": feature_text,
            "source_behavior_refs": (),
            "source_bundle_refs": (),
        }
        return {
            **without_digest,
            "content_digest": canonical_digest(without_digest),
            "display_order": 5 + line,
            "scenario_body": body,
            "_primary_kind": "UNHANDLED_CONDITION",
            "_given_lines": tuple(given),
            "_then_lines": tuple(then),
            "_action_line": f"{qualified} is invoked",
            "_scenario_kind": "Scenario",
            "_scenario_tags": ("@unhandled_condition_candidate",),
            "_examples": (),
        }

    def _analysis_warning_artifact(
        self,
        *,
        qualified: str,
        finding: dict[str, Any],
        source_symbol_id: str,
        symbol_lineage_id: str,
        artifact_revision_id: str,
    ) -> dict[str, Any]:
        code = str(finding.get("code") or "ANALYSIS_WARNING")
        message = self._one_line(finding.get("message") or code)
        consequence = self._one_line(
            finding.get("consequence") or "Manual review is required."
        )
        labels = {
            "CURSOR_PREDICATE_CONFLICTS_WITH_PRIOR_STATE_TRANSITION": (
                "Cursor eligibility conflicts with a prior state transition",
                "the procedure reaches the affected cursor after the earlier mutation",
            ),
            "SHARED_HANDLER_STATE_INTERFERENCE_CANDIDATE": (
                "Shared handler state can affect later cursor behavior",
                "later logic reads state written by the shared handler",
            ),
            "STALE_HANDLER_STATE_BEFORE_LOOP_CANDIDATE": (
                "Stale handler state can suppress a later loop",
                "the later loop begins without resetting the handler state",
            ),
            "HANDLER_REFERENCES_CONDITIONALLY_ESTABLISHED_SAVEPOINT": (
                "Exception handling may reference an unavailable savepoint",
                "an exception occurs before the savepoint is established",
            ),
            "HANDLER_BODY_FAILURE_PROPAGATES": (
                "Error logging can fail inside the exception handler",
                "the handler body attempts its persistence effect",
            ),
            "DIALECT_PROFILE_UNVERIFIED_DIAGNOSTIC_ITEM": (
                "Verify the diagnostic item against the target Db2 profile",
                "the configured platform and version profile is evaluated",
            ),
        }
        scenario_name, action = labels.get(
            code, ("Review a conditional analysis warning", "the warning condition is evaluated")
        )
        given_lines = [message]
        then_lines = [consequence]
        if code == "HANDLER_BODY_FAILURE_PROPAGATES":
            given_lines = [
                "an SQL exception activates the enclosing exception handler",
                "the handler reaches its error-log persistence statement",
            ]
            action = "the error-log persistence raises another SQL exception"
            then_lines = [
                "the current handler does not catch the logging failure",
                "the procedure terminates with the secondary logging failure",
                "successful delivery of the assigned output parameters is not established",
            ]
        elif code == "DIALECT_PROFILE_UNVERIFIED_DIAGNOSTIC_ITEM":
            given_lines = [
                "GET DIAGNOSTICS uses the EXCEPTION selector with RETURNED_SQLSTATE"
            ]
            action = "the statement is checked against the configured Db2 platform and version"
            then_lines = [
                "the EXCEPTION selector is not rejected solely as non-Db2 syntax",
                "support for the diagnostic-item combination remains profile-unverified",
            ]
        body = self._scenario_body(
            scenario_name=scenario_name,
            given_lines=given_lines,
            action_line=action,
            then_lines=then_lines,
            indent=4,
            scenario_tags=["@analysis_warning", "@conditional_technical_candidate"],
        )
        proposal_id = self._stable_id(
            "readable-analysis-warning", str(finding.get("finding_id") or code)
        )
        feature_text = self._single_feature_text(qualified, "Analysis warnings", body)
        evidence_refs = tuple(finding.get("evidence_node_refs", []))
        source_ranges = finding.get("source_ranges", [])
        line = min(
            (int(item.get("start_line", 0)) for item in source_ranges),
            default=0,
        )
        without_digest = {
            "proposal_id": proposal_id,
            "schema_version": "readable-bdd-proposal-1.5",
            "authority_scope": self.AUTHORITY_SCOPE,
            "review_required": True,
            "renderer_version": self.VERSION,
            "proposal_kind": "ANALYSIS_WARNING",
            "analysis_status": "ANALYSIS_WARNING",
            "confidence_class": "WARNING_REQUIRES_REVIEW",
            "variant_key": code.lower(),
            "behavior_id": None,
            "behavior_effect_bundle_ref": None,
            "behavior_slice_ref": None,
            "scenario_spec_ref": None,
            "technical_gherkin_artifact_ref": None,
            "source_symbol_id": source_symbol_id,
            "symbol_lineage_id": symbol_lineage_id,
            "artifact_revision_id": artifact_revision_id,
            "evidence_refs": evidence_refs,
            "finding_refs": (finding.get("finding_id"),),
            "blocker_codes": (code,),
            "blocker_details": (consequence,),
            "rule_name": "Analysis warnings",
            "scenario_name": scenario_name,
            "text": feature_text,
            "source_behavior_refs": (),
            "source_bundle_refs": (),
        }
        return {
            **without_digest,
            "content_digest": canonical_digest(without_digest),
            "display_order": line * 10 + 9,
            "scenario_body": body,
            "_primary_kind": "ANALYSIS_WARNING",
            "_given_lines": tuple(given_lines),
            "_then_lines": tuple(then_lines),
            "_action_line": action,
            "_scenario_kind": "Scenario",
            "_scenario_tags": ("@analysis_warning", "@conditional_technical_candidate"),
            "_examples": (),
        }

    def _consolidate_validation_signal_entries(
        self,
        qualified: str,
        entries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        others: list[dict[str, Any]] = []
        for entry in entries:
            then_lines = tuple(entry.get("_then_lines", ()))
            if (
                entry.get("proposal_kind") == "BEHAVIOR"
                and entry.get("_primary_kind") == "SIGNAL"
                and then_lines
                and any("handler is activated" in line for line in then_lines)
                and re.match(r"SQLSTATE\s+[^ ]+\s+is raised internally", then_lines[0])
            ):
                candidates.append(entry)
            else:
                others.append(entry)
        if len(candidates) < 2:
            return entries

        groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
        for entry in candidates:
            tail = tuple(
                re.sub(r"SQLSTATE\s+[0-9A-Z]+", "SQLSTATE <sqlstate>", line)
                for line in entry.get("_then_lines", ())
            )
            groups[tail].append(entry)

        for common_then, group in groups.items():
            if len(group) < 2:
                others.extend(group)
                continue
            group.sort(key=lambda item: (item["display_order"], item["proposal_id"]))
            examples: list[tuple[str, str]] = []
            for entry in group:
                state_match = re.match(
                    r"SQLSTATE\s+([0-9A-Z]+)\s+is raised internally",
                    str(entry.get("_then_lines", ("",))[0]),
                )
                if state_match is None:
                    continue
                examples.append(
                    (
                        self._invalid_input_description(entry.get("_given_lines", ())),
                        state_match.group(1),
                    )
                )
            if len(examples) < 2:
                others.extend(group)
                continue

            scenario_name = "Convert an invalid required input into error outputs"
            given_lines = ["<invalid_input>"]
            then_lines = list(common_then)
            body = self._scenario_outline_body(
                scenario_name=scenario_name,
                given_lines=given_lines,
                action_line=f"{qualified} is invoked",
                then_lines=then_lines,
                examples=examples,
                indent=4,
                scenario_tags=["@conditional_technical_candidate"],
            )
            rule_name = "Required input validation"
            base = group[0]
            source_behavior_refs = tuple(
                dict.fromkeys(
                    ref
                    for item in group
                    for ref in item.get("source_behavior_refs", ())
                    if ref
                )
            )
            source_bundle_refs = tuple(
                dict.fromkeys(
                    ref
                    for item in group
                    for ref in item.get("source_bundle_refs", ())
                    if ref
                )
            )
            proposal_id = self._stable_id(
                "readable-proposal", qualified, "required-input-validation-outline"
            )
            text = self._single_feature_text(qualified, rule_name, body)
            without_digest = {
                **{
                    key: value
                    for key, value in base.items()
                    if not key.startswith("_")
                    and key not in {
                        "content_digest",
                        "display_order",
                        "scenario_body",
                        "proposal_id",
                        "variant_key",
                        "behavior_id",
                        "behavior_effect_bundle_ref",
                        "behavior_slice_ref",
                        "scenario_spec_ref",
                        "technical_gherkin_artifact_ref",
                        "evidence_refs",
                        "finding_refs",
                        "blocker_codes",
                        "blocker_details",
                        "rule_name",
                        "scenario_name",
                        "text",
                        "source_behavior_refs",
                        "source_bundle_refs",
                    }
                },
                "proposal_id": proposal_id,
                "variant_key": "required-input-validation-outline",
                "behavior_id": None,
                "behavior_effect_bundle_ref": None,
                "behavior_slice_ref": None,
                "scenario_spec_ref": None,
                "technical_gherkin_artifact_ref": None,
                "evidence_refs": tuple(
                    dict.fromkeys(
                        ref for item in group for ref in item.get("evidence_refs", ())
                    )
                ),
                "finding_refs": tuple(
                    dict.fromkeys(
                        ref for item in group for ref in item.get("finding_refs", ())
                    )
                ),
                "blocker_codes": tuple(
                    dict.fromkeys(
                        ref for item in group for ref in item.get("blocker_codes", ())
                    )
                ),
                "blocker_details": tuple(
                    dict.fromkeys(
                        ref for item in group for ref in item.get("blocker_details", ())
                    )
                ),
                "rule_name": rule_name,
                "scenario_name": scenario_name,
                "text": text,
                "source_behavior_refs": source_behavior_refs,
                "source_bundle_refs": source_bundle_refs,
            }
            others.append(
                {
                    **without_digest,
                    "content_digest": canonical_digest(without_digest),
                    "display_order": min(item["display_order"] for item in group),
                    "scenario_body": body,
                    "_primary_kind": "SIGNAL_OUTLINE",
                    "_given_lines": tuple(given_lines),
                    "_then_lines": tuple(then_lines),
                    "_action_line": f"{qualified} is invoked",
                    "_scenario_kind": "Scenario Outline",
                    "_scenario_tags": ("@conditional_technical_candidate",),
                    "_examples": (
                        {
                            "headers": ["invalid_input", "sqlstate"],
                            "rows": [[invalid_input, f'"{sqlstate}"'] for invalid_input, sqlstate in examples],
                        },
                    ),
                }
            )
        return others

    @staticmethod
    def _invalid_input_description(lines: Iterable[str]) -> str:
        text = " ".join(lines)
        symbol_match = re.search(r"\b(P_[A-Za-z0-9_$]+)\b", text)
        symbol = symbol_match.group(1).upper() if symbol_match else "the required input"
        if "LENGTH(TRIM" in text.upper() or "BLANK" in text.upper():
            return f"{symbol} is null or blank"
        return f"{symbol} is null"

    def _suppress_fully_composed_standalone_entries(
        self, entries: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        suppressed = 0
        for entry in entries:
            kind = entry.get("_primary_kind")
            then = {line.casefold() for line in entry.get("_then_lines", ()) if line}
            if kind not in {"DML", "SEQUENCE_VALUE_ACQUISITION", "RESULT_SET_RETURN"} or not then:
                result.append(entry)
                continue
            composed_elsewhere = any(
                other is not entry
                and entry.get("proposal_kind") == other.get("proposal_kind") == "BEHAVIOR"
                and then < {
                    line.casefold()
                    for line in other.get("_then_lines", ())
                    if line
                }
                for other in entries
            )
            if composed_elsewhere:
                suppressed += 1
                continue
            result.append(entry)
        self._suppressed_composed_candidates = suppressed
        return result

    @staticmethod
    def _query_relation_names(text: str) -> list[str]:
        values: list[str] = []
        depth = 0
        quote: str | None = None
        index = 0
        while index < len(text):
            char = text[index]
            if quote:
                if char == quote:
                    if index + 1 < len(text) and text[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
                index += 1
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth = max(0, depth - 1)
            elif depth == 0:
                match = re.match(
                    r"(?:FROM|JOIN)\s+([A-Za-z_][A-Za-z0-9_.$]*)",
                    text[index:],
                    flags=re.IGNORECASE,
                )
                if match:
                    values.append(match.group(1).upper())
                    index += match.end()
                    continue
            index += 1
        return list(dict.fromkeys(values))


    @staticmethod
    def _parent_relations(nodes: dict[str, dict[str, Any]]) -> dict[str, str]:
        result: dict[str, str] = {}
        for node in nodes.values():
            for child in node.get("child_refs", []):
                result[child] = node["node_id"]
        return result

    @staticmethod
    def _initialization_only_refs(
        ast: dict[str, Any],
        effects: dict[str, dict[str, Any]],
        nodes: dict[str, dict[str, Any]],
    ) -> set[str]:
        by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for effect in effects.values():
            if effect.get("effect_kind") == "OUT_PARAMETER_ASSIGNMENT" and effect.get("target"):
                by_target[str(effect["target"]).upper()].append(effect)
        result: set[str] = set()
        for target, values in by_target.items():
            ordered = sorted(
                values,
                key=lambda effect: int(
                    nodes.get(effect.get("source_node_ref"), {})
                    .get("source_range", {})
                    .get("start_offset", 10**18)
                ),
            )
            for index, effect in enumerate(ordered[:-1]):
                node = nodes.get(effect.get("source_node_ref"), {})
                expression = " ".join(str(effect.get("value_expression") or "").split()).upper()
                if node.get("lexical_scope_ref") != "procedure-body":
                    continue
                if expression not in {"NULL", "0", "0.0", "0.00", "'RUNNING'"}:
                    continue
                result.add(str(effect.get("source_node_ref")))
        return result

    @staticmethod
    def _cfg_analysis(cfg: dict[str, Any]):
        graph = nx.DiGraph()
        for node in cfg.get("nodes", []):
            graph.add_node(node.get("cfg_node_id"))
        for edge in cfg.get("edges", []):
            graph.add_edge(edge.get("source_ref"), edge.get("target_ref"))
        entry = cfg.get("entry_ref")
        normal = cfg.get("normal_exit_ref")
        exceptional = cfg.get("exceptional_exit_ref")
        try:
            dominators = nx.immediate_dominators(graph, entry) if entry in graph else {}
        except (nx.NetworkXError, nx.NetworkXException):
            dominators = {}
        reverse = graph.reverse(copy=True)
        sink = "cfg:readable-postdom-sink"
        reverse.add_node(sink)
        if normal in reverse:
            reverse.add_edge(sink, normal)
        if exceptional in reverse:
            reverse.add_edge(sink, exceptional)
        try:
            postdominators = nx.immediate_dominators(reverse, sink)
        except (nx.NetworkXError, nx.NetworkXException):
            postdominators = {}
        return graph, dominators, postdominators

    def _analysis_status(
        self,
        *,
        admitted: bool,
        evidence_refs: set[str],
        variant_status: str | None,
    ) -> str:
        if variant_status:
            return variant_status
        codes = {
            code
            for ref in evidence_refs
            for code in self._finding_codes_by_ref.get(ref, set())
        }
        if codes & {"UNREACHABLE_BRANCH", "IMPOSSIBLE_NULL_PREDICATE"}:
            return "UNREACHABLE_TECHNICAL_CANDIDATE"
        if codes & {
            "CURSOR_PREDICATE_CONFLICTS_WITH_PRIOR_STATE_TRANSITION",
            "STALE_HANDLER_STATE_BEFORE_LOOP_CANDIDATE",
            "SHARED_HANDLER_STATE_INTERFERENCE_CANDIDATE",
            "HANDLER_REFERENCES_CONDITIONALLY_ESTABLISHED_SAVEPOINT",
        }:
            return "CONDITIONAL_TECHNICAL_CANDIDATE"
        return "ADMITTED_TECHNICAL_SCENARIO" if admitted else "PARTIAL_TECHNICAL_CANDIDATE"

    @staticmethod
    def _status_tag(status: str) -> str:
        return {
            "ADMITTED_TECHNICAL_SCENARIO": "@admitted_technical_scenario",
            "CONDITIONAL_TECHNICAL_CANDIDATE": "@conditional_technical_candidate",
            "UNREACHABLE_TECHNICAL_CANDIDATE": "@unreachable_technical_candidate",
            "PARTIAL_TECHNICAL_CANDIDATE": "@partial_technical_candidate",
        }.get(status, "@partial_technical_candidate")

    @staticmethod
    def _confidence_class(status: str) -> str:
        return {
            "ADMITTED_TECHNICAL_SCENARIO": "PROVEN_FROM_ADMITTED_TECHNICAL_SLICE",
            "CONDITIONAL_TECHNICAL_CANDIDATE": "CONDITIONAL_OR_DATA_DEPENDENT",
            "UNREACHABLE_TECHNICAL_CANDIDATE": "UNREACHABLE",
            "PARTIAL_TECHNICAL_CANDIDATE": "PARTIAL_OR_BLOCKED",
            "ANALYSIS_WARNING": "WARNING_REQUIRES_REVIEW",
        }.get(status, "PARTIAL_OR_BLOCKED")

    def _compose_variant_context_and_path(
        self,
        variant: dict[str, Any],
        *,
        bundle: dict[str, Any],
        primary: dict[str, Any],
        effects: dict[str, dict[str, Any]],
        nodes: dict[str, dict[str, Any]],
        query_bindings: dict[str, dict[str, Any]],
    ) -> dict[str, Any] | None:
        variant = dict(variant)
        source_ref = str(primary.get("source_node_ref") or "")
        context_lines, action_line, context_codes = self._enclosing_context(
            source_ref, query_bindings=query_bindings
        )
        given = [*context_lines, *variant.get("given_lines", [])]
        if action_line and "handler executes" in action_line:
            given = [
                line
                for line in given
                if line != "the prerequisite statements complete successfully"
            ]

        null_symbols = self._null_symbols(given)
        if any(self._nullability.get(symbol) == "DEFINITELY_NON_NULL" for symbol in null_symbols):
            return None

        target = str(primary.get("target") or "").upper()
        value = self._unquote(primary.get("value_expression"))
        terminal_path = self._path_terminates_after_source(source_ref)
        if (
            not terminal_path
            and not (action_line and "handler executes" in action_line)
            and primary.get("effect_kind") == "OUT_PARAMETER_ASSIGNMENT"
            and any(token in target for token in ("DECISION", "STATUS", "RESULT"))
            and value
        ):
            later_transform = self._later_reachable_assignment(target, value, source_ref)
            if later_transform:
                given.append(
                    f"no later {self._identifier_words(target).lower()} transformation condition applies"
                )
                variant["analysis_status"] = "CONDITIONAL_TECHNICAL_CANDIDATE"

        then_lines = self._remove_nonterminal_point_values(
            list(variant.get("then_lines", [])),
            primary=primary,
            terminal_path=terminal_path,
        )
        then_lines.extend(
            self._composed_path_effects(
                bundle=bundle,
                primary=primary,
                effects=effects,
                nodes=nodes,
            )
        )
        handler_region = self._enclosing_handler_region(source_ref)
        if handler_region:
            semantics = self._handler_semantics_by_region.get(handler_region, {})
            if semantics and not semantics.get("original_condition_propagated", False):
                then_lines.append("the original SQL condition is not propagated to the caller")
        variant["given_lines"] = self._normalize_step_lines(given)
        variant["then_lines"] = self._normalize_step_lines(then_lines)
        if action_line:
            variant["action_line"] = action_line
        if context_codes and "analysis_status" not in variant:
            variant["analysis_status"] = "CONDITIONAL_TECHNICAL_CANDIDATE"
        variant["scenario_name"] = self._stable_scenario_name(
            variant.get("scenario_name", ""), variant["then_lines"]
        )
        return variant

    def _enclosing_context(
        self,
        source_ref: str,
        *,
        query_bindings: dict[str, dict[str, Any]],
    ) -> tuple[list[str], str | None, set[str]]:
        chain: list[dict[str, Any]] = []
        current = source_ref
        seen: set[str] = set()
        while current in self._parent_by_child and current not in seen:
            seen.add(current)
            parent_ref = self._parent_by_child[current]
            parent = self._nodes.get(parent_ref)
            if parent is None:
                break
            chain.append(parent)
            current = parent_ref
        chain.reverse()
        conditions: list[str] = []
        loop: dict[str, Any] | None = None
        handler: dict[str, Any] | None = None
        codes: set[str] = set(self._finding_codes_by_ref.get(source_ref, set()))
        if_arms = [node for node in chain if node.get("kind") == "IF_ARM"]
        # The innermost arm is already represented by the bundle predicate.
        for arm in if_arms[:-1]:
            condition = (arm.get("if_arm") or {}).get("condition_text")
            if condition:
                conditions.extend(
                    self._condition_lines(condition, query_bindings=query_bindings)
                )
        for node in chain:
            if node.get("kind") == "LOOP_REGION":
                loop = node
            elif node.get("kind") == "HANDLER_REGION":
                handler = node
            codes.update(self._finding_codes_by_ref.get(str(node.get("node_id")), set()))
        if handler is not None:
            region = handler.get("handler_region") or {}
            handled = self._one_line(region.get("handled_condition_text") or "SQL condition")
            if handled.upper() == "SQLEXCEPTION":
                conditions.insert(0, "an SQL exception occurs during procedure processing")
                return conditions, "the enclosing SQLEXCEPTION handler executes", codes
            conditions.insert(0, f"the {handled} condition occurs")
            return conditions, f"the enclosing {handled} handler executes", codes
        if loop is not None:
            text = self._one_line(loop.get("text") or "")
            cursor = re.search(r"\bFETCH\s+(?:LAST\s+FROM\s+|PRIOR\s+FROM\s+)?([A-Za-z_][A-Za-z0-9_$]*)", text, re.I)
            if cursor:
                cursor_name = cursor.group(1).upper()
                codes.update(self._finding_codes_for_cursor(cursor_name))
                return conditions, f"one {cursor_name} cursor row is evaluated", codes
            if (loop.get("loop_region") or {}).get("loop_kind") == "FOR":
                return conditions, "one implicit cursor row is evaluated", codes
            return conditions, "one loop iteration is evaluated", codes
        return conditions, None, codes

    def _path_terminates_after_source(self, source_ref: str) -> bool:
        source_offset = int(
            self._nodes.get(source_ref, {}).get("source_range", {}).get("start_offset", -1)
        )
        current = source_ref
        seen: set[str] = set()
        while current in self._parent_by_child and current not in seen:
            seen.add(current)
            current = self._parent_by_child[current]
            parent = self._nodes.get(current, {})
            if parent.get("kind") != "IF_ARM":
                continue
            arm = parent.get("if_arm") or {}
            for ref in self._descendant_refs(tuple(arm.get("body_node_refs", []))):
                node = self._nodes.get(ref, {})
                if int(node.get("source_range", {}).get("start_offset", -1)) <= source_offset:
                    continue
                if node.get("kind") in {"LEAVE", "RETURN", "RESIGNAL"}:
                    return True
            return False
        return False

    def _remove_nonterminal_point_values(
        self,
        lines: list[str],
        *,
        primary: dict[str, Any],
        terminal_path: bool,
    ) -> list[str]:
        if terminal_path:
            return lines
        source_ref = str(primary.get("source_node_ref") or "")
        source_offset = int(
            self._nodes.get(source_ref, {}).get("source_range", {}).get("start_offset", -1)
        )
        later_targets = {
            str(effect.get("target") or "").upper()
            for effect in self._effects.values()
            if effect.get("effect_kind") == "OUT_PARAMETER_ASSIGNMENT"
            and int(
                self._nodes.get(str(effect.get("source_node_ref") or ""), {})
                .get("source_range", {})
                .get("start_offset", -1)
            ) > source_offset
        }
        primary_target = str(primary.get("target") or "").upper()
        result: list[str] = []
        for line in lines:
            match = re.match(r"(P_[A-Za-z0-9_$]+) is set to ", line, re.I)
            if not match:
                result.append(line)
                continue
            target = match.group(1).upper()
            matching_offsets = [
                int(
                    self._nodes.get(str(effect.get("source_node_ref") or ""), {})
                    .get("source_range", {})
                    .get("start_offset", -1)
                )
                for effect in self._effects.values()
                if str(effect.get("target") or "").upper() == target
                and self._humanize_effect(effect) == line
            ]
            # A co-effect assigned at or after the primary is part of the same
            # behavior progression, not a stale point-in-time definition.
            if any(offset >= source_offset for offset in matching_offsets):
                result.append(line)
                continue
            if target != primary_target and target in later_targets:
                continue
            result.append(line)
        return result

    def _applicable_handler_binding(self, source_ref: str) -> dict[str, Any] | None:
        bindings = self._handler_bindings_by_source.get(source_ref, [])
        if not bindings:
            return None
        text = self._one_line(self._nodes.get(source_ref, {}).get("text") or "").upper()
        signal_name = re.search(r"\bSIGNAL\s+([A-Z_][A-Z0-9_$]*)", text)
        if signal_name and signal_name.group(1) != "SQLSTATE":
            exact = next(
                (
                    item
                    for item in bindings
                    if self._one_line(item.get("handled_condition_text") or "").upper()
                    == signal_name.group(1)
                ),
                None,
            )
            if exact is not None:
                return exact
        exact_sqlstate = re.search(r"\bSIGNAL\s+SQLSTATE\s+'([^']+)'", text)
        if exact_sqlstate:
            state = exact_sqlstate.group(1)
            exact = next(
                (
                    item
                    for item in bindings
                    if state in self._one_line(item.get("handled_condition_text") or "")
                ),
                None,
            )
            if exact is not None:
                return exact
        return next(
            (
                item
                for item in bindings
                if self._one_line(item.get("handled_condition_text") or "").upper()
                == "SQLEXCEPTION"
            ),
            bindings[0],
        )

    def _enclosing_handler_region(self, source_ref: str) -> str | None:
        current = source_ref
        seen: set[str] = set()
        while current in self._parent_by_child and current not in seen:
            seen.add(current)
            current = self._parent_by_child[current]
            node = self._nodes.get(current, {})
            if node.get("kind") == "HANDLER_REGION":
                return current
        return None

    def _finding_codes_for_cursor(self, cursor_name: str) -> set[str]:
        result: set[str] = set()
        for finding in self._findings:
            if cursor_name in self._one_line(finding.get("message") or "").upper():
                result.add(str(finding.get("code")))
        return result

    def _later_reachable_assignment(self, target: str, value: str, source_ref: str) -> bool:
        source = self._nodes.get(source_ref, {})
        offset = int(source.get("source_range", {}).get("start_offset", -1))
        source_regions = self._enclosing_regions(source_ref, "IF_REGION")
        for effect in self._effects.values():
            if effect.get("effect_kind") != "OUT_PARAMETER_ASSIGNMENT":
                continue
            if str(effect.get("target") or "").upper() != target:
                continue
            ref = str(effect.get("source_node_ref") or "")
            node = self._nodes.get(ref, {})
            if int(node.get("source_range", {}).get("start_offset", -1)) <= offset:
                continue
            # Assignments in another arm of the same ordered IF are mutually
            # exclusive, not later transformations of the selected outcome.
            if source_regions & self._enclosing_regions(ref, "IF_REGION"):
                continue
            if self._assignment_gate_accepts_value(ref, target, value):
                return True
        return False

    def _enclosing_regions(self, source_ref: str, kind: str) -> set[str]:
        result: set[str] = set()
        current = source_ref
        seen: set[str] = set()
        while current in self._parent_by_child and current not in seen:
            seen.add(current)
            current = self._parent_by_child[current]
            node = self._nodes.get(current, {})
            if node.get("kind") == kind:
                result.add(current)
        return result

    def _assignment_gate_accepts_value(self, source_ref: str, target: str, value: str) -> bool:
        current = source_ref
        while current in self._parent_by_child:
            parent_ref = self._parent_by_child[current]
            parent = self._nodes.get(parent_ref, {})
            if parent.get("kind") == "IF_ARM":
                condition = self._one_line((parent.get("if_arm") or {}).get("condition_text") or "")
                if re.search(rf"\b{re.escape(target)}\b", condition, re.I):
                    return self._condition_accepts_literal(condition, target, value)
            current = parent_ref
        return True

    @staticmethod
    def _condition_accepts_literal(condition: str, target: str, value: str) -> bool:
        in_match = re.search(
            rf"\b{re.escape(target)}\s+IN\s*\(([^)]*)\)", condition, re.I
        )
        if in_match:
            values = {item.strip().strip("'").upper() for item in in_match.group(1).split(",")}
            return value.upper() in values
        eq = re.search(rf"\b{re.escape(target)}\s*=\s*'([^']+)'", condition, re.I)
        return eq is None or eq.group(1).upper() == value.upper()

    def _composed_path_effects(
        self,
        *,
        bundle: dict[str, Any],
        primary: dict[str, Any],
        effects: dict[str, dict[str, Any]],
        nodes: dict[str, dict[str, Any]],
    ) -> list[str]:
        source_ref = str(primary.get("source_node_ref") or "")
        member_ids = {member.get("effect_ref") for member in bundle.get("effect_members", [])}
        selected: list[dict[str, Any]] = []
        prefix_lines: list[str] = []
        suffix_lines: list[str] = []
        sibling_assignment_lines: list[str] = []

        # Handler bodies terminate or resume according to handler semantics; do
        # not attach normal procedure-tail effects to the handler itself.
        if self._enclosing_regions(source_ref, "HANDLER_REGION"):
            return []

        if self._path_terminates_after_source(source_ref):
            return []

        # A condition-raising statement may be overlaid by its applicable
        # handler.  This composes validation SIGNALs with their externally
        # visible error outputs instead of emitting an intermediate signal only.
        binding = (
            self._applicable_handler_binding(source_ref)
            if primary.get("effect_kind") == "SIGNAL"
            else None
        )
        if binding is not None:
            handler_ref = str(binding.get("handler_region_ref") or "")
            handled = self._one_line(
                binding.get("handled_condition_text") or "SQL condition"
            )
            prefix_lines.append(f"the enclosing {handled} handler is activated")
            for ref in self._descendant_refs((handler_ref,)):
                selected.extend(
                    effect
                    for effect in effects.values()
                    if effect.get("source_node_ref") == ref
                )
            semantics = self._handler_semantics_by_region.get(handler_ref, {})
            if semantics and not semantics.get("original_condition_propagated", False):
                suffix_lines.append(
                    "the original SQL condition is not propagated to the caller"
                )

        # Preserve sibling state changes in the same IF arm. This is required
        # for branches such as approval-not-found, where the OUT parameter,
        # depth, and path are cleared together but are emitted as separate
        # effects by the semantic layer.
        parent_arm = self._parent_by_child.get(source_ref)
        if parent_arm and self._nodes.get(parent_arm, {}).get("kind") == "IF_ARM":
            for effect in effects.values():
                effect_ref = str(effect.get("source_node_ref") or "")
                if effect.get("effect_id") in member_ids or effect_ref == source_ref:
                    continue
                if self._parent_by_child.get(effect_ref) != parent_arm:
                    continue
                if effect.get("effect_kind") in {
                    "OUT_PARAMETER_ASSIGNMENT",
                    "STATE_ASSIGNMENT",
                }:
                    selected.append(effect)
            for ref in self._descendant_refs((parent_arm,)):
                if ref == source_ref:
                    continue
                node = self._nodes.get(ref, {})
                if node.get("kind") != "SET":
                    continue
                assignment = re.match(
                    r"\s*SET\s+([A-Za-z_][A-Za-z0-9_.$]*)\s*=\s*(.*?)\s*;?\s*$",
                    str(node.get("text") or ""),
                    re.IGNORECASE | re.DOTALL,
                )
                if assignment is not None:
                    sibling_assignment_lines.append(
                        f"{assignment.group(1).upper()} is set to "
                        f"{self._display_value(assignment.group(2))}"
                    )

        target = str(primary.get("target") or "").upper()
        value = self._unquote(primary.get("value_expression"))
        if (
            primary.get("effect_kind") == "OUT_PARAMETER_ASSIGNMENT"
            and target
            and value
            and any(token in target for token in ("DECISION", "STATUS", "RESULT"))
        ):
            selected.extend(self._downstream_branch_effects(target, value, source_ref, effects))

        accumulator_lines: list[str] = []
        if (
            primary.get("effect_kind") == "OUT_PARAMETER_ASSIGNMENT"
            and any(token in target for token in ("DECISION", "STATUS", "RESULT"))
        ):
            primary_offset = int(
                nodes.get(source_ref, {}).get("source_range", {}).get("start_offset", 0)
            )
            for effect in effects.values():
                if effect.get("effect_kind") != "OUT_PARAMETER_ASSIGNMENT":
                    continue
                accumulator = str(effect.get("target") or "").upper()
                expression = self._one_line(effect.get("value_expression") or "")
                effect_offset = int(
                    nodes.get(str(effect.get("source_node_ref") or ""), {})
                    .get("source_range", {})
                    .get("start_offset", 0)
                )
                if (
                    accumulator
                    and accumulator != target
                    and effect_offset < primary_offset
                    and re.search(rf"\b{re.escape(accumulator)}\b", expression, re.I)
                ):
                    accumulator_lines.append(
                        f"{accumulator} contains the accumulated value from completed loop iterations"
                    )

        primary_cfg = f"cfg:{source_ref}"
        for effect in effects.values():
            if effect.get("effect_id") in member_ids:
                continue
            kind = effect.get("effect_kind")
            if kind not in {"DML", "SEQUENCE_VALUE_ACQUISITION", "RESULT_SET_RETURN"}:
                continue
            effect_ref = str(effect.get("source_node_ref") or "")
            effect_cfg = f"cfg:{effect_ref}"
            if effect_cfg not in self._cfg_graph or primary_cfg not in self._cfg_graph:
                continue
            effect_node = nodes.get(effect_ref, {})
            primary_node = nodes.get(source_ref, {})
            effect_offset = int(effect_node.get("source_range", {}).get("start_offset", 0))
            primary_offset = int(primary_node.get("source_range", {}).get("start_offset", 0))
            if effect_offset <= primary_offset:
                continue
            if self._dominates(effect_cfg, primary_cfg, self._cfg_postdominators):
                selected.append(effect)

        unique = {item.get("effect_id"): item for item in selected if item.get("effect_id")}
        ordered = sorted(
            unique.values(),
            key=lambda item: int(
                nodes.get(str(item.get("source_node_ref") or ""), {})
                .get("source_range", {})
                .get("start_offset", 10**18)
            ),
        )
        lines = [
            *prefix_lines,
            *(self._humanize_effect(item) for item in ordered),
            *sibling_assignment_lines,
            *suffix_lines,
        ]
        lines.extend(accumulator_lines)
        if any(
            edge.get("atomicity") == "ATOMIC_COMPOUND"
            for edge in bundle.get("ordering_edges", [])
        ):
            lines.append(
                "all mutations in the atomic compound succeed together or are rolled back together"
            )
        return self._dedupe(lines)

    def _downstream_branch_effects(
        self,
        target: str,
        value: str,
        source_ref: str,
        effects: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        source_offset = int(
            self._nodes.get(source_ref, {}).get("source_range", {}).get("start_offset", 0)
        )
        effect_by_source: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for effect in effects.values():
            effect_by_source[str(effect.get("source_node_ref"))].append(effect)
        result: list[dict[str, Any]] = []
        for region in self._nodes.values():
            if region.get("kind") != "IF_REGION":
                continue
            if int(region.get("source_range", {}).get("start_offset", 0)) <= source_offset:
                continue
            arms = (region.get("if_region") or {}).get("arms", [])
            if not any(
                re.search(
                    rf"\b{re.escape(target)}\b",
                    str(arm.get("condition_text") or ""),
                    re.I,
                )
                for arm in arms
            ):
                continue
            chosen: dict[str, Any] | None = None
            fallback: dict[str, Any] | None = None
            for arm in arms:
                condition = self._one_line(arm.get("condition_text") or "")
                if not condition:
                    fallback = arm
                    continue
                if self._condition_accepts_literal(condition, target, value):
                    chosen = arm
                    break
            chosen = chosen or fallback
            if chosen is None:
                continue
            for ref in self._direct_descendant_refs(tuple(chosen.get("body_node_refs", []))):
                result.extend(effect_by_source.get(ref, []))
        return result

    def _direct_descendant_refs(self, roots: tuple[str, ...]) -> set[str]:
        result: set[str] = set()
        stack = list(roots)
        boundary_kinds = {"IF_REGION", "LOOP_REGION", "HANDLER_REGION"}
        while stack:
            ref = stack.pop()
            if ref in result:
                continue
            result.add(ref)
            node = self._nodes.get(ref, {})
            if node.get("kind") in boundary_kinds:
                continue
            stack.extend(node.get("child_refs", []))
        return result

    def _descendant_refs(self, roots: tuple[str, ...]) -> set[str]:
        result: set[str] = set()
        stack = list(roots)
        while stack:
            ref = stack.pop()
            if ref in result:
                continue
            result.add(ref)
            stack.extend(self._nodes.get(ref, {}).get("child_refs", []))
        return result

    @staticmethod
    def _dominates(candidate: str, target: str, immediate: dict[str, str]) -> bool:
        current = target
        seen: set[str] = set()
        while current in immediate and current not in seen:
            if current == candidate:
                return True
            seen.add(current)
            parent = immediate[current]
            if parent == current:
                break
            current = parent
        return current == candidate

    @staticmethod
    def _null_symbols(lines: list[str]) -> set[str]:
        result: set[str] = set()
        for line in lines:
            match = re.match(r"(?:the query-bound value for )?([A-Za-z_][A-Za-z0-9_.$]*) is null$", line, re.I)
            if match:
                result.add(match.group(1).upper())
        return result

    def _normalize_step_lines(self, lines: Iterable[str]) -> list[str]:
        normalized: list[str] = []
        for original in lines:
            line = self._one_line(original)
            comparison = re.match(
                r"((?:the query-bound value for )?([A-Za-z_][A-Za-z0-9_.$]*)) "
                r"(equals|does not equal|is at least|is at most|is greater than|is less than) "
                r"([-+]?\d+(?:\.\d+)?)$",
                line,
                re.I,
            )
            if comparison:
                label, symbol, words, raw = comparison.groups()
                line = f"{label} {words.lower()} {self._format_numeric(symbol, raw)}"
            normalized.append(line)

        nulls = self._null_symbols(normalized)
        if nulls:
            filtered: list[str] = []
            for line in normalized:
                comparison_symbol = re.match(
                    r"(?:the query-bound value for )?([A-Za-z_][A-Za-z0-9_.$]*) "
                    r"(?:equals|does not equal|is at least|is at most|is greater than|is less than) ",
                    line,
                    re.I,
                )
                if comparison_symbol and comparison_symbol.group(1).upper() in nulls:
                    continue
                filtered.append(line)
            normalized = filtered

        result: list[str] = []
        seen: set[str] = set()
        for line in normalized:
            key = re.sub(r"(?<=\d)\.0+(?=\b)", "", line).casefold()
            if key in seen:
                continue
            seen.add(key)
            result.append(line)
        return result

    def _format_numeric(self, symbol: str, raw: str) -> str:
        type_info = self._symbol_types.get(symbol.upper(), {})
        family = str(type_info.get("family") or "")
        try:
            value = Decimal(raw)
        except InvalidOperation:
            return raw
        if family in {"INTEGER", "SMALL_INTEGER", "BIG_INTEGER"}:
            return str(int(value))
        if family == "DECIMAL" and type_info.get("scale") is not None:
            scale = int(type_info["scale"])
            return f"{value:.{scale}f}"
        return format(value.normalize(), "f")

    @staticmethod
    def _stable_scenario_name(name: str, then_lines: list[str]) -> str:
        text = " ".join(str(name or "").split())
        if text and not text.lower().startswith("readable technical behavior") and len(text) <= 140:
            return text
        if not then_lines:
            return "Review the extracted technical behavior"
        first = then_lines[0]
        mutation = re.match(r"the database mutation on ([A-Za-z0-9_.$]+) occurs", first, re.I)
        if mutation:
            return f"Apply the {mutation.group(1).upper()} database change"
        result_set = re.match(r"the (.+) result set is returned", first, re.I)
        if result_set:
            return f"Return the {result_set.group(1)} result set"
        return first[0].upper() + first[1:]

    def _behavior_variants(
        self,
        *,
        qualified: str,
        bundle: dict[str, Any],
        primary: dict[str, Any],
        effects: dict[str, dict[str, Any]],
        nodes: dict[str, dict[str, Any]],
        query_bindings: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        del qualified
        target = str(primary.get("target") or "").upper()
        control = str(bundle.get("controlling_region_ref") or "")
        if (
            control.startswith("if-arm:")
            and primary.get("effect_kind") == "OUT_PARAMETER_ASSIGNMENT"
            and any(token in target for token in ("DECISION", "STATUS", "RESULT"))
        ):
            variants = self._ordered_decision_variants(
                bundle=bundle,
                primary=primary,
                effects=effects,
                nodes=nodes,
                query_bindings=query_bindings,
            )
            if variants:
                return variants
        expression = self._one_line(primary.get("value_expression") or "")
        if (
            primary.get("effect_kind") == "OUT_PARAMETER_ASSIGNMENT"
            and "SCORE" in target
            and re.search(r"\bROUND\s*\(", expression, flags=re.IGNORECASE)
        ):
            return [
                self._variant(
                    "rounded-score",
                    self._bundle_source_order(bundle, effects, nodes),
                    "Computed output",
                    f"Return the rounded computed {self._identifier_words(target).lower()}",
                    [
                        "the required query-bound inputs are available",
                        "the preceding calculations complete successfully",
                    ],
                    self._bundle_then_lines(bundle, effects),
                )
            ]
        return [self._generic_variant(bundle, primary, effects, nodes)]

    def _ordered_decision_variants(
        self,
        *,
        bundle: dict[str, Any],
        primary: dict[str, Any],
        effects: dict[str, dict[str, Any]],
        nodes: dict[str, dict[str, Any]],
        query_bindings: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        control = str(bundle.get("controlling_region_ref") or "")
        parts = control.split(":")
        if len(parts) < 4:
            return []
        region = nodes.get(parts[1])
        try:
            arm_index = int(parts[2])
        except ValueError:
            return []
        arms = (region or {}).get("if_region", {}).get("arms", [])
        if arm_index >= len(arms):
            return []
        arm = arms[arm_index]
        value = self._unquote(primary.get("value_expression"))
        rule_name, scenario_name = self._outcome_labels(
            str(primary.get("target") or ""), value
        )
        then_lines = self._bundle_then_lines(bundle, effects)
        source_order = int(arm.get("source_range", {}).get("start_line", 0)) * 10

        if arm_index == 0:
            return [
                self._variant(
                    "ordered-arm-0",
                    source_order,
                    rule_name,
                    scenario_name,
                    self._decision_given(
                        self._condition_lines(
                            arm.get("condition_text"), query_bindings=query_bindings
                        )
                    ),
                    then_lines,
                )
            ]

        current_threshold = self._simple_threshold(arm.get("condition_text"))
        if current_threshold is not None and arm_index > 0:
            previous_pattern = self._threshold_with_exception(
                arms[arm_index - 1].get("condition_text")
            )
            if (
                previous_pattern is not None
                and previous_pattern[0] == current_threshold[0]
                and previous_pattern[2] > current_threshold[2]
            ):
                symbol, _operator, lower = current_threshold
                _same_symbol, _previous_operator, upper, exception_text = previous_pattern
                prior = self._negated_prior_lines(
                    arms[: arm_index - 1],
                    query_bindings=query_bindings,
                    excluded_symbol=symbol,
                )
                high_with_exception = [
                    *prior,
                    self._comparison_line(symbol, ">", upper, query_bindings),
                    *self._condition_lines(
                        exception_text,
                        query_bindings=query_bindings,
                        negate=True,
                    ),
                ]
                bounded_range = [
                    *prior,
                    self._comparison_line(symbol, ">", lower, query_bindings),
                    self._comparison_line(symbol, "<=", upper, query_bindings),
                ]
                return [
                    self._variant(
                        "higher-threshold-exception-fallthrough",
                        source_order,
                        rule_name,
                        self._variant_scenario_name(
                            scenario_name, "with the preceding exception condition"
                        ),
                        self._decision_given(high_with_exception),
                        then_lines,
                    ),
                    self._variant(
                        "bounded-threshold-range",
                        source_order + 1,
                        rule_name,
                        self._variant_scenario_name(
                            scenario_name,
                            f"when {self._identifier_words(symbol).lower()} is within the next decision range",
                        ),
                        self._decision_given(bounded_range),
                        then_lines,
                    ),
                ]

        latest_threshold = self._latest_simple_threshold(arms, arm_index)
        if latest_threshold is not None:
            threshold_index, symbol, _operator, boundary = latest_threshold
            prior = self._negated_prior_lines(
                arms[:threshold_index],
                query_bindings=query_bindings,
                excluded_symbol=symbol,
            )
            if arm.get("arm_kind") == "ELSE":
                current_lines = self._condition_lines(
                    arms[arm_index - 1].get("condition_text"),
                    query_bindings=query_bindings,
                    negate=True,
                )
            else:
                current_lines = self._condition_lines(
                    arm.get("condition_text"), query_bindings=query_bindings
                )
            normal = [
                *prior,
                self._comparison_line(symbol, "<=", boundary, query_bindings),
                *current_lines,
            ]
            nullable = [
                *prior,
                f"{self._symbol_label(symbol, query_bindings)} is null",
                *current_lines,
            ]
            nullable_then = self._null_output_then_lines(then_lines, symbol)
            return [
                self._variant(
                    "lower-or-equal-threshold",
                    source_order,
                    rule_name,
                    scenario_name,
                    self._decision_given(normal),
                    then_lines,
                ),
                self._variant(
                    "null-threshold-input",
                    source_order + 1,
                    rule_name,
                    self._variant_scenario_name(
                        scenario_name,
                        f"when {self._identifier_words(symbol).lower()} is null",
                    ),
                    self._decision_given(nullable),
                    nullable_then,
                ),
            ]

        given = self._negated_prior_lines(
            arms[:arm_index], query_bindings=query_bindings
        )
        if arm.get("arm_kind") != "ELSE":
            given.extend(
                self._condition_lines(
                    arm.get("condition_text"), query_bindings=query_bindings
                )
            )
        elif not given:
            given.append("none of the preceding ordered conditions evaluates true")
        return [
            self._variant(
                f"ordered-arm-{arm_index}",
                source_order,
                rule_name,
                scenario_name,
                self._decision_given(given),
                then_lines,
            )
        ]

    @staticmethod
    def _decision_given(lines: list[str]) -> list[str]:
        prerequisite = "the preceding procedure statements complete successfully"
        return [*lines, prerequisite] if prerequisite not in lines else lines

    @staticmethod
    def _null_output_then_lines(lines: list[str], symbol: str) -> list[str]:
        prefix = f"{symbol} is set to"
        return [
            f"{symbol} is set to null" if line.startswith(prefix) else line
            for line in lines
        ]

    def _negated_prior_lines(
        self,
        arms: list[dict[str, Any]],
        *,
        query_bindings: dict[str, dict[str, Any]],
        excluded_symbol: str | None = None,
    ) -> list[str]:
        result: list[str] = []
        for arm in arms:
            condition = arm.get("condition_text")
            if not condition:
                continue
            if excluded_symbol and re.search(
                rf"\b{re.escape(excluded_symbol)}\b", condition, flags=re.IGNORECASE
            ):
                continue
            result.extend(
                self._condition_lines(
                    condition,
                    query_bindings=query_bindings,
                    negate=True,
                )
            )
        return self._dedupe(result)

    def _condition_lines(
        self,
        condition: Any,
        *,
        query_bindings: dict[str, dict[str, Any]],
        negate: bool = False,
    ) -> list[str]:
        text = self._one_line(condition or "")
        if not text:
            return []
        terms = self._split_top_level_and(text)
        if negate and len(terms) > 1:
            positive = [
                self._humanize_atomic(
                    term,
                    query_bindings=query_bindings,
                    negate=False,
                )
                for term in terms
            ]
            return [
                "at least one of the following conditions is false or unknown: "
                + "; ".join(positive)
            ]
        return [
            self._humanize_atomic(
                term,
                query_bindings=query_bindings,
                negate=negate,
            )
            for term in terms
        ]

    def _humanize_atomic(
        self,
        expression: str,
        *,
        query_bindings: dict[str, dict[str, Any]],
        negate: bool,
    ) -> str:
        text = self._one_line(expression)
        alternatives = self._split_top_level_or(text)
        if len(alternatives) > 1:
            rendered = [
                self._humanize_atomic(
                    item, query_bindings=query_bindings, negate=negate
                )
                for item in alternatives
            ]
            return "either " + " or ".join(rendered)
        ratio = re.fullmatch(
            r"([A-Za-z_][A-Za-z0-9_.$]*)\s*>\s*([A-Za-z_][A-Za-z0-9_.$]*)\s*\*\s*1\.25",
            text, re.I
        )
        if ratio and not negate:
            return (
                f"{ratio.group(1)} exceeds 125 percent of {ratio.group(2)}"
            )
        exists = re.fullmatch(r"(NOT\s+)?EXISTS\s*\((SELECT.*)\)", text, flags=re.IGNORECASE)
        if exists:
            originally_negated = bool(exists.group(1))
            positive_exists = not originally_negated
            if negate:
                positive_exists = not positive_exists
            return self._exists_line(exists.group(2), positive_exists)

        count_match = re.fullmatch(
            r"\(\s*SELECT\s+COUNT\s*\(\s*\*\s*\)\s+FROM\s+([A-Za-z_][A-Za-z0-9_.$]*)\s+.*\)\s*(>=|>|<=|<|=|<>)\s*([0-9.]+)",
            text,
            flags=re.IGNORECASE,
        )
        if count_match:
            relation, operator, value = count_match.groups()
            if negate:
                operator = self._negated_operator(operator)
            verified = re.search(r"\bSTATUS\s*=\s*'([^']+)'", text, flags=re.IGNORECASE)
            qualifier = (
                f' with STATUS equal to "{verified.group(1)}"' if verified else ""
            )
            return (
                f"the {relation.upper()} query row count{qualifier} "
                f"{self._operator_words(operator)} {value}"
            )

        simple = re.fullmatch(
            r"([A-Za-z_][A-Za-z0-9_.$]*)\s*(=|<>|>=|<=|>|<)\s*(.+)", text
        )
        if simple:
            left, operator, right = simple.groups()
            if negate:
                operator = self._negated_operator(operator)
            lookup = self._lookup_equality_line(
                left,
                operator,
                right,
                query_bindings=query_bindings,
            )
            if lookup is not None:
                return lookup
            displayed = self._display_value(right)
            if re.fullmatch(r"[-+]?\d+(?:\.\d+)?", self._one_line(right)):
                displayed = self._format_numeric(left, self._one_line(right))
            return (
                f"{self._symbol_label(left, query_bindings)} "
                f"{self._operator_words(operator)} {displayed}"
            )
        return (
            f'the technical condition "{text}" '
            f"{'does not evaluate true' if negate else 'holds'}"
        )

    def _lookup_equality_line(
        self,
        symbol: str,
        operator: str,
        right: str,
        *,
        query_bindings: dict[str, dict[str, Any]],
    ) -> str | None:
        binding = query_bindings.get(symbol.upper())
        if binding is None or operator not in {"=", "<>"}:
            return None
        projection = self._one_line(binding.get("projection_expression") or "")
        scalar = re.search(
            r"\(\s*SELECT\s+('(?:''|[^'])*')\s+FROM\s+([A-Za-z_][A-Za-z0-9_.$]*)\b(.*?)\)",
            projection,
            flags=re.IGNORECASE,
        )
        if scalar is None or self._one_line(right) != scalar.group(1):
            return None
        _selected, relation, body = scalar.groups()
        filter_match = re.search(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*('(?:''|[^'])*')",
            body,
            flags=re.IGNORECASE,
        )
        filter_text = "the query-bound filters"
        if filter_match:
            filter_text = (
                f"{filter_match.group(1).upper()} equals "
                f"{self._display_value(filter_match.group(2))}"
            )
        if operator == "=":
            return f"the {relation.upper()} lookup finds a row where {filter_text}"
        return f"the {relation.upper()} lookup does not find a row where {filter_text}"

    def _symbol_label(
        self, symbol: str, query_bindings: dict[str, dict[str, Any]]
    ) -> str:
        binding = query_bindings.get(symbol.upper())
        if binding is None:
            return symbol
        projection = self._one_line(binding.get("projection_expression") or "")
        summary = binding.get("query_summary") or {}
        relations = [str(value).upper() for value in summary.get("relation_refs", [])]
        base_relation = relations[0] if relations else "query"
        if re.match(r"COUNT\s*\(", projection, flags=re.IGNORECASE):
            return f"the qualifying {base_relation} row count"
        average = re.match(r"AVG\s*\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*)", projection, flags=re.IGNORECASE)
        if average:
            return f"the qualifying average {average.group(1).upper()}"
        return f"the query-bound value for {symbol}"

    @staticmethod
    def _split_top_level_or(text: str) -> list[str]:
        result: list[str] = []
        start = 0
        depth = 0
        quote: str | None = None
        index = 0
        while index < len(text):
            char = text[index]
            if quote:
                if char == quote:
                    if index + 1 < len(text) and text[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
                index += 1
                continue
            if char == '(':
                depth += 1
            elif char == ')':
                depth = max(0, depth - 1)
            elif depth == 0:
                match = re.match(r"\s+OR\s+", text[index:], flags=re.IGNORECASE)
                if match:
                    result.append(text[start:index].strip())
                    index += match.end()
                    start = index
                    continue
            index += 1
        result.append(text[start:].strip())
        return [item for item in result if item]

    @staticmethod
    def _split_top_level_and(text: str) -> list[str]:
        result: list[str] = []
        start = 0
        depth = 0
        quote: str | None = None
        index = 0
        while index < len(text):
            char = text[index]
            if quote:
                if char == quote:
                    if index + 1 < len(text) and text[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
                index += 1
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth = max(0, depth - 1)
            elif depth == 0:
                match = re.match(r"\s+AND\s+", text[index:], flags=re.IGNORECASE)
                if match:
                    result.append(text[start:index].strip())
                    index += match.end()
                    start = index
                    continue
            index += 1
        result.append(text[start:].strip())
        return [item for item in result if item]

    @staticmethod
    def _simple_threshold(condition: Any) -> tuple[str, str, float] | None:
        text = " ".join(str(condition or "").split())
        match = re.fullmatch(
            r"([A-Za-z_][A-Za-z0-9_.$]*)\s*(>|>=)\s*([0-9]+(?:\.[0-9]+)?)",
            text,
        )
        if match is None:
            return None
        return match.group(1).upper(), match.group(2), float(match.group(3))

    def _threshold_with_exception(
        self, condition: Any
    ) -> tuple[str, str, float, str] | None:
        terms = self._split_top_level_and(self._one_line(condition or ""))
        threshold: tuple[str, str, float] | None = None
        exception: str | None = None
        for term in terms:
            candidate = self._simple_threshold(term)
            if candidate is not None:
                threshold = candidate
            elif re.match(r"NOT\s+EXISTS\b", term, flags=re.IGNORECASE):
                exception = term
        if threshold is None or exception is None:
            return None
        return (*threshold, exception)

    def _latest_simple_threshold(
        self, arms: list[dict[str, Any]], current_index: int
    ) -> tuple[int, str, str, float] | None:
        for index in range(current_index - 1, -1, -1):
            threshold = self._simple_threshold(arms[index].get("condition_text"))
            if threshold is not None:
                return index, *threshold
        return None

    def _comparison_line(
        self,
        symbol: str,
        operator: str,
        value: float,
        query_bindings: dict[str, dict[str, Any]],
    ) -> str:
        displayed = f"{value:.2f}" if not value.is_integer() else f"{value:.2f}"
        return (
            f"{self._symbol_label(symbol, query_bindings)} "
            f"{self._operator_words(operator)} {displayed}"
        )

    @staticmethod
    def _negated_operator(operator: str) -> str:
        return {
            "=": "<>",
            "<>": "=",
            ">": "<=",
            ">=": "<",
            "<": ">=",
            "<=": ">",
        }[operator]

    @staticmethod
    def _operator_words(operator: str) -> str:
        return {
            "=": "equals",
            "<>": "does not equal",
            ">=": "is at least",
            "<=": "is at most",
            ">": "is greater than",
            "<": "is less than",
        }[operator]

    @classmethod
    def _exists_line(cls, select_text: str, positive: bool) -> str:
        relation = re.search(
            r"\bFROM\s+([A-Za-z_][A-Za-z0-9_.$]*)",
            select_text,
            flags=re.IGNORECASE,
        )
        relation_name = relation.group(1).upper() if relation else "referenced relation"
        approved = re.search(
            r"\bAPPROVED\s*=\s*'Y'", select_text, flags=re.IGNORECASE
        )
        qualifier = "approved " if approved else "matching "
        if positive:
            return f"an {qualifier}{relation_name} row exists for the referenced keys"
        return f"no {qualifier}{relation_name} row exists for the referenced keys"

    @classmethod
    def _outcome_labels(cls, target: str, value: str) -> tuple[str, str]:
        normalized = value.upper()
        words = cls._identifier_words(normalized).lower()
        if normalized.startswith("REJECTED_"):
            reason = cls._identifier_words(normalized.removeprefix("REJECTED_")).lower()
            readable_reason = cls._hyphenate_phrase(reason)
            return (
                f"{cls._title_phrase(reason)} decision",
                f"Reject when the {readable_reason} condition applies",
            )
        if normalized == "MANUAL_REVIEW":
            return "Manual-review decision", "Send the case to manual review"
        if normalized.startswith("APPROVED_WITH_"):
            suffix = cls._identifier_words(normalized.removeprefix("APPROVED_WITH_")).lower()
            return f"Approval with {suffix}", f"Approve an eligible case with {suffix}"
        if normalized == "APPROVED":
            return "Standard approval", "Approve when no earlier decision condition applies"
        return f"{cls._identifier_words(target).title()} outcome", f"Set {target} to {words}"

    @staticmethod
    def _variant_scenario_name(base: str, suffix: str) -> str:
        if " when " in base.lower() and suffix.lower().startswith("when "):
            null_match = re.fullmatch(r"when (.+) is null", suffix, flags=re.IGNORECASE)
            if null_match:
                return f"{base} with a null {null_match.group(1)}"
            return f"{base} with {suffix[5:]}"
        return f"{base} {suffix}"

    @staticmethod
    def _identifier_words(value: str) -> str:
        parts = [part for part in value.strip("_").split("_") if part]
        if len(parts) > 1 and parts[0].upper() in {"P", "V"}:
            parts = parts[1:]
        return " ".join(parts)

    @staticmethod
    def _title_phrase(value: str) -> str:
        return ReadableCandidateRenderer._hyphenate_phrase(value).title().replace(
            "-Risk", "-risk"
        )

    @staticmethod
    def _hyphenate_phrase(value: str) -> str:
        words = value.split()
        if len(words) == 2 and words[-1].lower() == "risk":
            return f"{words[0]}-{words[1]}"
        return value


    def _generic_variant(
        self,
        bundle: dict[str, Any],
        primary: dict[str, Any],
        effects: dict[str, dict[str, Any]],
        nodes: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        controlling = str(bundle.get("controlling_region_ref") or "")
        given: list[str] = []
        order = self._bundle_source_order(bundle, effects, nodes)
        kind = str(primary.get("effect_kind") or "")
        target = str(primary.get("target") or "")
        source_ref = str(primary.get("source_node_ref") or "")
        handler_regions = self._enclosing_regions(source_ref, "HANDLER_REGION")
        if handler_regions:
            rule = "Exception handling"
        elif kind in {"SIGNAL", "RESIGNAL"}:
            rule = "Condition handling"
        elif kind == "RESULT_SET_RETURN":
            rule = "Returned result set"
        elif kind == "SEQUENCE_VALUE_ACQUISITION":
            rule = "Sequence advancement"
        elif kind == "DML":
            rule = f"{self._identifier_words(target).title()} persistence" if target else "Database effects"
        elif kind == "STATE_ASSIGNMENT":
            rule = "State accumulation"
        elif kind == "OUT_PARAMETER_ASSIGNMENT":
            rule = f"{self._identifier_words(target).title()} output"
        else:
            rule = "Technical effects"
        if controlling.startswith("if-arm:"):
            parts = controlling.split(":")
            if len(parts) >= 4:
                region = nodes.get(parts[1])
                arm_index = int(parts[2])
                arms = (region or {}).get("if_region", {}).get("arms", [])
                for preceding in arms[:arm_index]:
                    condition = preceding.get("condition_text")
                    if condition:
                        given.extend(
                            self._condition_lines(
                                condition, query_bindings={}, negate=True
                            )
                        )
                if arm_index < len(arms):
                    current = arms[arm_index]
                    condition = current.get("condition_text")
                    if condition:
                        given.extend(self._condition_lines(condition, query_bindings={}))
                    elif current.get("arm_kind") == "ELSE":
                        given.append("none of the preceding ordered conditions evaluates true")
                if kind == "OUT_PARAMETER_ASSIGNMENT":
                    rule = "Ordered decision behavior"

        if handler_regions and target == "P_FINAL_DECISION":
            rule = "Unexpected SQL exception handling"
            scenario_name = "Convert an unexpected SQL exception into error outputs"
            if not given:
                given.append("an SQL exception occurs during procedure processing")
            then_lines = self._bundle_then_lines(bundle, effects)
            return self._variant(
                "unexpected-sql-exception",
                order,
                rule,
                scenario_name,
                given,
                then_lines,
            )

        if (
            target == "P_APPROVER_ID"
            and self._one_line(primary.get("value_expression") or "").upper() == "NULL"
            and any("V_APPROVER_NOT_FOUND" in line.upper() for line in given)
        ):
            rule = "Approval lookup"
            scenario_name = "Continue without an approver when no qualified approver exists"
            then_lines = self._bundle_then_lines(bundle, effects)
            return self._variant(
                "approval-not-found",
                order,
                rule,
                scenario_name,
                given,
                then_lines,
            )
        if not given:
            given.append("the prerequisite statements complete successfully")
        then_lines = self._bundle_then_lines(bundle, effects)
        scenario_name = self._scenario_name(then_lines, bundle["bundle_id"])
        return self._variant(
            "default", order, rule, scenario_name, given, then_lines
        )

    def _bundle_then_lines(
        self, bundle: dict[str, Any], effects: dict[str, dict[str, Any]]
    ) -> list[str]:
        members = [
            effects[member["effect_ref"]]
            for member in bundle.get("effect_members", [])
            if member.get("effect_ref") in effects
        ]
        members.sort(key=self._effect_display_priority)
        return self._dedupe([self._humanize_effect(effect) for effect in members])

    def _variant(
        self,
        key: str,
        order: int,
        rule: str,
        scenario: str,
        given: list[str],
        then: list[str],
    ) -> dict[str, Any]:
        normalized_given = self._normalize_step_lines(given)
        normalized_then = self._normalize_step_lines(then)
        return {
            "variant_key": key,
            "display_order": order,
            "rule_name": rule,
            "scenario_name": self._stable_scenario_name(scenario, normalized_then),
            "given_lines": normalized_given,
            "then_lines": normalized_then,
        }

    @classmethod
    def _humanize_predicate(cls, expression: str) -> str:
        text = cls._one_line(expression)
        simple = re.fullmatch(
            r"([A-Za-z_][A-Za-z0-9_.$]*)\s*(=|<>|>=|<=|>|<)\s*(.+)", text
        )
        if simple:
            left, operator, right = simple.groups()
            words = {
                "=": "equals",
                "<>": "does not equal",
                ">=": "is at least",
                "<=": "is at most",
                ">": "is greater than",
                "<": "is less than",
            }
            return f"{left} {words[operator]} {cls._display_value(right)}"
        return f'the technical condition "{text}" holds'

    def _humanize_effect(self, effect: dict[str, Any]) -> str:
        kind = effect.get("effect_kind")
        target = str(effect.get("target") or "")
        value = effect.get("value_expression")
        source_ref = str(effect.get("source_node_ref") or "")
        text = self._one_line(self._nodes.get(source_ref, {}).get("text") or "")
        if kind == "OUT_PARAMETER_ASSIGNMENT" and target:
            if target == "P_CONFIDENCE_SCORE" and value:
                return "P_CONFIDENCE_SCORE is set to the rounded computed confidence score"
            if str(value or "").startswith("SELECT_INTO_PROJECTION_"):
                return f"{target} is set to the value selected by the query"
            return f"{target} is set to {self._display_value(value)}"
        if kind == "STATE_ASSIGNMENT" and target:
            return f"{target} is set to {self._display_value(value)}"
        if kind == "DML" and target:
            if value == "FINAL_TABLE_INSERT_WITH_RETURNED_ROW":
                return f"a {target} row is inserted and its generated row is returned by FINAL TABLE"
            update = re.search(
                r"\bUPDATE\s+([A-Za-z_][A-Za-z0-9_.$]*)\s+SET\s+(.*?)(?:\s+WHERE\b|$)",
                text, re.I
            )
            if update:
                assignments = [self._one_line(item) for item in self._split_top_level_commas(update.group(2))]
                detail = "; ".join(item.replace("=", " is set to ", 1) for item in assignments[:6])
                return f"the {target} row is updated ({detail})"
            insert = re.search(
                r"\bINSERT\s+INTO\s+[A-Za-z_][A-Za-z0-9_.$]*\s*\((.*?)\)\s*VALUES\s*\((.*?)\)",
                text, re.I
            )
            if insert:
                columns = [item.strip().upper() for item in self._split_top_level_commas(insert.group(1))]
                values = [self._one_line(item) for item in self._split_top_level_commas(insert.group(2))]
                pairs = "; ".join(f"{column} = {val}" for column, val in list(zip(columns, values))[:6])
                article = "an" if target[:1].upper() in {"A", "E", "I", "O", "U"} else "a"
                return f"{article} {target} row is inserted ({pairs})"
            if re.search(r"\bDELETE\s+FROM\b", text, re.I):
                return f"the matching {target} row is deleted"
            if re.search(r"\bMERGE\s+INTO\b", text, re.I):
                return f"the {target} row is inserted or updated by MERGE"
            return f"the database mutation on {target} occurs"
        if kind == "RESULT_SET_RETURN" and target:
            return f"the {target} result set is returned to the client"
        if kind == "SEQUENCE_VALUE_ACQUISITION" and target:
            return f"the next value from sequence {target} is acquired and advances sequence state"
        if kind == "DYNAMIC_SQL":
            return "the tenant-specific prepared query is executed"
        if kind == "SIGNAL":
            state = re.search(r"SQLSTATE\s+'([^']+)'", str(value or text), re.I)
            return f"SQLSTATE {state.group(1)} is raised internally" if state else "the declared SQL condition is raised internally"
        if kind == "RESIGNAL":
            state = re.search(r"SQLSTATE\s+'([^']+)'", str(value or text), re.I)
            return f"SQLSTATE {state.group(1)} is re-signalled to the caller" if state else "the SQL condition is re-signalled to the caller"
        if kind == "ROLLBACK":
            savepoint = re.search(r"ROLLBACK\s+TO\s+SAVEPOINT\s+([A-Za-z_][A-Za-z0-9_$]*)", text, re.I)
            return f"changes after savepoint {savepoint.group(1).upper()} are rolled back" if savepoint else "the transaction rollback effect occurs"
        target_text = f" on {target}" if target else ""
        return f"the {str(kind or 'technical').lower()} effect{target_text} occurs"

    @staticmethod
    def _split_top_level_commas(text: str) -> list[str]:
        result: list[str] = []
        start = 0
        depth = 0
        quote: str | None = None
        index = 0
        while index < len(text):
            char = text[index]
            if quote:
                if char == quote:
                    if index + 1 < len(text) and text[index + 1] == quote:
                        index += 2
                        continue
                    quote = None
                index += 1
                continue
            if char in {"'", '"'}:
                quote = char
            elif char == '(':
                depth += 1
            elif char == ')':
                depth = max(0, depth - 1)
            elif char == ',' and depth == 0:
                result.append(text[start:index].strip())
                start = index + 1
            index += 1
        result.append(text[start:].strip())
        return [item for item in result if item]

    @staticmethod
    def _display_value(value: Any) -> str:
        if value is None:
            return "the computed value"
        text = " ".join(str(value).strip().split())
        if text.upper() == "NULL":
            return "null"
        if len(text) >= 2 and text[0] == "'" and text[-1] == "'":
            return f'"{text[1:-1].replace(chr(34), chr(92) + chr(34))}"'
        return text

    @staticmethod
    def _unquote(value: Any) -> str:
        text = "" if value is None else str(value).strip()
        if len(text) >= 2 and text[0] == "'" and text[-1] == "'":
            return text[1:-1]
        return text

    @staticmethod
    def _effect_display_priority(effect: dict[str, Any]) -> tuple[int, str]:
        target = str(effect.get("target") or "").upper()
        if any(token in target for token in ("FINAL", "DECISION", "STATUS", "RESULT")):
            return (0, target)
        if "SCORE" in target:
            return (1, target)
        if "FLAG" in target:
            return (2, target)
        return (3, target)

    @classmethod
    def _scenario_name(cls, then_lines: list[str], bundle_id: str) -> str:
        if then_lines:
            summary = " and ".join(then_lines)
            summary = summary[0].upper() + summary[1:]
            if len(summary) <= 150:
                return summary
        return f"Readable technical behavior {bundle_id[-12:]}"

    @classmethod
    def _scenario_body(
        cls,
        *,
        scenario_name: str,
        given_lines: list[str],
        action_line: str,
        then_lines: list[str],
        indent: int,
        scenario_tags: list[str] | None = None,
    ) -> str:
        prefix = " " * indent
        step_prefix = " " * (indent + 2)
        lines: list[str] = []
        for tag in scenario_tags or []:
            lines.append(f"{prefix}{tag}")
        lines.append(f"{prefix}Scenario: {scenario_name}")
        for index, line in enumerate(given_lines):
            lines.append(f"{step_prefix}{'Given' if index == 0 else 'And'} {line}")
        lines.append(f"{step_prefix}When {action_line}")
        for index, line in enumerate(then_lines):
            lines.append(f"{step_prefix}{'Then' if index == 0 else 'And'} {line}")
        return "\n".join(lines)

    @classmethod
    def _scenario_outline_body(
        cls,
        *,
        scenario_name: str,
        given_lines: list[str],
        action_line: str,
        then_lines: list[str],
        examples: list[tuple[str, str]],
        indent: int,
        scenario_tags: list[str] | None = None,
    ) -> str:
        prefix = " " * indent
        step_prefix = " " * (indent + 2)
        table_prefix = " " * (indent + 4)
        lines: list[str] = []
        for tag in scenario_tags or []:
            lines.append(f"{prefix}{tag}")
        lines.append(f"{prefix}Scenario Outline: {scenario_name}")
        for index, line in enumerate(given_lines):
            lines.append(f"{step_prefix}{'Given' if index == 0 else 'And'} {line}")
        lines.append(f"{step_prefix}When {action_line}")
        for index, line in enumerate(then_lines):
            lines.append(f"{step_prefix}{'Then' if index == 0 else 'And'} {line}")
        lines.extend(
            [
                "",
                f"{step_prefix}Examples:",
                f"{table_prefix}| invalid_input | sqlstate |",
            ]
        )
        for invalid_input, sqlstate in examples:
            lines.append(
                f'{table_prefix}| {invalid_input} | "{sqlstate}" |'
            )
        return "\n".join(lines)

    @classmethod
    def _single_feature_text(cls, qualified: str, rule_name: str, scenario_body: str) -> str:
        return (
            f"{cls.FEATURE_TAGS}\n"
            f"Feature: {qualified} readable technical candidates\n\n"
            f"  Rule: {rule_name}\n\n"
            f"{scenario_body}\n"
        )

    @classmethod
    def _combined_feature_text(
        cls, qualified: str, entries: Iterable[dict[str, Any]]
    ) -> str:
        values = list(entries)
        lines = [
            cls.FEATURE_TAGS,
            f"Feature: {qualified} readable technical candidates",
        ]
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        first_order: dict[str, tuple[int, str]] = {}
        for entry in values:
            rule = entry["rule_name"]
            grouped[rule].append(entry)
            first_order.setdefault(rule, (int(entry["display_order"]), rule))
        for rule in sorted(grouped, key=lambda value: first_order[value]):
            lines.extend(["", f"  Rule: {rule}", ""])
            for entry in sorted(
                grouped[rule], key=lambda item: (item["display_order"], item["proposal_id"])
            ):
                lines.append(entry["scenario_body"])
                lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    @staticmethod
    def _bundle_source_order(
        bundle: dict[str, Any],
        effects: dict[str, dict[str, Any]],
        nodes: dict[str, dict[str, Any]],
    ) -> int:
        primary = effects.get(bundle.get("primary_effect_ref"), {})
        node = nodes.get(primary.get("source_node_ref"), {})
        return int(node.get("source_range", {}).get("start_line", 100000))

    @staticmethod
    def _one_line(value: Any) -> str:
        return " ".join(str(value).strip().split())

    @staticmethod
    def _dedupe(values: Iterable[str]) -> list[str]:
        return list(dict.fromkeys(value for value in values if value))

    @staticmethod
    def _stable_id(prefix: str, *parts: str) -> str:
        digest = canonical_digest({"prefix": prefix, "parts": parts}).removeprefix("sha256:")
        return f"{prefix}-{digest[:20]}"

    @staticmethod
    def _without_display_order(item: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in item.items()
            if key not in {"display_order", "scenario_body"}
            and not key.startswith("_")
        }
