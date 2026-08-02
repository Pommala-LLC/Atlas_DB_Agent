from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import shutil
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..core.canonical_json import canonical_digest, canonical_json_bytes
from .models import (
    CheckState,
    CompositionAssessment,
    CompositionResolution,
    CompositionTransactionRelationship,
    GraphEdge,
    GraphNode,
    MeteringSnapshot,
    OrganicPauseDisposition,
    OrganicValidationReport,
    PauseCause,
    PauseDispositionDecision,
    PauseResponsibility,
    ProcedureCheck,
    ProcedureCheckReport,
    ProcedureCompositionContract,
    ProcedureKnowledgeGraph,
)


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _write(path: Path, payload: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(payload) + b"\n")
    return path


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _safe_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "artifact"


class CommercialWorkflowError(RuntimeError):
    pass


class ImmutableArtifactStore:
    """Tenant-scoped immutable JSON artifact store with a chained audit trail."""

    def __init__(self, root: Path, *, tenant_ref: str) -> None:
        self.root = root.resolve()
        self.tenant_ref = _safe_id(tenant_ref)
        self.tenant_root = self.root / "tenants" / self.tenant_ref
        self.artifact_root = self.tenant_root / "artifacts"
        self.audit_path = self.tenant_root / "audit" / "events.ndjson"
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)

    def put(
        self,
        *,
        category: str,
        artifact_id: str,
        payload: object,
        actor_ref: str,
        role: str,
        action: str = "ARTIFACT_CREATED",
    ) -> Path:
        encoded = canonical_json_bytes(payload) + b"\n"
        digest = "sha256:" + hashlib.sha256(encoded).hexdigest()
        destination = self.artifact_root / _safe_id(category) / f"{_safe_id(artifact_id)}--{digest[7:19]}.json"
        if destination.exists():
            if destination.read_bytes() != encoded:
                raise CommercialWorkflowError(f"Immutable artifact collision: {destination}")
            return destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(encoded)
        self.audit(
            actor_ref=actor_ref,
            role=role,
            action=action,
            artifact_ref=destination.relative_to(self.tenant_root).as_posix(),
            artifact_digest=digest,
            details={"category": category, "artifact_id": artifact_id},
        )
        return destination

    def list(self, category: str | None = None) -> list[Path]:
        root = self.artifact_root / _safe_id(category) if category else self.artifact_root
        if not root.exists():
            return []
        return sorted(path for path in root.rglob("*.json") if path.is_file())

    def latest(self, category: str) -> Path | None:
        values = self.list(category)
        return max(values, key=lambda item: item.stat().st_mtime_ns) if values else None

    def audit(
        self,
        *,
        actor_ref: str,
        role: str,
        action: str,
        artifact_ref: str | None,
        artifact_digest: str | None,
        details: dict[str, object] | None = None,
    ) -> None:
        previous = None
        if self.audit_path.exists():
            lines = [line for line in self.audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            if lines:
                previous = json.loads(lines[-1]).get("event_digest")
        without_digest = {
            "schema_version": "commercial-ui-audit-event-1.0",
            "tenant_ref": self.tenant_ref,
            "occurred_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "actor_ref": actor_ref,
            "role": role,
            "action": action,
            "artifact_ref": artifact_ref,
            "artifact_digest": artifact_digest,
            "previous_event_digest": previous,
            "details": details or {},
        }
        record = {**without_digest, "event_digest": canonical_digest(without_digest)}
        with self.audit_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(canonical_json_bytes(record).decode("utf-8") + "\n")

    def audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        if not self.audit_path.exists():
            return []
        values = [json.loads(line) for line in self.audit_path.read_text(encoding="utf-8").splitlines() if line]
        return values[-limit:]


class OrganicPauseDispositionService:
    def build(
        self,
        *,
        report_path: Path,
        decision: PauseDispositionDecision,
        cause: PauseCause,
        responsibility: PauseResponsibility,
        rationale: str,
        remediation_actions: Iterable[str],
        owner_ref: str,
        approved_by_ref: str | None,
        decided_at: str,
        target_reassessment_at: str | None = None,
    ) -> OrganicPauseDisposition:
        report = OrganicValidationReport.model_validate_json(report_path.read_text(encoding="utf-8"))
        without = report.model_dump(mode="python", exclude={"content_digest"})
        if report.content_digest != canonical_digest(without):
            raise CommercialWorkflowError("Organic report digest mismatch.")
        if not report.pause_reasons and report.status.value not in {"ORGANIC_SMOKE_FAILED", "FAILED_INTERNAL"}:
            raise CommercialWorkflowError("A pause disposition cannot be created for a report without a pause or failure.")
        source_digests = tuple(sorted({item.source_digest_before for item in report.case_outcomes}))
        payload = {
            "schema_version": "organic-pause-disposition-1.0",
            "disposition_id": f"disposition-{_safe_id(report.validation_id)}-{decision.value.lower()}",
            "validation_report_ref": report_path.resolve().as_posix(),
            "validation_report_digest": report.content_digest,
            "validation_id": report.validation_id,
            "source_digests": source_digests,
            "pause_reasons": report.pause_reasons or (report.status.value,),
            "dominant_cause": cause,
            "responsibility": responsibility,
            "decision": decision,
            "blocker_codes": report.recurring_blocker_codes,
            "rationale": rationale,
            "remediation_actions": tuple(item for item in remediation_actions if item.strip()),
            "owner_ref": owner_ref,
            "approved_by_ref": approved_by_ref,
            "decided_at": decided_at,
            "target_reassessment_at": target_reassessment_at,
        }
        return OrganicPauseDisposition(**payload, content_digest=canonical_digest(payload))


class ProcedureCheckService:
    """Build a customer-readable six-state check matrix from one generated run."""

    def _artifact(self, run_dir: Path, name: str) -> tuple[Path | None, dict[str, Any] | None]:
        candidates = [run_dir / name, run_dir / "extraction" / name]
        if name == "03-semantic.json":
            candidates.append(run_dir / "extraction" / "03-semantic-phase2-4.json")
        if name == "end-to-end-run.json":
            candidates.append(run_dir / "extraction" / "run-manifest.json")
        for path in candidates:
            if path.is_file():
                return path, _load(path)
        return None, None

    def build(self, run_dir: Path) -> ProcedureCheckReport:
        run_dir = run_dir.resolve()
        parse_path, parse = self._artifact(run_dir, "02-parse.json")
        semantic_path, semantic = self._artifact(run_dir, "03-semantic.json")
        scenarios_path, scenarios = self._artifact(run_dir, "04-scenario-specs.json")
        end_path, end = self._artifact(run_dir, "end-to-end-run.json")
        if end is None:
            candidates = sorted(run_dir.glob("*end*run*.json"))
            if candidates:
                end_path, end = candidates[0], _load(candidates[0])
        bdd_manifest = run_dir / "bdd" / "proposal-manifest.json"
        bdd = _load(bdd_manifest) if bdd_manifest.is_file() else None
        lint_path = run_dir / "bdd" / "lint-report.json"
        lint = _load(lint_path) if lint_path.is_file() else None
        findings = []
        if semantic:
            findings.extend(semantic.get("findings", []))
        codes = {str(item.get("code", "")) for item in findings}
        procedure_ref = "UNKNOWN_PROCEDURE"
        if semantic:
            procedure_ref = str(semantic.get("procedure_ref") or semantic.get("procedure") or procedure_ref)
        if scenarios:
            procedure_ref = str(scenarios.get("procedure_ref") or scenarios.get("procedure") or procedure_ref)
        if bdd:
            procedure_ref = str(bdd.get("procedure") or procedure_ref)
        source_digest = None
        if end:
            source_digest = end.get("source_digest")
        if source_digest is None and parse:
            source_digest = parse.get("source_digest")
        checks: list[ProcedureCheck] = []

        if parse_path is None:
            checks.append(ProcedureCheck(check_id="PARSE", display_name="Source parsing", state=CheckState.NOT_EVALUATED, summary="Parse artifact is missing.", blocker_codes=("PARSE_ARTIFACT_MISSING",)))
        else:
            outcome = str(parse.get("outcome", "UNKNOWN"))
            if outcome == "PARSES_COMPLETE":
                state, summary = CheckState.PASS, "The source parsed without recovery."
            elif outcome == "PARSES_PARTIAL":
                state, summary = CheckState.CONDITIONAL, "The source parsed with recovery; downstream evidence is qualified."
            elif outcome.startswith("REFUSES"):
                state, summary = CheckState.FAIL, f"The parser refused the source: {outcome}."
            else:
                state, summary = CheckState.INCONCLUSIVE, f"Unrecognized parse outcome: {outcome}."
            kwargs: dict[str, object] = {"evidence_refs": (parse_path.as_posix(),)}
            if state is CheckState.CONDITIONAL:
                kwargs["condition_refs"] = ("PARSE_RECOVERY_BOUNDARY",)
            checks.append(ProcedureCheck(check_id="PARSE", display_name="Source parsing", state=state, summary=summary, **kwargs))

        if semantic_path is None:
            checks.append(ProcedureCheck(check_id="SEMANTIC_ANALYSIS", display_name="Semantic analysis", state=CheckState.NOT_EVALUATED, summary="Semantic artifact is missing.", blocker_codes=("SEMANTIC_ARTIFACT_MISSING",)))
        elif codes & {"BEHAVIOR_SLICE_PARTIAL", "HANDLER_FLOW_PARTIAL", "LOOP_SUMMARY_PARTIAL", "QUERY_SUMMARY_PARTIAL"}:
            checks.append(ProcedureCheck(check_id="SEMANTIC_ANALYSIS", display_name="Semantic analysis", state=CheckState.CONDITIONAL, summary="Semantic analysis completed with explicit partial boundaries.", evidence_refs=(semantic_path.as_posix(),), condition_refs=tuple(sorted(codes & {"BEHAVIOR_SLICE_PARTIAL", "HANDLER_FLOW_PARTIAL", "LOOP_SUMMARY_PARTIAL", "QUERY_SUMMARY_PARTIAL"}))))
        else:
            checks.append(ProcedureCheck(check_id="SEMANTIC_ANALYSIS", display_name="Semantic analysis", state=CheckState.PASS, summary="Semantic analysis completed without a known partial-analysis finding.", evidence_refs=(semantic_path.as_posix(),)))

        if scenarios_path is None:
            checks.append(ProcedureCheck(check_id="SCENARIO_ADMISSION", display_name="Scenario admission", state=CheckState.NOT_EVALUATED, summary="Scenario artifact is missing.", blocker_codes=("SCENARIO_ARTIFACT_MISSING",)))
        else:
            admitted = len(scenarios.get("scenario_specs", []))
            blocked = sum(1 for item in scenarios.get("compilation_results", []) if item.get("compilation_status") == "BLOCKED")
            if admitted and not blocked:
                state, summary = CheckState.PASS, f"{admitted} scenarios admitted and none blocked."
                kwargs = {"evidence_refs": (scenarios_path.as_posix(),)}
            elif admitted:
                state, summary = CheckState.CONDITIONAL, f"{admitted} scenarios admitted; {blocked} compilation results remain blocked."
                kwargs = {"evidence_refs": (scenarios_path.as_posix(),), "condition_refs": ("BLOCKED_SCENARIO_COVERAGE_GAPS",)}
            else:
                state, summary = CheckState.INCONCLUSIVE, "No scenarios were admitted."
                kwargs = {"evidence_refs": (scenarios_path.as_posix(),), "limitations": ("No executable behavior claim is established.",)}
            checks.append(ProcedureCheck(check_id="SCENARIO_ADMISSION", display_name="Scenario admission", state=state, summary=summary, **kwargs))

        if "TENANT_ISOLATION_MISSING" in codes:
            checks.append(ProcedureCheck(check_id="TENANT_ISOLATION", display_name="Tenant isolation", state=CheckState.FAIL, summary="A tenant-isolation violation was identified.", evidence_refs=(semantic_path.as_posix(),), blocker_codes=("TENANT_ISOLATION_MISSING",)))
        elif "TENANT_ISOLATION_NOT_EVALUATED" in codes:
            checks.append(ProcedureCheck(check_id="TENANT_ISOLATION", display_name="Tenant isolation", state=CheckState.NOT_EVALUATED, summary="Tenant isolation could not be evaluated with supplied metadata.", blocker_codes=("TENANT_ISOLATION_NOT_EVALUATED",)))
        else:
            checks.append(ProcedureCheck(check_id="TENANT_ISOLATION", display_name="Tenant isolation", state=CheckState.INCONCLUSIVE, summary="No violation was found, but absence of a finding is not a PASS.", evidence_refs=((semantic_path.as_posix(),) if semantic_path else ()), limitations=("Requires an authoritative relation/tenant catalog for PASS.",)))

        if "DML_CALLER_CONTROLLED" in codes:
            checks.append(ProcedureCheck(check_id="TRANSACTION_OUTCOME", display_name="Transaction outcome", state=CheckState.CONDITIONAL, summary="DML outcome depends on the declared caller transaction contract.", evidence_refs=(semantic_path.as_posix(),), condition_refs=("CALLER_TRANSACTION_CONTRACT",)))
        elif semantic_path:
            checks.append(ProcedureCheck(check_id="TRANSACTION_OUTCOME", display_name="Transaction outcome", state=CheckState.INCONCLUSIVE, summary="Transaction effects were analyzed, but runtime caller behavior is not proven.", evidence_refs=(semantic_path.as_posix(),)))
        else:
            checks.append(ProcedureCheck(check_id="TRANSACTION_OUTCOME", display_name="Transaction outcome", state=CheckState.NOT_EVALUATED, summary="Semantic artifact is missing.", blocker_codes=("SEMANTIC_ARTIFACT_MISSING",)))

        dynamic_codes = tuple(sorted(code for code in codes if code.startswith("DYNAMIC_") or "DYNAMIC" in code))
        if not dynamic_codes:
            checks.append(ProcedureCheck(check_id="DYNAMIC_SQL", display_name="Dynamic SQL resolution", state=CheckState.NOT_APPLICABLE, summary="No dynamic SQL boundary was recorded."))
        elif any("UNRESOLVED" in code or "RUNTIME_CAPTURE_REQUIRED" in code for code in dynamic_codes):
            checks.append(ProcedureCheck(check_id="DYNAMIC_SQL", display_name="Dynamic SQL resolution", state=CheckState.CONDITIONAL, summary="Dynamic SQL contains unresolved or runtime-dependent variants.", evidence_refs=(semantic_path.as_posix(),), condition_refs=dynamic_codes))
        else:
            checks.append(ProcedureCheck(check_id="DYNAMIC_SQL", display_name="Dynamic SQL resolution", state=CheckState.PASS, summary="Recorded dynamic SQL variants were statically reconstructed within the configured budget.", evidence_refs=(semantic_path.as_posix(),)))

        if lint_path.is_file():
            error_count = int(lint.get("error_count", 0))
            warning_count = int(lint.get("warning_count", 0))
            if error_count:
                checks.append(ProcedureCheck(check_id="GHERKIN_QUALITY", display_name="Gherkin quality", state=CheckState.FAIL, summary=f"Gherkin quality gate has {error_count} errors.", evidence_refs=(lint_path.as_posix(),)))
            elif warning_count:
                checks.append(ProcedureCheck(check_id="GHERKIN_QUALITY", display_name="Gherkin quality", state=CheckState.CONDITIONAL, summary=f"Gherkin is structurally valid with {warning_count} governed warnings.", evidence_refs=(lint_path.as_posix(),), condition_refs=("WARNING_GOVERNANCE",)))
            else:
                checks.append(ProcedureCheck(check_id="GHERKIN_QUALITY", display_name="Gherkin quality", state=CheckState.PASS, summary="Gherkin quality gate passed without findings.", evidence_refs=(lint_path.as_posix(),)))
        else:
            checks.append(ProcedureCheck(check_id="GHERKIN_QUALITY", display_name="Gherkin quality", state=CheckState.NOT_EVALUATED, summary="Lint report is missing.", blocker_codes=("LINT_REPORT_MISSING",)))

        if bdd_manifest.is_file():
            manifest = _load(bdd_manifest)
            authority = str(manifest.get("authority_scope", "UNKNOWN"))
            if authority == "NON_AUTHORITATIVE_PROPOSAL":
                checks.append(ProcedureCheck(check_id="BUSINESS_VOCABULARY", display_name="Business vocabulary", state=CheckState.CONDITIONAL, summary="Readable output remains a non-authoritative proposal pending vocabulary approval.", evidence_refs=(bdd_manifest.as_posix(),), condition_refs=("APPROVED_VOCABULARY",)))
            else:
                checks.append(ProcedureCheck(check_id="BUSINESS_VOCABULARY", display_name="Business vocabulary", state=CheckState.INCONCLUSIVE, summary=f"Vocabulary authority scope is {authority}.", evidence_refs=(bdd_manifest.as_posix(),)))
        else:
            checks.append(ProcedureCheck(check_id="BUSINESS_VOCABULARY", display_name="Business vocabulary", state=CheckState.NOT_EVALUATED, summary="Readable BDD manifest is missing.", blocker_codes=("READABLE_BDD_MANIFEST_MISSING",)))

        counts = Counter(item.state.value for item in checks)
        for state in CheckState:
            counts.setdefault(state.value, 0)
        payload = {
            "schema_version": "procedure-check-report-1.0",
            "report_id": f"check-{_safe_id(procedure_ref)}-{hashlib.sha256(run_dir.as_posix().encode()).hexdigest()[:12]}",
            "procedure_ref": procedure_ref,
            "source_digest": source_digest,
            "analysis_run_ref": run_dir.as_posix(),
            "checks": tuple(checks),
            "counts_by_state": dict(sorted(counts.items())),
        }
        return ProcedureCheckReport(**payload, content_digest=canonical_digest(payload))


class CompositionContractService:
    def assess(
        self,
        contract: ProcedureCompositionContract,
        *,
        upstream_semantic_digest: str,
        downstream_semantic_digest: str,
        transaction_contract_digest: str | None = None,
        orchestration_definition_digest: str | None = None,
    ) -> CompositionAssessment:
        upstream_match = contract.upstream_semantic_digest == upstream_semantic_digest
        downstream_match = contract.downstream_semantic_digest == downstream_semantic_digest
        transaction_match = None if contract.transaction_contract_digest is None else contract.transaction_contract_digest == transaction_contract_digest
        orchestration_match = None if contract.orchestration_definition_digest is None else contract.orchestration_definition_digest == orchestration_definition_digest
        blockers: list[str] = []
        if not upstream_match:
            blockers.append("UPSTREAM_SEMANTIC_DIGEST_STALE")
        if not downstream_match:
            blockers.append("DOWNSTREAM_SEMANTIC_DIGEST_STALE")
        if transaction_match is False:
            blockers.append("TRANSACTION_CONTRACT_DIGEST_STALE")
        if orchestration_match is False:
            blockers.append("ORCHESTRATION_DEFINITION_DIGEST_STALE")
        proof = {
            "UPSTREAM_EXECUTED": CheckState.CONDITIONAL,
            "EXECUTION_ORDER_KNOWN": CheckState.PASS if contract.invocation_site_ref else CheckState.CONDITIONAL,
            "PARAMETER_IDENTITIES_MAPPED": CheckState.PASS if contract.parameter_mappings else CheckState.FAIL,
            "SUCCESS_ENTAILS_PRECONDITION": CheckState.PASS if all(item.entailment_status == "PROVEN" for item in contract.condition_mappings) else CheckState.CONDITIONAL,
            "NO_INTERVENING_INVALIDATION": CheckState.CONDITIONAL,
            "TRANSACTION_VISIBILITY_COMPATIBLE": CheckState.PASS if contract.transaction_relationship in {CompositionTransactionRelationship.SAME_UOW, CompositionTransactionRelationship.SEPARATE_COMMITTED_UOW} else CheckState.CONDITIONAL,
            "HANDLED_ERROR_NOT_SUCCESS": CheckState.CONDITIONAL,
        }
        if blockers:
            resolution = CompositionResolution.STALE_CONTRACT_DIGEST
        elif any(value is CheckState.FAIL for value in proof.values()):
            resolution = CompositionResolution.CONFLICTING_COMPOSITION_EVIDENCE
        elif all(value is CheckState.PASS for value in proof.values()):
            resolution = CompositionResolution.PROVEN_BY_COMPOSITION_CONTRACT
        else:
            resolution = CompositionResolution.CONDITIONAL_ON_COMPOSITION_CONTRACT
        payload = {
            "schema_version": "composition-assessment-1.0",
            "contract_id": contract.contract_id,
            "resolution": resolution,
            "upstream_digest_matches": upstream_match,
            "downstream_digest_matches": downstream_match,
            "transaction_contract_digest_matches": transaction_match,
            "orchestration_digest_matches": orchestration_match,
            "proof_obligations": proof,
            "blockers": tuple(blockers),
        }
        return CompositionAssessment(**payload, content_digest=canonical_digest(payload))


class ProcedureKnowledgeGraphService:
    """Build a conservative graph from emitted JSON evidence without inventing semantic edges."""

    RELATION_KEYS = {"relation", "relation_ref", "relation_name", "table", "table_name", "target_relation"}
    CALL_KEYS = {"call_target", "procedure_ref", "target_procedure", "routine_ref"}

    def build(self, run_dir: Path) -> ProcedureKnowledgeGraph:
        run_dir = run_dir.resolve()
        documents: list[tuple[Path, Any]] = []
        for path in sorted(run_dir.rglob("*.json")):
            try:
                documents.append((path, _load(path)))
            except Exception:
                continue
        procedure_ref = "UNKNOWN_PROCEDURE"
        nodes: dict[str, GraphNode] = {}
        edges: dict[str, GraphEdge] = {}
        unresolved: set[str] = set()

        def add_node(node_type: str, label: str, *, status: str = "OBSERVED_OR_EXTRACTED", attributes: dict[str, object] | None = None) -> str:
            node_id = f"{node_type.lower()}:{_safe_id(label)}"
            nodes.setdefault(node_id, GraphNode(node_id=node_id, node_type=node_type, label=label, status=status, attributes=attributes or {}))
            return node_id

        def add_edge(source: str, target: str, edge_type: str, attributes: dict[str, object] | None = None) -> None:
            edge_id = f"edge:{hashlib.sha256(f'{source}|{target}|{edge_type}'.encode()).hexdigest()[:20]}"
            edges.setdefault(edge_id, GraphEdge(edge_id=edge_id, source=source, target=target, edge_type=edge_type, attributes=attributes or {}))

        for path, payload in documents:
            if isinstance(payload, dict):
                procedure_ref = str(payload.get("procedure_ref") or payload.get("procedure") or procedure_ref)
        procedure_node = add_node("PROCEDURE", procedure_ref, attributes={"run_dir": run_dir.as_posix()})

        def walk(value: Any, *, source_path: Path, parent_key: str | None = None) -> None:
            if isinstance(value, dict):
                finding_code = value.get("code")
                if isinstance(finding_code, str) and any(token in finding_code for token in ("UNRESOLVED", "UNAVAILABLE", "PARTIAL")):
                    unresolved.add(finding_code)
                    finding_node = add_node("BOUNDARY", finding_code, status="UNRESOLVED", attributes={"source": source_path.as_posix()})
                    add_edge(procedure_node, finding_node, "HAS_BOUNDARY")
                for key, item in value.items():
                    if key in self.RELATION_KEYS and isinstance(item, str) and item.strip():
                        relation = add_node("RELATION", item.strip(), attributes={"source": source_path.as_posix()})
                        add_edge(procedure_node, relation, "REFERENCES_RELATION")
                    elif key in self.CALL_KEYS and isinstance(item, str) and item.strip() and item != procedure_ref:
                        target = add_node("PROCEDURE", item.strip(), attributes={"source": source_path.as_posix()})
                        add_edge(procedure_node, target, "CALLS_OR_REFERENCES")
                    elif key in {"effect_ref", "expected_effects"}:
                        if isinstance(item, str):
                            effect = add_node("EFFECT", item, attributes={"source": source_path.as_posix()})
                            add_edge(procedure_node, effect, "HAS_EFFECT")
                    walk(item, source_path=source_path, parent_key=key)
            elif isinstance(value, list):
                for item in value:
                    walk(item, source_path=source_path, parent_key=parent_key)
        for path, payload in documents:
            walk(payload, source_path=path)
        graph_id = f"graph-{_safe_id(procedure_ref)}-{hashlib.sha256(run_dir.as_posix().encode()).hexdigest()[:12]}"
        payload = {
            "schema_version": "procedure-knowledge-graph-1.0",
            "graph_id": graph_id,
            "procedure_ref": procedure_ref,
            "nodes": tuple(sorted(nodes.values(), key=lambda item: item.node_id)),
            "edges": tuple(sorted(edges.values(), key=lambda item: item.edge_id)),
            "unresolved_boundaries": tuple(sorted(unresolved)),
        }
        return ProcedureKnowledgeGraph(**payload, content_digest=canonical_digest(payload))


class CommercialOperationsService:
    def generate_sbom(self, output: Path) -> Path:
        components: list[dict[str, object]] = []
        for distribution in sorted(importlib.metadata.distributions(), key=lambda item: (item.metadata.get("Name") or "").lower()):
            name = distribution.metadata.get("Name")
            if not name:
                continue
            components.append({
                "type": "library",
                "name": name,
                "version": distribution.version,
                "purl": f"pkg:pypi/{name.lower().replace('_', '-')}@{distribution.version}",
            })
        payload = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{hashlib.sha256(canonical_json_bytes(components)).hexdigest()[:32]}",
            "version": 1,
            "metadata": {"timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "component": {"type": "application", "name": "atlas-procedure-intelligence", "version": importlib.metadata.version("atlas-procedure-intelligence") if self._installed("atlas-procedure-intelligence") else "source-tree"}},
            "components": components,
        }
        return _write(output, payload)

    def _installed(self, name: str) -> bool:
        try:
            importlib.metadata.version(name)
            return True
        except importlib.metadata.PackageNotFoundError:
            return False

    def build_support_bundle(self, *, run_dir: Path, output: Path, include_source: bool = False) -> Path:
        run_dir = run_dir.resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        source_extensions = {".sql", ".ddl", ".cbl", ".cob", ".java", ".py"}
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            manifest: list[dict[str, object]] = []
            for path in sorted(run_dir.rglob("*")):
                if not path.is_file():
                    continue
                relative = path.relative_to(run_dir)
                if not include_source and path.suffix.lower() in source_extensions:
                    continue
                archive.write(path, f"artifacts/{relative.as_posix()}")
                manifest.append({"path": relative.as_posix(), "sha256": _sha256(path), "size_bytes": path.stat().st_size})
            manifest_payload = {
                "schema_version": "support-bundle-manifest-1.0",
                "source_included": include_source,
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "artifacts": manifest,
            }
            archive.writestr("support-bundle-manifest.json", canonical_json_bytes(manifest_payload) + b"\n")
        return output

    def meter_workspace(self, *, store: ImmutableArtifactStore, period_start: str, period_end: str) -> MeteringSnapshot:
        events = store.audit_events(limit=1_000_000)
        procedure_digests = {str(item.get("artifact_digest")) for item in events if item.get("action") == "ANALYSIS_RUN_COMPLETED" and item.get("artifact_digest")}
        analysis_runs = sum(1 for item in events if item.get("action") == "ANALYSIS_RUN_COMPLETED")
        generated_artifacts = sum(1 for item in events if item.get("action") == "ARTIFACT_CREATED")
        runtime_observations = sum(1 for item in events if item.get("action") == "RUNTIME_OBSERVATION_IMPORTED")
        lines = sum(int((item.get("details") or {}).get("source_lines", 0)) for item in events)
        payload = {
            "schema_version": "metering-snapshot-1.0",
            "tenant_ref": store.tenant_ref,
            "estate_refs": tuple(sorted({str((item.get("details") or {}).get("estate_ref")) for item in events if (item.get("details") or {}).get("estate_ref")})),
            "environment_refs": tuple(sorted({str((item.get("details") or {}).get("environment_ref")) for item in events if (item.get("details") or {}).get("environment_ref")})),
            "unique_procedure_digests": len(procedure_digests),
            "analysis_runs": analysis_runs,
            "source_lines_processed": lines,
            "generated_artifacts": generated_artifacts,
            "runtime_observations": runtime_observations,
            "period_start": period_start,
            "period_end": period_end,
        }
        return MeteringSnapshot(**payload, content_digest=canonical_digest(payload))


class RelationalFixturePlanningService:
    """Plans relational fixture dependencies without inventing row values or executable SQL."""

    def build(
        self,
        *,
        procedure_ref: str,
        relation_refs: Iterable[str],
        catalog_paths: Iterable[Path],
    ):
        from ..type_system.models import RelationDefinition
        from .models import FixturePlanStatus, RelationFixtureRequirement, RelationalFixturePlan

        catalog: dict[str, RelationDefinition] = {}
        providers: set[str] = set()
        for path in catalog_paths:
            relation = RelationDefinition.model_validate_json(path.read_text(encoding="utf-8"))
            without = relation.model_dump(mode="python", exclude={"content_digest"})
            if relation.content_digest != canonical_digest(without):
                raise CommercialWorkflowError(f"RelationDefinition digest mismatch: {path}")
            ref = f"{relation.schema_name}.{relation.relation_name}".upper()
            catalog[ref] = relation
            providers.add(relation.provider_ref)

        requested = tuple(dict.fromkeys(value.strip().upper() for value in relation_refs if value.strip()))
        unresolved = tuple(sorted(ref for ref in requested if ref not in catalog))
        selected = {ref: catalog[ref] for ref in requested if ref in catalog}

        # Build parent-before-child order from foreign keys only when both sides are selected.
        dependency_map: dict[str, set[str]] = {ref: set() for ref in selected}
        for ref, relation in selected.items():
            for fk in relation.foreign_keys:
                parent_schema = fk.referenced_schema or relation.schema_name
                parent_ref = f"{parent_schema}.{fk.referenced_relation}".upper()
                if parent_ref in selected and parent_ref != ref:
                    dependency_map[ref].add(parent_ref)

        ordered: list[str] = []
        remaining = {key: set(value) for key, value in dependency_map.items()}
        while remaining:
            ready = sorted(key for key, dependencies in remaining.items() if not dependencies)
            if not ready:
                # Cycles are explicit blockers; retain deterministic order for review.
                ready = [sorted(remaining)[0]]
            for key in ready:
                ordered.append(key)
                remaining.pop(key, None)
                for dependencies in remaining.values():
                    dependencies.discard(key)

        requirements = []
        for index, ref in enumerate(ordered, start=1):
            relation = selected[ref]
            required_columns = tuple(
                column.column_name
                for column in relation.columns
                if not column.nullable
                and column.default_expression is None
                and not column.generated
                and not column.identity_column
            )
            omitted = tuple(
                column.column_name
                for column in relation.columns
                if column.generated or column.identity_column
            )
            parents = tuple(sorted(dependency_map[ref]))
            blockers: list[str] = []
            if any(column.sql_type.completeness.value != "COMPLETE" for column in relation.columns):
                blockers.append("COLUMN_TYPE_METADATA_INCOMPLETE")
            requirements.append(
                RelationFixtureRequirement(
                    relation_ref=ref,
                    insertion_order=index,
                    required_input_columns=required_columns,
                    omitted_generated_columns=omitted,
                    parent_relation_refs=parents,
                    check_constraints=relation.check_constraints,
                    blocker_codes=tuple(blockers),
                )
            )
        blocked = bool(unresolved or any(item.blocker_codes for item in requirements))
        payload = {
            "schema_version": "relational-fixture-plan-1.0",
            "plan_id": f"fixture-plan-{_safe_id(procedure_ref)}-{hashlib.sha256('|'.join(requested).encode()).hexdigest()[:12]}",
            "procedure_ref": procedure_ref,
            "status": FixturePlanStatus.BLOCKED if blocked else FixturePlanStatus.READY_FOR_REVIEW,
            "catalog_provider_refs": tuple(sorted(providers)),
            "relation_requirements": tuple(requirements),
            "unresolved_relation_refs": unresolved,
            "generated_sql": (),
            "limitations": (
                "No row values are generated without approved scenario-to-relational constraints.",
                "No setup or teardown SQL is emitted in RC25.",
                "The plan establishes metadata requirements and parent-before-child ordering only.",
            ),
        }
        return RelationalFixturePlan(**payload, content_digest=canonical_digest(payload))


class CommercialDataLifecycleService:
    def backup_tenant_artifacts(self, *, store: ImmutableArtifactStore, output: Path) -> Path:
        """Back up immutable artifacts and audit evidence only; source/run workspaces are excluded."""
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            records: list[dict[str, object]] = []
            for path in [*store.list(), store.audit_path]:
                if not path.is_file():
                    continue
                relative = path.relative_to(store.tenant_root).as_posix()
                archive.write(path, relative)
                records.append({"path": relative, "sha256": _sha256(path), "size_bytes": path.stat().st_size})
            payload = {
                "schema_version": "commercial-artifact-backup-manifest-1.0",
                "tenant_ref": store.tenant_ref,
                "source_included": False,
                "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "records": records,
            }
            archive.writestr("backup-manifest.json", canonical_json_bytes(payload) + b"\n")
        return output

    def execute_deletion(
        self,
        *,
        store: ImmutableArtifactStore,
        request,
        executed_by_ref: str,
        executed_role: str,
        as_of: str,
    ):
        from datetime import datetime
        from .models import CommercialDeletionAttestation, CommercialDeletionRequest, DeletedArtifactRecord, DeletionScope

        if not isinstance(request, CommercialDeletionRequest):
            raise CommercialWorkflowError("A validated CommercialDeletionRequest is required.")
        without = request.model_dump(mode="python", exclude={"content_digest"})
        if request.content_digest != canonical_digest(without):
            raise CommercialWorkflowError("Deletion request digest mismatch.")
        when = datetime.fromisoformat(as_of.replace("Z", "+00:00"))
        allowed = datetime.fromisoformat(request.execute_after.replace("Z", "+00:00"))
        if when < allowed:
            raise CommercialWorkflowError("Deletion request is not yet executable.")
        if _safe_id(request.tenant_ref) != store.tenant_ref:
            raise CommercialWorkflowError("Deletion request tenant does not match the active tenant workspace.")
        if executed_by_ref in {request.requested_by_ref, request.approved_by_ref}:
            raise CommercialWorkflowError("Deletion execution requires a third actor distinct from requester and approver.")

        if request.scope is DeletionScope.TENANT_WORKSPACE:
            targets = store.list()
        else:
            targets = []
            for ref in request.target_artifact_refs:
                candidate = (store.tenant_root / ref).resolve()
                try:
                    candidate.relative_to(store.artifact_root)
                except ValueError as exc:
                    raise CommercialWorkflowError(f"Deletion target is outside the immutable artifact root: {ref}") from exc
                if candidate.is_file():
                    targets.append(candidate)
        deleted = []
        for path in sorted(set(targets)):
            deleted.append(
                DeletedArtifactRecord(
                    artifact_ref=path.relative_to(store.tenant_root).as_posix(),
                    artifact_digest_before_deletion=_sha256(path),
                    size_bytes=path.stat().st_size,
                )
            )
            path.unlink()
        payload = {
            "schema_version": "commercial-deletion-attestation-1.0",
            "attestation_id": f"deletion-attestation-{_safe_id(request.request_id)}",
            "request_id": request.request_id,
            "tenant_ref": request.tenant_ref,
            "deleted_artifacts": tuple(deleted),
            "retained_audit_ref": store.audit_path.relative_to(store.tenant_root).as_posix(),
            "completed_at": as_of,
            "executed_by_ref": executed_by_ref,
        }
        attestation = CommercialDeletionAttestation(**payload, content_digest=canonical_digest(payload))
        # Attestation is written after deletion and the audit chain is retained.
        store.put(
            category="deletion-attestations",
            artifact_id=attestation.attestation_id,
            payload=attestation,
            actor_ref=executed_by_ref,
            role=executed_role,
            action="COMMERCIAL_DELETION_ATTESTED",
        )
        return attestation
