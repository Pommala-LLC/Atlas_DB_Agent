from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from ..commercial.workflows import ImmutableArtifactStore, ProcedureCheckService


def _load(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _latest(store: ImmutableArtifactStore, category: str) -> tuple[Path | None, dict[str, Any] | None]:
    path = store.latest(category)
    return path, _load(path)


def _status(value: str | None, *, missing: str = "NOT_EVALUATED") -> str:
    return str(value or missing)


def _capability_summary(store: ImmutableArtifactStore, templates_dir: Path) -> dict[str, Any]:
    path, payload = _latest(store, "capabilities")
    source = "TENANT_ARTIFACT"
    if payload is None:
        template = templates_dir / "capability-manifest.json"
        payload = _load(template)
        path = template if payload is not None else None
        source = "PACKAGED_TEMPLATE" if payload is not None else "MISSING"
    payload = payload or {}
    capabilities = payload.get("capabilities") if isinstance(payload.get("capabilities"), list) else []
    state_counts = Counter(str(item.get("state", "UNKNOWN")) for item in capabilities if isinstance(item, dict))
    datasheet_eligible = [
        item for item in capabilities
        if isinstance(item, dict) and bool(item.get("datasheet_eligible"))
    ]
    return {
        "source": source,
        "artifact_path": path.as_posix() if path else None,
        "commercial_maturity": _status(payload.get("commercial_maturity"), missing="ORGANIC_VALIDATION_REQUIRED"),
        "naming_status": _status(payload.get("naming_status"), missing="PROVISIONAL_PENDING_NAMING_BASELINE"),
        "edition_model_status": _status(payload.get("edition_model_status"), missing="DEFERRED"),
        "distribution_name": payload.get("distribution_name", "atlas-procedure-intelligence"),
        "distribution_version": payload.get("distribution_version"),
        "capability_count": len(capabilities),
        "state_counts": dict(sorted(state_counts.items())),
        "datasheet_eligible_count": len(datasheet_eligible),
        "prohibited_claim_count": len(payload.get("prohibited_datasheet_claims") or []),
    }


def _custody_summary(store: ImmutableArtifactStore) -> dict[str, Any]:
    path, payload = _latest(store, "custody")
    if payload is None:
        return {
            "status": "NOT_APPROVED",
            "ready": False,
            "artifact_path": None,
            "agreement_id": None,
            "approval_evidence_mode": "NOT_SUPPLIED",
            "processing_location": "NOT_SUPPLIED",
            "allowed_source_root_count": 0,
            "source_retention_days": None,
            "derived_artifact_retention_days": None,
            "deletion_request_sla_days": None,
            "deletion_attestation_required": None,
            "backup_policy": None,
            "expires_at": None,
        }
    status = _status(payload.get("status"))
    return {
        "status": status,
        "ready": status == "APPROVED",
        "artifact_path": path.as_posix() if path else None,
        "agreement_id": payload.get("agreement_id"),
        "approval_evidence_mode": payload.get("approval_evidence_mode"),
        "processing_location": payload.get("processing_location"),
        "allowed_source_root_count": len(payload.get("allowed_source_roots") or []),
        "source_retention_days": payload.get("source_retention_days"),
        "derived_artifact_retention_days": payload.get("derived_artifact_retention_days"),
        "deletion_request_sla_days": payload.get("deletion_request_sla_days"),
        "deletion_attestation_required": payload.get("deletion_attestation_required"),
        "backup_policy": payload.get("backup_policy"),
        "expires_at": payload.get("expires_at"),
    }


def _organic_summary(store: ImmutableArtifactStore) -> dict[str, Any]:
    path, payload = _latest(store, "organic-reports")
    if payload is None:
        return {
            "status": "NOT_PERFORMED",
            "artifact_path": None,
            "validation_level": None,
            "source_count": 0,
            "semantic_completed": 0,
            "admitted_scenarios": 0,
            "blocked_scenarios": 0,
            "materially_false_confident_behaviors": 0,
            "pause_reasons": [],
            "recurring_blocker_codes": [],
        }
    return {
        "status": _status(payload.get("status")),
        "artifact_path": path.as_posix() if path else None,
        "validation_id": payload.get("validation_id"),
        "validation_level": payload.get("validation_level"),
        "source_count": int(payload.get("source_count") or 0),
        "semantic_completed": int(payload.get("semantic_completed") or 0),
        "admitted_scenarios": int(payload.get("admitted_scenarios") or 0),
        "blocked_scenarios": int(payload.get("blocked_scenarios") or 0),
        "materially_false_confident_behaviors": int(payload.get("materially_false_confident_behaviors") or 0),
        "pause_reasons": list(payload.get("pause_reasons") or []),
        "recurring_blocker_codes": list(payload.get("recurring_blocker_codes") or []),
    }


def _readiness_summary(store: ImmutableArtifactStore) -> dict[str, Any]:
    path, payload = _latest(store, "readiness")
    if payload is None:
        return {
            "status": "BLOCKED_NOT_ASSESSED",
            "artifact_path": None,
            "commercial_maturity": "COMMERCIALIZATION_CANDIDATE",
            "naming_status": "PROVISIONAL_PENDING_NAMING_BASELINE",
            "blockers": [
                "READINESS_NOT_ASSESSED",
                "ORGANIC_VALIDATION_NOT_PERFORMED",
                "SOURCE_CUSTODY_NOT_APPROVED",
            ],
            "verified_gate_ids": [],
            "deployment_gates": [],
            "customer_boundary_gates": [],
        }
    blockers = list(payload.get("blockers") or [])
    return {
        "status": "READY" if not blockers else "BLOCKED",
        "artifact_path": path.as_posix() if path else None,
        "commercial_maturity": payload.get("commercial_maturity"),
        "naming_status": payload.get("naming_status"),
        "blockers": blockers,
        "verified_gate_ids": list(payload.get("verified_gate_ids") or []),
        "deployment_gates": list(payload.get("deployment_gates") or []),
        "customer_boundary_gates": list(payload.get("customer_boundary_gates") or []),
    }


def _latest_status(store: ImmutableArtifactStore, category: str, fields: tuple[str, ...]) -> dict[str, Any]:
    path, payload = _latest(store, category)
    if payload is None:
        return {"status": "NOT_EVALUATED", "artifact_path": None}
    status = next((payload.get(field) for field in fields if payload.get(field) is not None), "RECORDED")
    return {
        "status": str(status),
        "artifact_path": path.as_posix() if path else None,
        "artifact": payload,
    }


def _procedure_checks(run_dir: Path) -> dict[str, Any]:
    try:
        report = ProcedureCheckService().build(run_dir)
    except Exception as exc:  # review surface must show a refusal rather than crash
        return {
            "status": "NOT_EVALUATED",
            "error": str(exc),
            "procedure_ref": None,
            "checks": [],
            "counts_by_state": {},
        }
    payload = report.model_dump(mode="json")
    return {
        "status": "EVALUATED",
        "error": None,
        "procedure_ref": payload.get("procedure_ref"),
        "checks": payload.get("checks") or [],
        "counts_by_state": payload.get("counts_by_state") or {},
        "content_digest": payload.get("content_digest"),
    }


def build_commercial_control_summary(
    *,
    store: ImmutableArtifactStore,
    templates_dir: Path,
    run_dir: Path,
    review: dict[str, Any],
) -> dict[str, Any]:
    capability = _capability_summary(store, templates_dir)
    custody = _custody_summary(store)
    organic = _organic_summary(store)
    readiness = _readiness_summary(store)
    baseline = _latest_status(store, "baseline", ("comparison_status", "status", "classification"))
    composition = _latest_status(store, "composition", ("resolution", "status"))
    authority = _latest_status(store, "authority", ("status", "validation_status"))
    reviews = _latest_status(store, "reviews", ("status", "review_status"))
    checks = _procedure_checks(run_dir)
    audit_events = store.audit_events(20)
    categories = {
        category: len(store.list(category))
        for category in (
            "capabilities", "custody", "organic-reports", "reviews", "authority",
            "baseline", "composition", "procedure-checks", "graphs",
            "readiness", "operations",
        )
    }
    blocker_count = len(readiness["blockers"])
    top_status = "BLOCKED" if blocker_count or not custody["ready"] or organic["status"] == "NOT_PERFORMED" else "REVIEW_REQUIRED"
    return {
        "overall_status": top_status,
        "capability": capability,
        "custody": custody,
        "organic": organic,
        "readiness": readiness,
        "procedure_checks": checks,
        "authority": {
            "proposal_authority_scope": review.get("authority_scope"),
            "candidate_status": review.get("candidate_status"),
            "vocabulary_status": review.get("vocabulary_status"),
            "review_required": review.get("candidate_status") == "CANDIDATE_BDD",
            "authority_validation": authority,
            "sme_review": reviews,
            "baseline": baseline,
            "composition": composition,
        },
        "artifact_counts": categories,
        "audit_events": audit_events,
        "quick_actions": [
            {"label": "Validate custody", "href": "/custody", "minimum_role": "ADMIN"},
            {"label": "Run organic validation", "href": "/organic", "minimum_role": "ANALYST"},
            {"label": "Record SME review", "href": "/reviews", "minimum_role": "REVIEWER"},
            {"label": "Assess composition", "href": "/composition", "minimum_role": "REVIEWER"},
            {"label": "Assess readiness", "href": "/readiness", "minimum_role": "ADMIN"},
            {"label": "View full audit", "href": "/audit", "minimum_role": "VIEWER"},
        ],
    }
