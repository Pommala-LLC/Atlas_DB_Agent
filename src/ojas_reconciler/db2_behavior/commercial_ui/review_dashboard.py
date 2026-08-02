from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..decision import ExtractedDecisionModelBuilder


class ReviewDashboardError(RuntimeError):
    pass


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _artifact(run_dir: Path, *candidates: str) -> dict[str, Any] | None:
    for candidate in candidates:
        path = run_dir / candidate
        if path.is_file():
            return _load(path)
    return None


def _scenario_group(rule_name: str, scenario_name: str) -> str:
    scenario = scenario_name.casefold()
    if "claim not found" in scenario or "missing required" in scenario:
        return "entry"
    if "escalat" in scenario or "related claim" in scenario:
        return "escalation"
    return _group_for_rule(rule_name)


def _group_for_rule(rule_name: str) -> str:
    value = rule_name.casefold()
    if any(word in value for word in ("exception", "validation", "input", "lookup", "not found", "existence", "condition handling")):
        return "entry"
    if any(word in value for word in ("escalat", "related claim", "cursor", "loop")):
        return "escalation"
    if any(word in value for word in ("persist", "audit", "mutation", "sequence", "result set", "computed output")):
        return "persistence"
    if any(word in value for word in ("decision", "approval", "outcome")):
        return "decision"
    return "entry"


def _decision_priority(rule_name: str, scenario_name: str) -> int:
    value = f"{rule_name} {scenario_name}".casefold()
    if "fraud" in value:
        return 10
    if "rule decision" in value:
        return 20
    if "no approval" in value:
        return 30
    if "manual-review" in value or "manual review" in value:
        return 40
    if "standard approval" in value or value.startswith("approve"):
        return 50
    if "final decision outcome" in value:
        return 60
    return 100


def _effect_group(kind: str, target: str) -> str:
    value = f"{kind} {target}".upper()
    if any(token in value for token in ("SIGNAL", "HANDLER", "ERROR", "SQLSTATE")):
        return "entry"
    if any(token in value for token in ("CURSOR", "LOOP", "ESCALAT")):
        return "escalation"
    if "P_FINAL_DECISION" in value or "P_STATUS" in value:
        return "decision"
    return "persistence"


def _decision_class(outcome: str) -> str:
    value = outcome.upper()
    if "REJECT" in value or "ERROR" in value or "NOT_FOUND" in value:
        return "reject"
    if "REVIEW" in value or "ESCALAT" in value:
        return "review"
    if "APPROV" in value or "SETTLED" in value:
        return "approve"
    return "neutral"


def _outcome_from_steps(steps: list[dict[str, Any]], fallback: str) -> tuple[str, str | None]:
    outcome = fallback
    exception_flag = None
    for step in steps:
        text = str(step.get("text", ""))
        if step.get("keyword") == "Then" and outcome == fallback:
            outcome = text
        if "P_FINAL_DECISION is set to" in text or "P_STATUS is set to" in text:
            outcome = text.split(" is set to ", 1)[-1].strip()
        if "P_EXCEPTION_FLAG is set to" in text:
            exception_flag = text.split(" is set to ", 1)[-1].strip()
    return outcome, exception_flag



def _split_steps(steps: list[dict[str, Any]]) -> tuple[list[str], list[str]]:
    preconditions: list[str] = []
    outcomes: list[str] = []
    phase = "precondition"
    for step in steps:
        keyword = str(step.get("keyword", ""))
        text = str(step.get("text", ""))
        if keyword == "When":
            phase = "action"
            continue
        if keyword == "Then":
            phase = "outcome"
            outcomes.append(text)
            continue
        if keyword == "Given":
            preconditions.append(text)
            phase = "precondition"
            continue
        if keyword == "And":
            (outcomes if phase == "outcome" else preconditions).append(text)
    return preconditions, outcomes


def _node_map(parse: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not parse:
        return {}
    ast = parse.get("ast") or {}
    return {str(node.get("node_id")): node for node in ast.get("nodes", []) if node.get("node_id")}


def _source_evidence(refs: list[str], nodes: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    values: list[dict[str, Any]] = []
    for ref in refs:
        node = nodes.get(ref)
        if node:
            source_range = node.get("source_range") or {}
            values.append(
                {
                    "ref": ref,
                    "kind": node.get("kind"),
                    "text": node.get("text"),
                    "start_line": source_range.get("start_line"),
                    "end_line": source_range.get("end_line"),
                }
            )
        else:
            values.append({"ref": ref, "kind": None, "text": None, "start_line": None, "end_line": None})
    return values


def _relation_lineage(semantic: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not semantic:
        return []
    relations: dict[str, dict[str, Any]] = {}
    for summary in semantic.get("query_summaries", []):
        for relation in summary.get("relation_refs", []):
            record = relations.setdefault(str(relation), {"relation": str(relation), "queries": [], "status": summary.get("analysis_completeness")})
            record["queries"].append(
                {
                    "kind": summary.get("summary_kind"),
                    "clauses": summary.get("clauses", []),
                    "joins": summary.get("joins", []),
                    "projections": summary.get("projection_expressions", []),
                    "evidence_refs": summary.get("evidence_refs", []),
                }
            )
    return sorted(relations.values(), key=lambda item: item["relation"])


def _decision_requirements(scenarios: list[dict[str, Any]], semantic: dict[str, Any] | None) -> list[dict[str, Any]]:
    counts = {"entry": 0, "decision": 0, "escalation": 0, "persistence": 0}
    for scenario in scenarios:
        counts[str(scenario.get("group", "entry"))] += 1
    if semantic:
        counts["escalation"] += len(semantic.get("loop_summaries", []))
        counts["persistence"] += len(semantic.get("effects", []))
    return [
        {"id": "entry", "icon": "◈", "label": "Entry, Validation & Exceptions", "count": counts["entry"]},
        {"id": "decision", "icon": "▦", "label": "Main Decision Logic", "count": counts["decision"]},
        {"id": "escalation", "icon": "↻", "label": "Escalation & Iteration", "count": counts["escalation"]},
        {"id": "persistence", "icon": "▣", "label": "Persistence & Observable Effects", "count": counts["persistence"]},
    ]


def discover_runs(workspace: Path) -> list[dict[str, Any]]:
    root = workspace.resolve() / "runs"
    if not root.exists():
        return []
    records = []
    for directory in sorted((item for item in root.iterdir() if item.is_dir()), key=lambda item: item.stat().st_mtime_ns, reverse=True):
        proposal = _artifact(directory, "bdd/proposal-manifest.json")
        parse = _artifact(directory, "extraction/02-parse.json", "02-parse.json")
        procedure = (proposal or {}).get("procedure")
        if not procedure and parse:
            ast = parse.get("ast") or {}
            procedure = ".".join(filter(None, (ast.get("schema_name"), ast.get("procedure_name"))))
        records.append(
            {
                "run_name": directory.name,
                "procedure": procedure or directory.name,
                "updated_at": directory.stat().st_mtime,
                "quality_status": ((proposal or {}).get("quality") or {}).get("status", "NOT_EVALUATED"),
            }
        )
    return records


def build_review_dashboard(run_dir: Path) -> dict[str, Any]:
    run_dir = run_dir.resolve()
    if not run_dir.is_dir():
        raise ReviewDashboardError(f"Analysis run does not exist: {run_dir}")
    readable = _artifact(run_dir, "bdd/readable-bdd-document.json")
    proposal = _artifact(run_dir, "bdd/proposal-manifest.json")
    semantic = _artifact(run_dir, "extraction/03-semantic-phase2-4.json", "extraction/03-semantic.json", "03-semantic.json")
    parse = _artifact(run_dir, "extraction/02-parse.json", "02-parse.json")
    lint = _artifact(run_dir, "bdd/lint-report.json")
    feature_validation = _artifact(run_dir, "bdd/feature-validation-report.json")
    if not readable or not proposal:
        raise ReviewDashboardError("The run does not contain readable BDD review artifacts.")

    feature = readable.get("feature") or {}
    rules = feature.get("rules", [])
    proposal_by_id = {str(item.get("proposal_id")): item for item in proposal.get("artifacts", []) if item.get("proposal_id")}
    nodes = _node_map(parse)

    scenarios: list[dict[str, Any]] = []
    decision_rows: list[dict[str, Any]] = []
    for rule_index, rule in enumerate(rules, start=1):
        for scenario_index, scenario in enumerate(rule.get("scenarios", []), start=1):
            group = _scenario_group(str(rule.get("name", "")), str(scenario.get("name", "")))
            steps = scenario.get("steps", [])
            preconditions, outcomes = _split_steps(steps)
            proposal_item = proposal_by_id.get(str(scenario.get("proposal_id")), {})
            evidence_refs = list(dict.fromkeys(proposal_item.get("evidence_refs", [])))
            record = {
                "id": f"scenario-{rule_index}-{scenario_index}",
                "group": group,
                "rule": rule.get("name"),
                "name": scenario.get("name"),
                "kind": scenario.get("kind"),
                "analysis_status": scenario.get("analysis_status"),
                "proposal_kind": scenario.get("proposal_kind"),
                "proposal_id": scenario.get("proposal_id"),
                "tags": scenario.get("tags", []),
                "steps": steps,
                "examples": scenario.get("examples", []),
                "preconditions": preconditions,
                "outcomes": outcomes,
                "source_behavior_refs": scenario.get("source_behavior_refs", []),
                "source_bundle_refs": scenario.get("source_bundle_refs", []),
                "blocker_codes": proposal_item.get("blocker_codes", []),
                "blocker_details": proposal_item.get("blocker_details", []),
                "evidence_refs": evidence_refs,
                "source_evidence": _source_evidence(evidence_refs, nodes),
            }
            scenarios.append(record)
            if group == "decision":
                outcome, exception_flag = _outcome_from_steps(steps, str(scenario.get("name", "")))
                decision_rows.append(
                    {
                        "id": record["id"],
                        "order": len(decision_rows) + 1,
                        "priority": _decision_priority(str(record["rule"]), str(record["name"])),
                        "rule": record["rule"],
                        "scenario": record["name"],
                        "conditions": preconditions,
                        "outcome": outcome,
                        "exception_flag": exception_flag,
                        "class": _decision_class(outcome),
                        "proposal_id": record["proposal_id"],
                        "evidence_refs": evidence_refs,
                        "source_evidence": record["source_evidence"],
                        "status": record["analysis_status"],
                    }
                )

    decision_rows.sort(key=lambda item: (item["priority"], item["order"], item["scenario"]))
    for index, item in enumerate(decision_rows, start=1):
        item["order"] = index

    effects: list[dict[str, Any]] = []
    effect_modality: dict[str, str] = {}
    if semantic:
        for obligation in semantic.get("effect_obligations", []):
            effect_modality[str(obligation.get("effect_ref"))] = str(obligation.get("modality", "UNKNOWN"))
        for effect in semantic.get("effects", []):
            refs = list(effect.get("evidence_refs", []))
            effects.append(
                {
                    "effect_id": effect.get("effect_id"),
                    "kind": effect.get("effect_kind"),
                    "target": effect.get("target"),
                    "group": _effect_group(str(effect.get("effect_kind", "")), str(effect.get("target", ""))),
                    "value": effect.get("value_expression"),
                    "observability": effect.get("observability"),
                    "modality": effect_modality.get(str(effect.get("effect_id")), "UNKNOWN"),
                    "transaction_ref": effect.get("transaction_analysis_ref"),
                    "evidence_refs": refs,
                    "source_evidence": _source_evidence(refs, nodes),
                }
            )

    parse_ast = (parse or {}).get("ast") or {}
    procedure = proposal.get("procedure") or ".".join(filter(None, (parse_ast.get("schema_name"), parse_ast.get("procedure_name"))))
    last_extraction = run_dir.stat().st_mtime
    quality = proposal.get("quality") or {}
    tags = feature.get("tags", [])
    warnings = (lint or {}).get("warning_count", quality.get("warning_count", 0))
    parser = f"{quality.get('parser_name', 'unknown')} {quality.get('parser_version', '')}".strip()

    try:
        decision_model = ExtractedDecisionModelBuilder().build(run_dir)
    except Exception as exc:
        decision_model = None
        what_if_reason = f"Extracted decision model unavailable: {exc}"
    else:
        what_if_reason = (
            "Evaluate the extracted technical decision model from explicit TRUE/FALSE/UNKNOWN "
            "predicate assignments. No business logic is reimplemented in the browser."
            if decision_model.rules
            else "No predicate-controlled observable decision rules were admitted."
        )

    return {
        "run_name": run_dir.name,
        "run_dir": run_dir.as_posix(),
        "procedure": procedure,
        "source_name": (parse or {}).get("source_name"),
        "source_digest": (parse or {}).get("source_digest"),
        "last_extraction": last_extraction,
        "candidate_status": "CANDIDATE_BDD" if proposal.get("review_required") else "TECHNICAL_EVIDENCE",
        "vocabulary_status": "REQUIRES_VOCABULARY_APPROVAL" if "@requires_vocabulary_approval" in tags else "TECHNICAL_VOCABULARY",
        "authority_scope": proposal.get("authority_scope"),
        "quality_status": quality.get("status"),
        "parser": parser,
        "warning_count": warnings,
        "feature_count": (feature_validation or {}).get("feature_count", (feature_validation or {}).get("validated_feature_count")),
        "semantic_digest": proposal.get("semantic_digest"),
        "content_digest": proposal.get("gherkin_content_digest"),
        "decision_requirements": _decision_requirements(scenarios, semantic),
        "decision_rows": decision_rows,
        "scenarios": scenarios,
        "effects": effects,
        "relations": _relation_lineage(semantic),
        "loop_summaries": (semantic or {}).get("loop_summaries", []),
        "findings": (semantic or {}).get("findings", []),
        "what_if_supported": bool(decision_model and decision_model.rules),
        "what_if_reason": what_if_reason,
        "decision_model": (decision_model.model_dump(mode="json") if decision_model else None),
    }
