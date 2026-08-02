from __future__ import annotations

import importlib.metadata
import os
import re
from datetime import datetime, timezone
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from ojas_reconciler.db2_behavior.bdd.gherkin import gherkin_digest
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest


class ReadableBddQualityError(RuntimeError):
    """Raised when emitted readable Gherkin fails a mandatory quality gate."""

    def __init__(self, message: str, *, report: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.report = report or {}


@dataclass(frozen=True)
class ParsedGherkin:
    parser_name: str
    parser_version: str
    raw_document: dict[str, Any]
    normalized_document: dict[str, Any]


class OfficialGherkinParser:
    REQUIRED_DISTRIBUTION_VERSION = "42.0.0"

    """Thin adapter around Cucumber's official Python Gherkin parser.

    The fallback is intentionally test-only. Production generation fails closed
    when the mandatory dependency is unavailable.
    """

    @staticmethod
    def _load_official_parser() -> Any:
        from gherkin.parser import Parser  # type: ignore[import-not-found]

        return Parser

    def parse(self, text: str) -> ParsedGherkin:
        parser_name = "gherkin-official"
        parser_version = _distribution_version("gherkin-official")
        parser_callable: Any
        try:
            Parser = self._load_official_parser()
        except ImportError as exc:
            if (os.environ.get("ATLAS_TEST_ALLOW_GHERKIN_FALLBACK") or os.environ.get("OJAS_TEST_ALLOW_GHERKIN_FALLBACK")) == "1":
                parser_name = "ojas-test-canonical-gherkin-parser"
                parser_version = "test-only"
                parser_callable = _parse_canonical_gherkin_for_tests
            else:
                raise ReadableBddQualityError(
                    "Mandatory dependency gherkin-official is not installed. "
                    "Install the declared project dependencies before generating readable BDD."
                ) from exc
        else:
            if parser_version != self.REQUIRED_DISTRIBUTION_VERSION:
                report = _base_lint_report(
                    parser_name=parser_name, parser_version=parser_version
                )
                report["issues"].append(
                    _issue(
                        "UNSUPPORTED_GHERKIN_PARSER_VERSION",
                        "ERROR",
                        "Installed gherkin-official version does not match the release-pinned version.",
                        details={
                            "required_version": self.REQUIRED_DISTRIBUTION_VERSION,
                            "installed_version": parser_version,
                        },
                    )
                )
                _finish_report(report, feature_name="")
                raise ReadableBddQualityError(
                    "Official Gherkin parser version gate failed.", report=report
                )
            parser_callable = lambda value: Parser().parse(value)

        try:
            raw = parser_callable(text)
        except Exception as exc:  # official parser exposes generated exception types
            report = _base_lint_report(
                parser_name=parser_name,
                parser_version=parser_version,
            )
            report["issues"].append(
                _issue(
                    "GHERKIN_PARSE_ERROR",
                    "ERROR",
                    f"Gherkin parser rejected emitted text: {exc}",
                    details={"exception_type": type(exc).__name__},
                )
            )
            _finish_report(report, feature_name="")
            raise ReadableBddQualityError(
                "Official Gherkin parse gate failed.", report=report
            ) from exc

        normalized = (
            raw
            if parser_name == "ojas-test-canonical-gherkin-parser"
            else normalize_official_gherkin_document(raw)
        )
        return ParsedGherkin(
            parser_name=parser_name,
            parser_version=parser_version,
            raw_document=raw,
            normalized_document=normalized,
        )


class ReadableBddQualityGate:
    VERSION = "readable-bdd-quality-gate-1.1.1"

    HARD_CODES = {
        "GHERKIN_PARSE_ERROR",
        "AST_READABLE_MODEL_MISMATCH",
        "DUPLICATE_SCENARIO_NAME",
        "EXACT_DUPLICATE_SCENARIO",
        "INCONSISTENT_CANONICAL_VOCABULARY",
        "BROKEN_OUTLINE_EXAMPLES",
        "MISSING_THEN_BY_OJAS_POLICY",
        "UNSUPPORTED_GHERKIN_PARSER_VERSION",
        "WARNING_GOVERNANCE_FAILED",
    }

    def __init__(self, parser: OfficialGherkinParser | None = None) -> None:
        self.parser = parser or OfficialGherkinParser()

    def validate(
        self,
        *,
        readable_document: dict[str, Any],
        feature_text: str,
        warning_policy: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        parsed = self.parser.parse(feature_text)
        expected_projection = _readable_feature_projection(readable_document["feature"])
        actual_projection = parsed.normalized_document["feature"]
        feature_name = str(expected_projection.get("name", ""))
        report = _base_lint_report(
            parser_name=parsed.parser_name,
            parser_version=parsed.parser_version,
        )

        if actual_projection != expected_projection:
            report["issues"].append(
                _issue(
                    "AST_READABLE_MODEL_MISMATCH",
                    "ERROR",
                    "Parsed Gherkin structure differs from the Atlas ReadableBddDocument projection.",
                    details={
                        "expected_digest": canonical_digest(expected_projection),
                        "actual_digest": canonical_digest(actual_projection),
                        "feature_name": feature_name,
                    },
                )
            )

        report["issues"].extend(
            _lint_normalized_document(
                actual_projection, readable_feature=readable_document["feature"]
            )
        )
        _finish_report(report, feature_name=feature_name)
        _apply_warning_governance(
            report, warning_policy=warning_policy, feature_name=feature_name
        )
        _finish_report(report, feature_name=feature_name, preserve_fingerprints=True)

        gherkin_projection = {
            "schema_version": "normalized-gherkin-document-1.0",
            "parser_name": parsed.parser_name,
            "parser_version": parsed.parser_version,
            "feature": actual_projection,
        }
        gherkin_projection["structure_digest"] = canonical_digest(actual_projection)

        if report["error_count"]:
            raise ReadableBddQualityError(
                "Readable BDD quality gate failed.", report=report
            )

        return {
            "readable_document": readable_document,
            "gherkin_document": gherkin_projection,
            "lint_report": report,
            "semantic_digest": readable_document["semantic_digest"],
            "gherkin_content_digest": gherkin_digest(feature_text),
            "gherkin_structure_digest": gherkin_projection["structure_digest"],
            "lint_report_digest": report["lint_report_digest"],
        }

    def validate_feature_collection(
        self, *, feature_files: Iterable[tuple[str, str]]
    ) -> dict[str, Any]:
        records: list[dict[str, Any]] = []
        issues: list[dict[str, Any]] = []
        parser_names: set[tuple[str, str]] = set()
        for artifact_ref, text in sorted(feature_files):
            try:
                parsed = self.parser.parse(text)
            except ReadableBddQualityError as exc:
                for issue in exc.report.get("issues", []):
                    details = dict(issue.get("details", {}))
                    details["artifact_ref"] = artifact_ref
                    issues.append({**issue, "details": details})
                if not exc.report.get("issues"):
                    issues.append(
                        _issue(
                            "GHERKIN_PARSE_ERROR",
                            "ERROR",
                            f"Feature artifact {artifact_ref!r} could not be parsed: {exc}",
                            details={"artifact_ref": artifact_ref},
                        )
                    )
                continue
            parser_names.add((parsed.parser_name, parsed.parser_version))
            feature = parsed.normalized_document.get("feature", {})
            records.append(
                {
                    "artifact_ref": artifact_ref,
                    "parser_name": parsed.parser_name,
                    "parser_version": parsed.parser_version,
                    "gherkin_content_digest": gherkin_digest(text),
                    "gherkin_structure_digest": canonical_digest(feature),
                    "feature_name": feature.get("name", ""),
                    "scenario_count": sum(
                        len(rule.get("scenarios", []))
                        for rule in feature.get("rules", [])
                    ),
                }
            )
        report = {
            "schema_version": "gherkin-feature-validation-report-1.0",
            "quality_gate_version": self.VERSION,
            "status": "FAILED" if issues else "PASSED",
            "error_count": len(issues),
            "validated_feature_count": len(records),
            "parser_identities": [
                {"parser_name": name, "parser_version": version}
                for name, version in sorted(parser_names)
            ],
            "features": records,
            "issues": issues,
        }
        report["feature_validation_report_digest"] = canonical_digest(report)
        if issues:
            raise ReadableBddQualityError(
                "One or more emitted feature files failed the parse gate.", report=report
            )
        return report


def build_readable_document(
    *,
    qualified: str,
    feature_tags: Iterable[str],
    entries: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    values = list(entries)
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    first_order: dict[str, tuple[int, str]] = {}
    for entry in values:
        rule = str(entry["rule_name"])
        grouped[rule].append(entry)
        first_order.setdefault(rule, (int(entry["display_order"]), rule))

    rules: list[dict[str, Any]] = []
    for rule_name in sorted(grouped, key=lambda value: first_order[value]):
        scenarios: list[dict[str, Any]] = []
        for entry in sorted(
            grouped[rule_name],
            key=lambda item: (item["display_order"], item["proposal_id"]),
        ):
            given = list(entry.get("_given_lines", ()))
            then = list(entry.get("_then_lines", ()))
            action = str(entry.get("_action_line") or "")
            steps: list[dict[str, str]] = []
            for index, text in enumerate(given):
                steps.append({"keyword": "Given" if index == 0 else "And", "text": text})
            steps.append({"keyword": "When", "text": action})
            for index, text in enumerate(then):
                steps.append({"keyword": "Then" if index == 0 else "And", "text": text})
            scenarios.append(
                {
                    "kind": entry.get("_scenario_kind", "Scenario"),
                    "name": entry["scenario_name"],
                    "tags": list(entry.get("_scenario_tags", ())),
                    "steps": steps,
                    "examples": list(entry.get("_examples", ())),
                    "proposal_id": entry["proposal_id"],
                    "proposal_kind": entry["proposal_kind"],
                    "analysis_status": entry["analysis_status"],
                    "source_behavior_refs": list(entry.get("source_behavior_refs", ())),
                    "source_bundle_refs": list(entry.get("source_bundle_refs", ())),
                }
            )
        rules.append({"name": rule_name, "scenarios": scenarios})

    document_without_digest = {
        "schema_version": "readable-bdd-document-1.0",
        "feature": {
            "name": f"{qualified} readable technical candidates",
            "tags": list(feature_tags),
            "rules": rules,
        },
    }
    return {
        **document_without_digest,
        "semantic_digest": canonical_digest(document_without_digest),
    }



def _readable_feature_projection(feature: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": feature.get("name", ""),
        "tags": list(feature.get("tags", [])),
        "rules": [
            {
                "name": rule.get("name", ""),
                "scenarios": [
                    {
                        "kind": scenario.get("kind", "Scenario"),
                        "name": scenario.get("name", ""),
                        "tags": list(scenario.get("tags", [])),
                        "steps": list(scenario.get("steps", [])),
                        "examples": list(scenario.get("examples", [])),
                    }
                    for scenario in rule.get("scenarios", [])
                ],
            }
            for rule in feature.get("rules", [])
        ],
    }

def normalize_official_gherkin_document(raw: dict[str, Any]) -> dict[str, Any]:
    feature = raw.get("feature")
    if not isinstance(feature, dict):
        return {"feature": {"name": "", "tags": [], "rules": []}}
    rules: list[dict[str, Any]] = []
    unruled: list[dict[str, Any]] = []
    for child in feature.get("children", []):
        if "rule" in child:
            rule = child["rule"]
            scenarios = [
                _normalize_official_scenario(grandchild["scenario"])
                for grandchild in rule.get("children", [])
                if "scenario" in grandchild
            ]
            rules.append({"name": rule.get("name", ""), "scenarios": scenarios})
        elif "scenario" in child:
            unruled.append(_normalize_official_scenario(child["scenario"]))
    if unruled:
        rules.insert(0, {"name": "", "scenarios": unruled})
    return {
        "feature": {
            "name": feature.get("name", ""),
            "tags": [tag.get("name", "") for tag in feature.get("tags", [])],
            "rules": rules,
        }
    }


def _normalize_official_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    examples_values: list[dict[str, Any]] = []
    for examples in scenario.get("examples", []):
        header = examples.get("tableHeader") or {}
        headers = [cell.get("value", "") for cell in header.get("cells", [])]
        rows = [
            [cell.get("value", "") for cell in row.get("cells", [])]
            for row in examples.get("tableBody", [])
        ]
        examples_values.append({"headers": headers, "rows": rows})
    keyword = str(scenario.get("keyword") or "Scenario").strip()
    kind = "Scenario Outline" if "Outline" in keyword or examples_values else "Scenario"
    return {
        "kind": kind,
        "name": scenario.get("name", ""),
        "tags": [tag.get("name", "") for tag in scenario.get("tags", [])],
        "steps": [
            {
                "keyword": str(step.get("keyword") or "").strip(),
                "text": step.get("text", ""),
            }
            for step in scenario.get("steps", [])
        ],
        "examples": examples_values,
    }


def _lint_normalized_document(
    feature: dict[str, Any], *, readable_feature: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    scenarios = [
        (rule.get("name", ""), scenario)
        for rule in feature.get("rules", [])
        for scenario in rule.get("scenarios", [])
    ]
    context_index = _readable_context_index(readable_feature or {})

    name_counts = Counter(scenario.get("name", "") for _, scenario in scenarios)
    for name, count in sorted(name_counts.items()):
        if name and count > 1:
            issues.append(
                _issue(
                    "DUPLICATE_SCENARIO_NAME",
                    "ERROR",
                    f"Scenario name {name!r} appears {count} times.",
                    details={"scenario_name": name, "occurrence_count": count},
                )
            )

    exact: dict[str, list[str]] = defaultdict(list)
    for rule_name, scenario in scenarios:
        identity = canonical_digest(
            {
                "rule": rule_name,
                "tags": scenario.get("tags", []),
                "steps": scenario.get("steps", []),
                "examples": scenario.get("examples", []),
            }
        )
        exact[identity].append(str(scenario.get("name", "")))
    for names in exact.values():
        if len(names) > 1:
            issues.append(
                _issue(
                    "EXACT_DUPLICATE_SCENARIO",
                    "ERROR",
                    f"Scenarios share an identical structure: {sorted(names)!r}.",
                    details={"scenario_names": sorted(names)},
                )
            )

    casing: dict[str, set[str]] = defaultdict(set)
    for _, scenario in scenarios:
        for step in scenario.get("steps", []):
            text = str(step.get("text", ""))
            casing[text.casefold()].add(text)
    for values in casing.values():
        if len(values) > 1:
            issues.append(
                _issue(
                    "INCONSISTENT_CANONICAL_VOCABULARY",
                    "ERROR",
                    f"Step texts differ only by case: {sorted(values)!r}.",
                    details={"step_variants": sorted(values)},
                )
            )

    for rule_name, scenario in scenarios:
        roles = _step_roles(scenario.get("steps", []))
        if "THEN" not in roles:
            issues.append(
                _issue(
                    "MISSING_THEN_BY_OJAS_POLICY",
                    "ERROR",
                    f"Scenario {scenario.get('name')!r} under rule {rule_name!r} has no Then outcome.",
                    details=_scenario_details(context_index, rule_name, scenario),
                )
            )
        if scenario.get("kind") == "Scenario Outline":
            placeholders = set(
                re.findall(
                    r"<([A-Za-z0-9_]+)>",
                    " ".join(
                        [str(scenario.get("name", ""))]
                        + [str(step.get("text", "")) for step in scenario.get("steps", [])]
                    ),
                )
            )
            examples = scenario.get("examples", [])
            headers = set(examples[0].get("headers", [])) if examples else set()
            row_widths = {
                len(row)
                for example in examples
                for row in example.get("rows", [])
            }
            if (
                not examples
                or placeholders != headers
                or row_widths not in ({len(headers)}, set())
                or not all(example.get("rows") for example in examples)
            ):
                issues.append(
                    _issue(
                        "BROKEN_OUTLINE_EXAMPLES",
                        "ERROR",
                        f"Scenario Outline {scenario.get('name')!r} placeholders and examples do not match.",
                        details={
                            "placeholders": sorted(placeholders),
                            "headers": sorted(headers),
                        },
                    )
                )

    for index, (rule_name, scenario) in enumerate(scenarios):
        then_set = _then_bundle(scenario.get("steps", []))
        given_set = _given_bundle(scenario.get("steps", []))
        if not then_set:
            continue
        for other_rule, other in scenarios[index + 1 :]:
            other_then = _then_bundle(other.get("steps", []))
            other_given = _given_bundle(other.get("steps", []))
            if then_set == other_then and given_set != other_given:
                issues.append(
                    _issue(
                        "POSSIBLE_DUPLICATE_EFFECT_BUNDLE",
                        "WARNING",
                        f"Scenarios {scenario.get('name')!r} and {other.get('name')!r} share an outcome bundle but have distinct preconditions.",
                        details=_pair_details(context_index, rule_name, scenario, other_rule, other),
                    )
                )
            elif then_set < other_then or other_then < then_set:
                issues.append(
                    _issue(
                        "POSSIBLE_SUBSUMED_SCENARIO",
                        "WARNING",
                        f"Outcome steps for {scenario.get('name')!r} and {other.get('name')!r} have a strict subset relationship.",
                        details=_pair_details(context_index, rule_name, scenario, other_rule, other),
                    )
                )

        when_texts = [
            str(step.get("text", ""))
            for step, role in zip(scenario.get("steps", []), _step_roles_in_order(scenario.get("steps", [])))
            if role == "WHEN"
        ]
        if any(text.endswith(" is invoked") for text in when_texts) and any(
            "prerequisite statements complete successfully" in value.casefold()
            for value in given_set
        ):
            issues.append(
                _issue(
                    "GENERIC_INVOCATION_WHEN",
                    "WARNING",
                    f"Scenario {scenario.get('name')!r} uses generic invocation wording with a generic prerequisite.",
                    details=_scenario_details(context_index, rule_name, scenario),
                )
            )

    same_rule_bundles: dict[tuple[str, tuple[str, ...]], list[str]] = defaultdict(list)
    for rule_name, scenario in scenarios:
        if scenario.get("kind") != "Scenario":
            continue
        same_rule_bundles[(rule_name, tuple(sorted(_then_bundle(scenario.get("steps", [])))))].append(
            str(scenario.get("name", ""))
        )
    for (rule_name, _), names in same_rule_bundles.items():
        if len(names) > 1:
            issues.append(
                _issue(
                    "OUTLINE_CANDIDATE",
                    "WARNING",
                    f"Rule {rule_name!r} contains scenarios with the same outcome skeleton: {sorted(names)!r}.",
                    details={"rule_name": rule_name, "scenario_names": sorted(names)},
                )
            )
    return issues


def _step_roles(steps: Iterable[dict[str, Any]]) -> set[str]:
    return set(_step_roles_in_order(steps))


def _step_roles_in_order(steps: Iterable[dict[str, Any]]) -> list[str]:
    result: list[str] = []
    current = ""
    for step in steps:
        keyword = str(step.get("keyword", "")).strip().upper()
        if keyword == "GIVEN":
            current = "GIVEN"
        elif keyword == "WHEN":
            current = "WHEN"
        elif keyword == "THEN":
            current = "THEN"
        result.append(current)
    return result


def _then_bundle(steps: Iterable[dict[str, Any]]) -> set[str]:
    roles = _step_roles_in_order(steps)
    return {
        str(step.get("text", "")).casefold()
        for step, role in zip(steps, roles)
        if role == "THEN"
    }


def _given_bundle(steps: Iterable[dict[str, Any]]) -> set[str]:
    roles = _step_roles_in_order(steps)
    return {
        str(step.get("text", "")).casefold()
        for step, role in zip(steps, roles)
        if role == "GIVEN"
    }


def _base_lint_report(*, parser_name: str, parser_version: str) -> dict[str, Any]:
    return {
        "schema_version": "readable-bdd-lint-report-1.1",
        "quality_gate_version": ReadableBddQualityGate.VERSION,
        "parser_name": parser_name,
        "parser_version": parser_version,
        "status": "PENDING",
        "error_count": 0,
        "warning_count": 0,
        "issues": [],
        "warning_governance": {
            "mode": "REPORT_ONLY",
            "status": "NOT_EVALUATED",
            "baseline_warning_count": 0,
            "current_warning_count": 0,
            "new_warning_count": 0,
            "waived_warning_count": 0,
            "expired_waiver_count": 0,
        },
    }


def _issue(
    code: str,
    severity: str,
    message: str,
    *,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "details": details or {},
    }


def _finish_report(
    report: dict[str, Any], *, feature_name: str, preserve_fingerprints: bool = False
) -> None:
    for issue in report.get("issues", []):
        details = dict(issue.get("details", {}))
        details.setdefault("feature_name", feature_name)
        issue["details"] = details
        if not preserve_fingerprints or "fingerprint" not in issue:
            issue["fingerprint"] = canonical_digest(
                {
                    "code": issue.get("code"),
                    "feature_name": feature_name,
                    "details": details,
                    "message": issue.get("message"),
                }
            )
    report["issues"].sort(
        key=lambda item: (
            0 if item["severity"] == "ERROR" else 1,
            item["code"],
            item["message"],
        )
    )
    report["error_count"] = sum(
        1 for item in report["issues"] if item["severity"] == "ERROR"
    )
    report["warning_count"] = sum(
        1 for item in report["issues"] if item["severity"] == "WARNING"
    )
    if report["error_count"]:
        report["status"] = "FAILED"
    elif report["warning_count"]:
        governance_status = report.get("warning_governance", {}).get("status")
        report["status"] = (
            "PASSED_WITH_WARNINGS"
            if governance_status == "GOVERNED"
            else "PASSED_WITH_WARNINGS_REVIEW_REQUIRED"
        )
    else:
        report["status"] = "PASSED"
    without_digest = dict(report)
    without_digest.pop("lint_report_digest", None)
    report["lint_report_digest"] = canonical_digest(without_digest)


def _apply_warning_governance(
    report: dict[str, Any], *, warning_policy: dict[str, Any] | None, feature_name: str
) -> None:
    warnings = [i for i in report.get("issues", []) if i.get("severity") == "WARNING"]
    policy = warning_policy or {
        "schema_version": "readable-bdd-warning-policy-1.0",
        "mode": "REPORT_ONLY",
        "baseline_fingerprints": [],
        "waivers": [],
    }
    mode = str(policy.get("mode", "REPORT_ONLY"))
    baseline = {str(value) for value in policy.get("baseline_fingerprints", [])}
    now = datetime.now(timezone.utc)
    valid_waivers: set[str] = set()
    expired: list[str] = []
    for waiver in policy.get("waivers", []):
        fingerprint = str(waiver.get("fingerprint", ""))
        expires_at = str(waiver.get("expires_at", ""))
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            expiry = datetime.min.replace(tzinfo=timezone.utc)
        if expiry >= now and all(
            str(waiver.get(field, "")).strip()
            for field in ("justification", "owner", "approved_by", "release_scope")
        ):
            valid_waivers.add(fingerprint)
        else:
            expired.append(fingerprint)
    current = {str(item.get("fingerprint", "")) for item in warnings}
    new = sorted(current - baseline - valid_waivers)
    expired_current = sorted(current & set(expired))
    max_warning_count = policy.get("max_warning_count")
    budget_exceeded = (
        isinstance(max_warning_count, int) and len(warnings) > max_warning_count
    )
    governance_status = "CLEAN"
    if warnings and mode == "REPORT_ONLY":
        governance_status = "REVIEW_REQUIRED"
    elif new or expired_current or budget_exceeded:
        governance_status = "FAILED" if mode == "NO_NEW_WARNINGS" else "REVIEW_REQUIRED"
    elif warnings:
        governance_status = "GOVERNED"
    report["warning_governance"] = {
        "mode": mode,
        "status": governance_status,
        "baseline_warning_count": len(baseline),
        "current_warning_count": len(current),
        "new_warning_count": len(new),
        "new_warning_fingerprints": new,
        "waived_warning_count": len(current & valid_waivers),
        "expired_waiver_count": len(expired_current),
        "expired_waiver_fingerprints": expired_current,
        "max_warning_count": max_warning_count,
        "budget_exceeded": budget_exceeded,
        "policy_digest": canonical_digest(policy),
    }
    if mode == "NO_NEW_WARNINGS" and (new or expired_current or budget_exceeded):
        report["issues"].append(
            _issue(
                "WARNING_GOVERNANCE_FAILED",
                "ERROR",
                "Readable BDD warnings violate the configured no-new-warnings policy.",
                details={
                    "feature_name": feature_name,
                    "new_warning_fingerprints": new,
                    "expired_waiver_fingerprints": expired_current,
                    "budget_exceeded": budget_exceeded,
                },
            )
        )


def _readable_context_index(feature: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    return {
        (str(rule.get("name", "")), str(scenario.get("name", ""))): scenario
        for rule in feature.get("rules", [])
        for scenario in rule.get("scenarios", [])
    }


def _scenario_details(
    context_index: dict[tuple[str, str], dict[str, Any]],
    rule_name: str,
    scenario: dict[str, Any],
) -> dict[str, Any]:
    name = str(scenario.get("name", ""))
    context = context_index.get((rule_name, name), {})
    return {
        "rule_name": rule_name,
        "scenario_name": name,
        "proposal_id": context.get("proposal_id"),
        "proposal_kind": context.get("proposal_kind"),
        "analysis_status": context.get("analysis_status"),
        "source_behavior_refs": list(context.get("source_behavior_refs", [])),
        "source_bundle_refs": list(context.get("source_bundle_refs", [])),
    }


def _pair_details(
    context_index: dict[tuple[str, str], dict[str, Any]],
    left_rule: str,
    left: dict[str, Any],
    right_rule: str,
    right: dict[str, Any],
) -> dict[str, Any]:
    return {
        "left": _scenario_details(context_index, left_rule, left),
        "right": _scenario_details(context_index, right_rule, right),
    }


def _distribution_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "UNKNOWN"


def _parse_canonical_gherkin_for_tests(text: str) -> dict[str, Any]:
    """Parse only the deterministic subset emitted by this renderer.

    This is not a production fallback and is enabled only by an explicit test
    environment variable when the official wheel is unavailable in the build
    sandbox.
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    feature_tags: list[str] = []
    feature_name = ""
    rules: list[dict[str, Any]] = []
    current_rule: dict[str, Any] | None = None
    pending_tags: list[str] = []
    current_scenario: dict[str, Any] | None = None
    current_examples: dict[str, Any] | None = None

    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("@"):
            tags = stripped.split()
            if not feature_name:
                feature_tags.extend(tags)
            else:
                pending_tags.extend(tags)
            continue
        if stripped.startswith("Feature:"):
            feature_name = stripped.split(":", 1)[1].strip()
            continue
        if stripped.startswith("Rule:"):
            current_rule = {"name": stripped.split(":", 1)[1].strip(), "scenarios": []}
            rules.append(current_rule)
            current_scenario = None
            continue
        if stripped.startswith("Scenario Outline:") or stripped.startswith("Scenario:"):
            if current_rule is None:
                current_rule = {"name": "", "scenarios": []}
                rules.append(current_rule)
            kind = "Scenario Outline" if stripped.startswith("Scenario Outline:") else "Scenario"
            current_scenario = {
                "kind": kind,
                "name": stripped.split(":", 1)[1].strip(),
                "tags": pending_tags,
                "steps": [],
                "examples": [],
            }
            pending_tags = []
            current_rule["scenarios"].append(current_scenario)
            current_examples = None
            continue
        if stripped.startswith("Examples:"):
            if current_scenario is None:
                raise ValueError("Examples without Scenario Outline")
            current_examples = {"headers": [], "rows": []}
            current_scenario["examples"].append(current_examples)
            continue
        if stripped.startswith("|") and current_examples is not None:
            cells = [cell.strip() for cell in stripped.strip("|").split("|")]
            if not current_examples["headers"]:
                current_examples["headers"] = cells
            else:
                current_examples["rows"].append(cells)
            continue
        match = re.match(r"^(Given|When|Then|And|But)\s+(.+)$", stripped)
        if match and current_scenario is not None:
            current_scenario["steps"].append(
                {"keyword": match.group(1), "text": match.group(2)}
            )
            continue
        raise ValueError(f"Unsupported canonical Gherkin line: {raw!r}")

    return {"feature": {"name": feature_name, "tags": feature_tags, "rules": rules}}
