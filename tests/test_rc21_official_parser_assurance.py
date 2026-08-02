from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

import ojas_reconciler.db2_behavior.bdd.readable_quality as readable_quality_module
from ojas_reconciler.db2_behavior.application.deliverables import (
    DeliverablesGenerationBlocked,
    DeliverablesGenerator,
)
from ojas_reconciler.db2_behavior.bdd.gherkin import gherkin_digest
from ojas_reconciler.db2_behavior.bdd.readable_quality import (
    OfficialGherkinParser,
    ParsedGherkin,
    ReadableBddQualityError,
    ReadableBddQualityGate,
    _parse_canonical_gherkin_for_tests,
)
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.core.release_models import AuthorityMode
from atlas.pytest_evidence_summary import outcome_counts, skip_reason_groups

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "advanced_claim_orchestrate_db2.sql"
UPSTREAM_GHERKIN_FIXTURES = ROOT / "tests" / "fixtures" / "gherkin-official"
UPSTREAM_BAD_FIXTURES = (
    "file_ends_with_open_docstring.feature",
    "inconsistent_cell_count.feature",
    "whitespace_in_tags.feature",
)


def _scenario(
    name: str,
    *,
    given: str = "a condition holds",
    when: str = "an action occurs",
    then: str | None = "an outcome occurs",
    kind: str = "Scenario",
    examples: list[dict[str, Any]] | None = None,
    proposal_id: str | None = None,
) -> dict[str, Any]:
    steps = [
        {"keyword": "Given", "text": given},
        {"keyword": "When", "text": when},
    ]
    if then is not None:
        steps.append({"keyword": "Then", "text": then})
    return {
        "kind": kind,
        "name": name,
        "tags": [],
        "steps": steps,
        "examples": examples or [],
        "proposal_id": proposal_id or f"proposal-{name.lower().replace(' ', '-')}",
        "proposal_kind": "BEHAVIOR",
        "analysis_status": "CONDITIONAL_TECHNICAL_CANDIDATE",
        "source_behavior_refs": [f"behavior:{name}"],
        "source_bundle_refs": [f"bundle:{name}"],
    }


def _readable(*scenarios: dict[str, Any], rule_name: str = "R") -> dict[str, Any]:
    without_digest = {
        "schema_version": "readable-bdd-document-1.0",
        "feature": {
            "name": "S.P readable technical candidates",
            "tags": ["@technical_candidate"],
            "rules": [{"name": rule_name, "scenarios": list(scenarios)}],
        },
    }
    return {**without_digest, "semantic_digest": canonical_digest(without_digest)}


def _feature(*blocks: str) -> str:
    return (
        "@technical_candidate\n"
        "Feature: S.P readable technical candidates\n\n"
        "  Rule: R\n\n"
        + "\n\n".join(blocks)
        + "\n"
    )


def _scenario_text(
    name: str,
    *,
    given: str = "a condition holds",
    when: str = "an action occurs",
    then: str | None = "an outcome occurs",
) -> str:
    lines = [
        f"    Scenario: {name}",
        f"      Given {given}",
        f"      When {when}",
    ]
    if then is not None:
        lines.append(f"      Then {then}")
    return "\n".join(lines)


def _issue_codes(exc: pytest.ExceptionInfo[ReadableBddQualityError]) -> set[str]:
    return {str(item["code"]) for item in exc.value.report.get("issues", [])}


class _CanonicalTestParser:
    """Explicit test-only parser for Ojas lint-rule unit tests."""

    def parse(self, text: str) -> ParsedGherkin:
        normalized = _parse_canonical_gherkin_for_tests(text)
        return ParsedGherkin(
            "ojas-test-canonical-gherkin-parser",
            "test-only",
            normalized,
            normalized,
        )


def _lint_gate() -> ReadableBddQualityGate:
    return ReadableBddQualityGate(parser=_CanonicalTestParser())


def _unterminated_docstring() -> str:
    return (
        "Feature: X\n"
        "  Scenario: Y\n"
        "    Given a document\n"
        '      """\n'
        "      unterminated content\n"
    )


def _upstream_bad_fixture(name: str) -> str:
    return (UPSTREAM_GHERKIN_FIXTURES / "bad" / name).read_text(encoding="utf-8")


def _git_blob_sha1(content: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(content)}\0".encode("ascii") + content, usedforsecurity=False
    ).hexdigest()




def test_release_evidence_counts_parameterized_skips() -> None:
    evidence = {
        "outcomes": {"passed": 205, "failed": 0, "skipped": 6, "errors": 0},
        "skip_reason_groups": [
            {"reason": "missing gherkin at parser.py:10", "count": 3},
            {"reason": "missing gherkin at parser.py:20", "count": 1},
        ],
    }
    counts = outcome_counts(evidence)
    groups = skip_reason_groups(evidence)
    assert counts["passed"] == 205
    assert counts["skipped"] == 6
    assert sum(int(item["count"]) for item in groups) == 4
    assert len(groups) == 2


def test_generation_persists_integrity_artifacts_and_cross_digests(tmp_path: Path) -> None:
    output = tmp_path / "advanced"
    DeliverablesGenerator().generate(
        source=FIXTURE,
        output_dir=output,
        authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
    )
    bdd = output / "bdd"
    feature_text = (bdd / "READABLE_CANDIDATES.feature").read_text(encoding="utf-8")
    manifest = json.loads((bdd / "proposal-manifest.json").read_text())
    readable = json.loads((bdd / "readable-bdd-document.json").read_text())
    gherkin = json.loads((bdd / "gherkin-document.json").read_text())
    lint = json.loads((bdd / "lint-report.json").read_text())
    feature_validation = json.loads((bdd / "feature-validation-report.json").read_text())

    for schema_name, payload in [
        ("readable-bdd-proposal-batch-1.5.schema.json", manifest),
        ("readable-bdd-document-1.0.schema.json", readable),
        ("normalized-gherkin-document-1.0.schema.json", gherkin),
        ("readable-bdd-lint-report-1.1.schema.json", lint),
        ("gherkin-feature-validation-report-1.0.schema.json", feature_validation),
    ]:
        schema = json.loads((ROOT / "contracts" / schema_name).read_text())
        Draft202012Validator(schema).validate(payload)

    assert manifest["quality"]["error_count"] == 0
    assert manifest["semantic_digest"] == readable["semantic_digest"]
    assert manifest["gherkin_content_digest"] == gherkin_digest(feature_text)
    assert manifest["gherkin_structure_digest"] == gherkin["structure_digest"]
    assert manifest["lint_report_digest"] == lint["lint_report_digest"]
    digests = manifest["quality"]["quality_artifact_digests"]
    assert digests["feature_text"] == gherkin_digest(feature_text)
    assert digests["readable_bdd_document"] == canonical_digest(readable)
    assert digests["gherkin_document"] == canonical_digest(gherkin)
    assert digests["lint_report"] == canonical_digest(lint)
    assert digests["feature_validation_report"] == canonical_digest(feature_validation)
    expected_manifest = dict(manifest)
    manifest_digest = expected_manifest.pop("manifest_digest")
    assert manifest_digest == canonical_digest(expected_manifest)
    assert feature_validation["status"] == "PASSED"
    assert feature_validation["validated_feature_count"] == len(feature_validation["features"])
    refs = {item["artifact_ref"] for item in feature_validation["features"]}
    assert "bdd/READABLE_CANDIDATES.feature" in refs
    assert any(ref.startswith("bdd/readable-candidates/") for ref in refs)
    assert any(ref.startswith("bdd/technical/") for ref in refs)
    assert any(ref.startswith("test-package/features/") for ref in refs)
    assert all(issue["fingerprint"].startswith("sha256:") for issue in lint["issues"])
    assert all(issue["details"].get("feature_name") for issue in lint["issues"])
    if lint["warning_count"]:
        assert lint["status"] == "PASSED_WITH_WARNINGS_REVIEW_REQUIRED"
        assert lint["warning_governance"]["status"] == "REVIEW_REQUIRED"


def test_fallback_parser_rejects_genuinely_malformed_gherkin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_official_parser() -> Any:
        raise ImportError("simulated missing gherkin-official")

    monkeypatch.setattr(
        OfficialGherkinParser,
        "_load_official_parser",
        staticmethod(missing_official_parser),
    )
    monkeypatch.setenv("OJAS_TEST_ALLOW_GHERKIN_FALLBACK", "1")
    with pytest.raises(ReadableBddQualityError) as exc:
        OfficialGherkinParser().parse(_unterminated_docstring())
    assert "GHERKIN_PARSE_ERROR" in _issue_codes(exc)
    assert exc.value.report["parser_name"] == "ojas-test-canonical-gherkin-parser"
    assert exc.value.report["parser_version"] == "test-only"


@pytest.mark.parametrize("fixture_name", UPSTREAM_BAD_FIXTURES)
def test_official_parser_rejects_pinned_upstream_bad_fixture(
    fixture_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("gherkin")
    monkeypatch.delenv("OJAS_TEST_ALLOW_GHERKIN_FALLBACK", raising=False)
    with pytest.raises(ReadableBddQualityError) as exc:
        OfficialGherkinParser().parse(_upstream_bad_fixture(fixture_name))
    assert "GHERKIN_PARSE_ERROR" in _issue_codes(exc)
    assert exc.value.report["parser_name"] == "gherkin-official"
    assert exc.value.report["parser_version"] == "42.0.0"


def test_official_parser_accepts_feature_description_that_looks_like_steps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("gherkin")
    monkeypatch.delenv("OJAS_TEST_ALLOW_GHERKIN_FALLBACK", raising=False)
    source = (
        "Feature: X\n"
        "  this is descriptive text\n"
        "  Given this also remains description text\n"
    )
    parsed = OfficialGherkinParser().parse(source)
    assert parsed.parser_name == "gherkin-official"
    assert parsed.parser_version == "42.0.0"
    feature = parsed.raw_document["feature"]
    assert "this is descriptive text" in feature.get("description", "")
    assert "Given this also remains description text" in feature.get("description", "")
    assert feature.get("children", []) == []


def test_pinned_upstream_bad_fixture_provenance_and_hashes() -> None:
    provenance = json.loads(
        (UPSTREAM_GHERKIN_FIXTURES / "UPSTREAM_FIXTURES.json").read_text(encoding="utf-8")
    )
    assert provenance["commit"] == "b4e91c9d219bed119b5127b43dc30186b258c38c"
    assert provenance["package_version"] == "gherkin-official==42.0.0"
    assert {Path(item["path"]).name for item in provenance["fixtures"]} == set(
        UPSTREAM_BAD_FIXTURES
    )
    for item in provenance["fixtures"]:
        path = ROOT / item["local_path"]
        content = path.read_bytes()
        assert hashlib.sha256(content).hexdigest() == item["sha256"]
        assert _git_blob_sha1(content) == item["git_blob_sha1"]
        expected_errors = (ROOT / item["local_expected_errors_path"]).read_bytes()
        assert hashlib.sha256(expected_errors).hexdigest() == item["expected_errors_sha256"]
        assert _git_blob_sha1(expected_errors) == item["expected_errors_git_blob_sha1"]
        assert item["expected"] == "GHERKIN_PARSE_ERROR"


def test_fallback_is_used_only_after_official_import_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing_official_parser() -> Any:
        raise ImportError("simulated missing gherkin-official")

    monkeypatch.setattr(
        OfficialGherkinParser,
        "_load_official_parser",
        staticmethod(missing_official_parser),
    )
    monkeypatch.setenv("OJAS_TEST_ALLOW_GHERKIN_FALLBACK", "1")
    parsed = OfficialGherkinParser().parse(
        "Feature: X\n  Scenario: Y\n    Given a\n    When b\n    Then c\n"
    )
    assert parsed.parser_name == "ojas-test-canonical-gherkin-parser"
    assert parsed.parser_version == "test-only"


def test_fallback_flag_does_not_override_installed_official_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("gherkin")
    monkeypatch.setenv("OJAS_TEST_ALLOW_GHERKIN_FALLBACK", "1")

    def fail_if_called(text: str) -> dict[str, Any]:
        raise AssertionError("test-only fallback must not run when official parser imports")

    monkeypatch.setattr(
        readable_quality_module,
        "_parse_canonical_gherkin_for_tests",
        fail_if_called,
    )
    parsed = OfficialGherkinParser().parse(
        "Feature: X\n  Scenario: Y\n    Given a\n    When b\n    Then c\n"
    )
    assert parsed.parser_name == "gherkin-official"
    assert parsed.parser_version == "42.0.0"


def test_hard_rule_ast_readable_model_mismatch() -> None:
    class MismatchParser:
        def parse(self, text: str) -> ParsedGherkin:
            normalized = {
                "feature": {
                    "name": "S.P readable technical candidates",
                    "tags": ["@technical_candidate"],
                    "rules": [{"name": "R", "scenarios": []}],
                }
            }
            return ParsedGherkin("fake", "1", normalized, normalized)

    readable = _readable(_scenario("Expected"))
    with pytest.raises(ReadableBddQualityError) as exc:
        ReadableBddQualityGate(parser=MismatchParser()).validate(
            readable_document=readable,
            feature_text=_feature(_scenario_text("Expected")),
        )
    assert "AST_READABLE_MODEL_MISMATCH" in _issue_codes(exc)


def test_hard_rule_duplicate_scenario_name() -> None:
    readable = _readable(
        _scenario("Duplicate", given="a", then="c", proposal_id="p1"),
        _scenario("Duplicate", given="d", then="f", proposal_id="p2"),
    )
    text = _feature(
        _scenario_text("Duplicate", given="a", then="c"),
        _scenario_text("Duplicate", given="d", then="f"),
    )
    with pytest.raises(ReadableBddQualityError) as exc:
        _lint_gate().validate(readable_document=readable, feature_text=text)
    assert "DUPLICATE_SCENARIO_NAME" in _issue_codes(exc)


def test_hard_rule_exact_duplicate_scenario() -> None:
    readable = _readable(_scenario("One"), _scenario("Two"))
    text = _feature(_scenario_text("One"), _scenario_text("Two"))
    with pytest.raises(ReadableBddQualityError) as exc:
        _lint_gate().validate(readable_document=readable, feature_text=text)
    assert "EXACT_DUPLICATE_SCENARIO" in _issue_codes(exc)


def test_hard_rule_inconsistent_canonical_vocabulary() -> None:
    readable = _readable(
        _scenario("One", then="P_VALUE is null"),
        _scenario("Two", then="P_VALUE is NULL"),
    )
    text = _feature(
        _scenario_text("One", then="P_VALUE is null"),
        _scenario_text("Two", then="P_VALUE is NULL"),
    )
    with pytest.raises(ReadableBddQualityError) as exc:
        _lint_gate().validate(readable_document=readable, feature_text=text)
    assert "INCONSISTENT_CANONICAL_VOCABULARY" in _issue_codes(exc)


def test_hard_rule_broken_outline_examples() -> None:
    scenario = _scenario(
        "Outline <input>",
        given="<input> is invalid",
        then="SQLSTATE <sqlstate> occurs",
        kind="Scenario Outline",
        examples=[{"headers": ["input"], "rows": [["null"]]}],
    )
    readable = _readable(scenario)
    text = _feature(
        "    Scenario Outline: Outline <input>\n"
        "      Given <input> is invalid\n"
        "      When an action occurs\n"
        "      Then SQLSTATE <sqlstate> occurs\n\n"
        "      Examples:\n"
        "        | input |\n"
        "        | null |"
    )
    with pytest.raises(ReadableBddQualityError) as exc:
        _lint_gate().validate(readable_document=readable, feature_text=text)
    assert "BROKEN_OUTLINE_EXAMPLES" in _issue_codes(exc)


def test_hard_rule_missing_then() -> None:
    readable = _readable(_scenario("No outcome", then=None))
    text = _feature(_scenario_text("No outcome", then=None))
    with pytest.raises(ReadableBddQualityError) as exc:
        _lint_gate().validate(readable_document=readable, feature_text=text)
    assert "MISSING_THEN_BY_OJAS_POLICY" in _issue_codes(exc)


def test_combined_hard_rule_report_counts_and_sorts() -> None:
    readable = _readable(
        _scenario("Duplicate", then="P is null", proposal_id="p1"),
        _scenario("Duplicate", then="P is NULL", proposal_id="p2"),
    )
    text = _feature(
        _scenario_text("Duplicate", then="P is null"),
        _scenario_text("Duplicate", then="P is NULL"),
    )
    with pytest.raises(ReadableBddQualityError) as exc:
        _lint_gate().validate(readable_document=readable, feature_text=text)
    report = exc.value.report
    assert report["error_count"] >= 2
    assert report["status"] == "FAILED"
    assert all(item["fingerprint"].startswith("sha256:") for item in report["issues"])


def test_warning_policy_no_new_warnings_blocks_new_warning() -> None:
    readable = _readable(
        _scenario(
            "Generic",
            given="the prerequisite statements complete successfully",
            when="S.P is invoked",
        )
    )
    text = _feature(
        _scenario_text(
            "Generic",
            given="the prerequisite statements complete successfully",
            when="S.P is invoked",
        )
    )
    policy = {
        "schema_version": "readable-bdd-warning-policy-1.0",
        "mode": "NO_NEW_WARNINGS",
        "baseline_fingerprints": [],
        "waivers": [],
        "max_warning_count": 0,
    }
    with pytest.raises(ReadableBddQualityError) as exc:
        _lint_gate().validate(
            readable_document=readable, feature_text=text, warning_policy=policy
        )
    assert "WARNING_GOVERNANCE_FAILED" in _issue_codes(exc)
    assert exc.value.report["warning_governance"]["new_warning_count"] == 1


def test_warning_policy_accepts_baselined_warning() -> None:
    readable = _readable(
        _scenario(
            "Generic",
            given="the prerequisite statements complete successfully",
            when="S.P is invoked",
        )
    )
    text = _feature(
        _scenario_text(
            "Generic",
            given="the prerequisite statements complete successfully",
            when="S.P is invoked",
        )
    )
    initial = _lint_gate().validate(readable_document=readable, feature_text=text)
    fingerprints = [
        item["fingerprint"]
        for item in initial["lint_report"]["issues"]
        if item["severity"] == "WARNING"
    ]
    policy = {
        "schema_version": "readable-bdd-warning-policy-1.0",
        "mode": "NO_NEW_WARNINGS",
        "baseline_fingerprints": fingerprints,
        "waivers": [],
        "max_warning_count": len(fingerprints),
    }
    governed = _lint_gate().validate(
        readable_document=readable, feature_text=text, warning_policy=policy
    )
    report = governed["lint_report"]
    assert report["error_count"] == 0
    assert report["warning_governance"]["status"] == "GOVERNED"
    assert report["warning_governance"]["new_warning_count"] == 0


def test_production_parser_fails_closed_when_dependency_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if importlib.util.find_spec("gherkin") is not None:
        pytest.skip("gherkin-official is installed; missing-dependency behavior is not applicable")
    monkeypatch.delenv("OJAS_TEST_ALLOW_GHERKIN_FALLBACK", raising=False)
    with pytest.raises(ReadableBddQualityError, match="gherkin-official"):
        OfficialGherkinParser().parse("Feature: X\n")


def test_generation_blocks_cleanly_when_official_parser_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if importlib.util.find_spec("gherkin") is not None:
        pytest.skip("gherkin-official is installed; missing-dependency behavior is not applicable")
    monkeypatch.delenv("OJAS_TEST_ALLOW_GHERKIN_FALLBACK", raising=False)
    with pytest.raises(DeliverablesGenerationBlocked, match="READABLE_BDD_QUALITY_GATE_FAILED"):
        DeliverablesGenerator().generate(
            source=FIXTURE,
            output_dir=tmp_path / "blocked",
            authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
        )


def test_official_parser_integration_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("gherkin")
    monkeypatch.delenv("OJAS_TEST_ALLOW_GHERKIN_FALLBACK", raising=False)
    parsed = OfficialGherkinParser().parse(
        "Feature: X\n  Scenario: Y\n    Given a\n    When b\n    Then c\n"
    )
    assert parsed.parser_name == "gherkin-official"
    assert parsed.parser_version == "42.0.0"
    assert parsed.normalized_document["feature"]["name"] == "X"


def test_warning_policy_expired_waiver_fails() -> None:
    readable = _readable(
        _scenario(
            "Generic",
            given="the prerequisite statements complete successfully",
            when="S.P is invoked",
        )
    )
    text = _feature(
        _scenario_text(
            "Generic",
            given="the prerequisite statements complete successfully",
            when="S.P is invoked",
        )
    )
    initial = _lint_gate().validate(readable_document=readable, feature_text=text)
    fingerprint = next(
        item["fingerprint"]
        for item in initial["lint_report"]["issues"]
        if item["severity"] == "WARNING"
    )
    policy = {
        "schema_version": "readable-bdd-warning-policy-1.0",
        "mode": "NO_NEW_WARNINGS",
        "baseline_fingerprints": [],
        "waivers": [
            {
                "fingerprint": fingerprint,
                "justification": "Temporary review exception",
                "owner": "owner:test",
                "approved_by": "reviewer:test",
                "expires_at": "2020-01-01T00:00:00Z",
                "release_scope": "1.0.1rc23",
            }
        ],
    }
    with pytest.raises(ReadableBddQualityError) as exc:
        _lint_gate().validate(
            readable_document=readable, feature_text=text, warning_policy=policy
        )
    assert "WARNING_GOVERNANCE_FAILED" in _issue_codes(exc)
    assert exc.value.report["warning_governance"]["expired_waiver_count"] == 1


def test_invalid_warning_policy_blocks_generation(tmp_path: Path) -> None:
    policy = tmp_path / "invalid-policy.json"
    policy.write_text('{"schema_version":"wrong"}', encoding="utf-8")
    with pytest.raises(
        DeliverablesGenerationBlocked, match="READABLE_BDD_WARNING_POLICY_INVALID"
    ):
        DeliverablesGenerator().generate(
            source=FIXTURE,
            output_dir=tmp_path / "blocked-policy",
            authority_mode=AuthorityMode.TEST_FIXTURE_ONLY,
            bdd_warning_policy=policy,
        )


def test_warning_fingerprints_are_stable() -> None:
    readable = _readable(
        _scenario(
            "Generic",
            given="the prerequisite statements complete successfully",
            when="S.P is invoked",
        )
    )
    text = _feature(
        _scenario_text(
            "Generic",
            given="the prerequisite statements complete successfully",
            when="S.P is invoked",
        )
    )
    first = _lint_gate().validate(
        readable_document=readable, feature_text=text
    )["lint_report"]
    second = _lint_gate().validate(
        readable_document=readable, feature_text=text
    )["lint_report"]
    assert [item["fingerprint"] for item in first["issues"]] == [
        item["fingerprint"] for item in second["issues"]
    ]
    assert first["lint_report_digest"] == second["lint_report_digest"]
