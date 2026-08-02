from __future__ import annotations

from pathlib import Path

from ojas_reconciler.db2_behavior.analysis.models import EffectKind
from ojas_reconciler.db2_behavior.analysis.service import Phase1SemanticAnalyzer
from ojas_reconciler.db2_behavior.parsing.adapters.lark_sqlpl.parser import LarkSqlPlSpikeParser
from ojas_reconciler.db2_behavior.parsing.inventory import InventoryAnalyzer
from ojas_reconciler.db2_behavior.parsing.models import NodeKind, ParseOutcome, ParserFindingCode


IBM_REPOSITORY = "IBM/db2-samples"
IBM_COMMIT = "23a61f9be5187d98c4dd4c0546382cbb5b3fd820"
IBM_BLOBS = {
    "basecase.db2": "95cb6f007f57c51083591f2f303f2219ff731688",
    "iterate.db2": "94436689aa0b53f1a5c99b0a09d6b7bbab3aad8b",
    "nestedsp.db2": "910befc9d7bfd102da449f8a7abc9266ac194300",
    "rsultset.db2": "8899bbbd07d00a4d187b02d86a34f4f8407dad08",
    "spserver.db2": "a9851b005c04b1a68791a3080ca595c964f0427d",
}


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_ibm_basecase_case_is_structured_not_opaque(tmp_path: Path) -> None:
    source = _write(
        tmp_path,
        "basecase.db2",
        """
-- Provenance: IBM/db2-samples sqlpl/basecase.db2 pinned by IBM_COMMIT/IBM_BLOBS.
-- To create: db2 -td@ -vf basecase.db2
CREATE PROCEDURE update_salary
(IN employee_number CHAR(6), IN rating INT)
LANGUAGE SQL
BEGIN
  DECLARE SQLSTATE CHAR(5);
  DECLARE not_found CONDITION FOR SQLSTATE '02000';
  DECLARE EXIT HANDLER FOR not_found SIGNAL SQLSTATE '02444';
  CASE rating
    WHEN 1 THEN
      UPDATE employee SET salary = salary * 1.10, bonus = 1000
      WHERE empno = employee_number;
    WHEN 2 THEN
      UPDATE employee SET salary = salary * 1.05, bonus = 500
      WHERE empno = employee_number;
    ELSE
      UPDATE employee SET salary = salary * 1.03, bonus = 0
      WHERE empno = employee_number;
  END CASE;
END @
""".strip()
        + "\n",
    )
    result = LarkSqlPlSpikeParser().parse_file(source)
    assert result.outcome == ParseOutcome.PARSES_COMPLETE
    assert result.ast is not None
    assert not any(node.kind == NodeKind.OPAQUE for node in result.ast.nodes)
    case = next(
        node
        for node in result.ast.nodes
        if node.if_region is not None and node.if_region.source_construct == "SIMPLE_CASE"
    )
    assert case.if_region is not None
    assert case.if_region.selector_expression == "rating"
    assert [arm.condition_text for arm in case.if_region.arms] == [
        "(rating) = (1)",
        "(rating) = (2)",
        None,
    ]


def test_ibm_rsultset_header_comment_and_returned_cursors(tmp_path: Path) -> None:
    source = _write(
        tmp_path,
        "rsultset.db2",
        """
CREATE PROCEDURE median_result_set
-- Declare medianSalary as OUT so it can be used to return values
(OUT medianSalary DOUBLE)
RESULT SETS 2
LANGUAGE SQL
BEGIN
  DECLARE c2 CURSOR WITH RETURN FOR
    SELECT name, job, salary FROM staff WHERE salary > medianSalary;
  DECLARE c3 CURSOR WITH RETURN FOR
    SELECT name, job, salary FROM staff WHERE salary < medianSalary;
  OPEN c2;
  OPEN c3;
END @
""".strip()
        + "\n",
    )
    result = LarkSqlPlSpikeParser().parse_file(source)
    assert result.outcome == ParseOutcome.PARSES_COMPLETE
    assert result.ast is not None
    assert result.ast.declared_result_set_capacity == 2
    assert [(item.cursor_name, item.return_scope) for item in result.ast.returned_cursor_declarations] == [
        ("C2", "UNSPECIFIED"),
        ("C3", "UNSPECIFIED"),
    ]
    assert all(item.returned_cursor for item in result.ast.cursor_open_effects)
    semantic = Phase1SemanticAnalyzer().analyze(result)
    returned = [effect for effect in semantic.effects if effect.effect_kind == EffectKind.RESULT_SET_RETURN]
    assert {effect.target for effect in returned} == {"C2", "C3"}
    assert {effect.value_expression for effect in returned} == {"WITH RETURN UNSPECIFIED"}


def test_result_set_capacity_and_unopened_cursor_findings(tmp_path: Path) -> None:
    source = _write(
        tmp_path,
        "bad_result_sets.db2",
        """
CREATE PROCEDURE bad_result_sets()
DYNAMIC RESULT SETS 1
LANGUAGE SQL
BEGIN
  DECLARE c1 CURSOR WITH RETURN TO CLIENT FOR SELECT 1 FROM sysibm.sysdummy1;
  DECLARE c2 CURSOR WITH RETURN TO CALLER FOR SELECT 2 FROM sysibm.sysdummy1;
  OPEN c1;
END @
""".strip()
        + "\n",
    )
    result = LarkSqlPlSpikeParser().parse_file(source)
    codes = {finding.code for finding in result.findings}
    assert ParserFindingCode.RESULT_SET_CAPACITY_EXCEEDED in codes
    assert ParserFindingCode.RETURNED_CURSOR_NOT_OPENED in codes


def test_clp_script_segments_every_procedure_and_single_api_fails_closed(tmp_path: Path) -> None:
    procedures = "\n".join(
        f"CREATE PROCEDURE P{i}() LANGUAGE SQL BEGIN SET V = {i}; END @"
        for i in range(1, 10)
    )
    source = _write(
        tmp_path,
        "spserver.db2",
        "-- To create: db2 -td@ -vf spserver.db2\n" + procedures + "\n",
    )
    parser = LarkSqlPlSpikeParser()
    script = parser.parse_script_file(source)
    assert script.detected_terminator == "@"
    assert script.expected_source_unit_count == 9
    assert script.discovered_source_unit_count == 9
    assert script.complete_count == 9
    assert script.partial_count == 0
    assert script.blocked_count == 0
    assert [result.ast.procedure_name for result in script.procedure_results if result.ast] == [
        f"P{i}" for i in range(1, 10)
    ]

    compatibility = parser.parse_file(source)
    assert compatibility.outcome == ParseOutcome.REFUSES_EXPECTED
    assert compatibility.ast is None
    assert {finding.code for finding in compatibility.findings} == {
        ParserFindingCode.MULTIPLE_PROCEDURE_SOURCE_UNITS
    }


def test_inventory_dir_includes_db2_and_reports_file_unit_counts(tmp_path: Path) -> None:
    source = _write(
        tmp_path,
        "nestedsp.db2",
        """
-- db2 -td@ -vf nestedsp.db2
CREATE PROCEDURE MAX_SALARY (OUT maxSalary DOUBLE)
LANGUAGE SQL BEGIN SELECT MAX(salary) INTO maxSalary FROM staff; END @
CREATE PROCEDURE OUT_MEDIAN (OUT medianSalary DOUBLE, OUT maxSalary DOUBLE)
DYNAMIC RESULT SETS 0 LANGUAGE SQL BEGIN SET medianSalary = 1; CALL MAX_SALARY(maxSalary); END @
CREATE PROCEDURE OUT_AVERAGE (OUT averageSalary DOUBLE)
DYNAMIC RESULT SETS 2 LANGUAGE SQL BEGIN
  DECLARE r1 CURSOR WITH RETURN TO CLIENT FOR SELECT name FROM staff;
  DECLARE r2 CURSOR WITH RETURN TO CLIENT FOR SELECT name FROM staff;
  OPEN r1; OPEN r2;
END @
""".strip()
        + "\n",
    )
    report = InventoryAnalyzer().analyze_directory(tmp_path)
    assert source.exists()
    assert report.source_file_count == 1
    assert report.expected_source_unit_count == 3
    assert report.discovered_source_unit_count == 3
    assert len(report.procedure_reports) == 3
    assert report.source_unit_count_mismatch_files == ()
    assert [item.procedure.name for item in report.procedure_reports] == [
        "MAX_SALARY",
        "OUT_MEDIAN",
        "OUT_AVERAGE",
    ]


def test_provenance_constants_pin_the_verified_ibm_sources() -> None:
    assert IBM_REPOSITORY == "IBM/db2-samples"
    assert len(IBM_COMMIT) == 40
    assert set(IBM_BLOBS) == {
        "basecase.db2",
        "iterate.db2",
        "nestedsp.db2",
        "rsultset.db2",
        "spserver.db2",
    }
    assert all(len(blob) == 40 for blob in IBM_BLOBS.values())


def test_public_repository_validation_uses_blob_and_license_not_custody(tmp_path: Path) -> None:
    from ojas_reconciler.db2_behavior.commercial.public_repository import (
        PublicRepositoryOrganicValidationService,
        PublicRepositoryValidationManifest,
        PublicRepositorySourceCase,
    )
    from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest

    repo = tmp_path / "repo"
    sqlpl = repo / "sqlpl"
    sqlpl.mkdir(parents=True)
    cases = []
    for index in range(1, 6):
        path = sqlpl / f"p{index}.db2"
        path.write_text(
            f"CREATE PROCEDURE P{index}() LANGUAGE SQL BEGIN SET V = {index}; END @\n",
            encoding="utf-8",
        )
        blob = PublicRepositoryOrganicValidationService._git_blob_sha(path.read_bytes())
        cases.append(
            PublicRepositorySourceCase(
                case_id=f"case-{index}",
                relative_path=f"sqlpl/p{index}.db2",
                git_blob_sha=blob,
                expected_procedure_count=1,
            )
        )
    payload = {
        "schema_version": "public-repository-organic-manifest-1.0",
        "validation_id": "public-db2-test",
        "repository": "example/public-db2",
        "commit_sha": "a" * 40,
        "license_ref": "Apache-2.0",
        "dialect": "db2",
        "cases": tuple(cases),
    }
    manifest = PublicRepositoryValidationManifest(
        **payload,
        content_digest=canonical_digest(payload),
    )
    report = PublicRepositoryOrganicValidationService().run(
        manifest=manifest,
        repository_root=repo,
    )
    assert report.source_file_count == 5
    assert report.source_unit_count == 5
    assert report.parsed_complete == 5
    assert report.parsed_partial == 0
    assert report.parsed_blocked == 0
    assert report.opaque_count == 0
    assert report.first_five_pause_rule_fired is False
    assert report.pause_reasons == ()
    assert report.commercialization_state == "ORGANIC_VALIDATION_REQUIRED"
    assert all(item.blob_verified and item.source_unmodified for item in report.file_outcomes)


def test_public_repository_first_five_pause_rule_is_explicit(tmp_path: Path) -> None:
    from ojas_reconciler.db2_behavior.commercial.public_repository import (
        PublicRepositoryOrganicValidationService,
        PublicRepositoryValidationManifest,
        PublicRepositorySourceCase,
    )
    from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest

    repo = tmp_path / "repo"
    repo.mkdir()
    cases = []
    for index in range(1, 6):
        path = repo / f"p{index}.db2"
        text = (
            f"CREATE PROCEDURE P{index}() LANGUAGE SQL BEGIN SET V = {index}; END @\n"
            if index <= 2
            else f"CREATE PROCEDURE P{index}() LANGUAGE SQL BEGIN UNKNOWN THING; END @\n"
        )
        path.write_text(text, encoding="utf-8")
        cases.append(
            PublicRepositorySourceCase(
                case_id=f"case-{index}",
                relative_path=path.name,
                git_blob_sha=PublicRepositoryOrganicValidationService._git_blob_sha(path.read_bytes()),
                expected_procedure_count=1,
            )
        )
    payload = {
        "schema_version": "public-repository-organic-manifest-1.0",
        "validation_id": "pause-test",
        "repository": "example/public-db2",
        "commit_sha": "b" * 40,
        "license_ref": "Apache-2.0",
        "dialect": "db2",
        "cases": tuple(cases),
    }
    manifest = PublicRepositoryValidationManifest(
        **payload,
        content_digest=canonical_digest(payload),
    )
    report = PublicRepositoryOrganicValidationService().run(
        manifest=manifest,
        repository_root=repo,
    )
    assert report.first_five_pause_rule_fired is True
    assert "THREE_OF_FIRST_FIVE_FAILED_PARSE_GATE" in report.pause_reasons
    assert report.commercialization_state == "BLOCKED"


def test_canonical_atlas_source_unit_uses_db2_clp_segmentation(tmp_path: Path) -> None:
    from atlas.application import AtlasSourceUnitService
    from atlas.core.models import DialectId

    source = _write(
        tmp_path,
        "multi.db2",
        """
CREATE PROCEDURE A() LANGUAGE SQL BEGIN SET X = 1; END @
CREATE PROCEDURE B() LANGUAGE SQL BEGIN CASE X WHEN 1 THEN SET X = 2; ELSE SET X = 3; END CASE; END @
CREATE PROCEDURE C() LANGUAGE SQL BEGIN SET X = 4; END @
""".strip() + "\n",
    )
    result = AtlasSourceUnitService("2.0.0rc5").analyze(source, DialectId.DB2_SQL_PL)
    assert len(result.routines) == 3
    assert not any(item.code == "SOURCE_UNIT_COUNT_MISMATCH" for item in result.discovery_findings)


def test_canonical_atlas_cli_exposes_public_db2_validation(tmp_path: Path, capsys) -> None:
    from atlas.cli import main
    from ojas_reconciler.db2_behavior.commercial.public_repository import (
        PublicRepositoryOrganicValidationService,
        seal_public_manifest,
    )

    repo = tmp_path / "repo"
    repo.mkdir()
    cases = []
    for index in range(1, 6):
        path = repo / f"p{index}.db2"
        path.write_text(f"CREATE PROCEDURE P{index}() LANGUAGE SQL BEGIN SET V = {index}; END @\n")
        cases.append({
            "case_id": f"case-{index}",
            "relative_path": path.name,
            "git_blob_sha": PublicRepositoryOrganicValidationService._git_blob_sha(path.read_bytes()),
            "expected_procedure_count": 1,
            "authored_for_tool": False,
            "source_must_remain_unmodified": True,
        })
    manifest = tmp_path / "manifest.json"
    manifest.write_text(__import__("json").dumps(seal_public_manifest({
        "schema_version": "public-repository-organic-manifest-1.0",
        "validation_id": "canonical-cli-test",
        "repository": "example/public-db2",
        "commit_sha": "a" * 40,
        "license_ref": "Apache-2.0",
        "dialect": "db2",
        "cases": cases,
    })))
    output = tmp_path / "report.json"
    assert main(["validate-public-db2", str(manifest), "--repository-root", str(repo), "--output", str(output)]) == 0
    assert output.is_file()
    summary = __import__("json").loads(capsys.readouterr().out)
    assert summary["parsed_complete"] == 5
    assert summary["pause_reasons"] == []
