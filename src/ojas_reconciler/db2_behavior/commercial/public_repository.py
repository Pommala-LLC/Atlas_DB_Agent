from __future__ import annotations

import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from ..analysis.service import Phase1SemanticAnalyzer
from ..compiler.scenario_spec import ScenarioSpecCompiler
from ..core.canonical_json import canonical_digest, canonical_json_bytes
from ..core.models import CanonicalModel
from ..parsing.adapters.lark_sqlpl.parser import LarkSqlPlSpikeParser
from ..parsing.models import NodeKind, ParseOutcome


class PublicRepositorySourceCase(CanonicalModel):
    case_id: str
    relative_path: str
    git_blob_sha: str
    expected_procedure_count: int | None = Field(default=None, ge=1)
    authored_for_tool: Literal[False] = False
    source_must_remain_unmodified: Literal[True] = True

    @model_validator(mode="after")
    def validate_blob(self) -> "PublicRepositorySourceCase":
        if len(self.git_blob_sha) != 40 or any(ch not in "0123456789abcdef" for ch in self.git_blob_sha.lower()):
            raise ValueError("git_blob_sha must be a 40-character hexadecimal Git blob SHA-1.")
        if Path(self.relative_path).is_absolute() or ".." in Path(self.relative_path).parts:
            raise ValueError("relative_path must remain inside the repository root.")
        return self


class PublicRepositoryValidationManifest(CanonicalModel):
    schema_version: Literal["public-repository-organic-manifest-1.0"] = "public-repository-organic-manifest-1.0"
    validation_id: str
    repository: str
    commit_sha: str
    license_ref: str
    dialect: Literal["db2"] = "db2"
    cases: tuple[PublicRepositorySourceCase, ...]
    content_digest: str

    @model_validator(mode="after")
    def validate_manifest(self) -> "PublicRepositoryValidationManifest":
        if len(self.commit_sha) != 40:
            raise ValueError("commit_sha must be a full 40-character commit SHA.")
        if len(self.cases) < 5:
            raise ValueError("Public-repository discovery validation requires at least five source files.")
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("case_id values must be unique.")
        if len({case.relative_path for case in self.cases}) != len(self.cases):
            raise ValueError("relative_path values must be unique.")
        return self


class PublicProcedureOutcome(CanonicalModel):
    unit_index: int = Field(ge=1)
    procedure_name: str | None
    parse_outcome: str
    node_count: int = Field(ge=0)
    opaque_count: int = Field(ge=0)
    parse_findings: tuple[str, ...]
    semantic_completed: bool
    technical_scenario_count: int = Field(ge=0)
    blocked_scenario_count: int = Field(ge=0)
    blocker_codes: tuple[str, ...] = ()
    declared_result_set_capacity: int | None = Field(default=None, ge=0)
    returned_cursor_count: int = Field(default=0, ge=0)


class PublicFileOutcome(CanonicalModel):
    case_id: str
    relative_path: str
    git_blob_sha_expected: str
    git_blob_sha_actual: str
    blob_verified: bool
    source_digest_before: str
    source_digest_after: str
    source_unmodified: bool
    detected_terminator: str
    expected_source_unit_count: int = Field(ge=0)
    discovered_source_unit_count: int = Field(ge=0)
    source_unit_count_matches: bool
    complete_count: int = Field(ge=0)
    partial_count: int = Field(ge=0)
    blocked_count: int = Field(ge=0)
    opaque_count: int = Field(ge=0)
    procedure_outcomes: tuple[PublicProcedureOutcome, ...]
    unclassified_fragment_count: int = Field(ge=0)


class PublicRepositoryOrganicReport(CanonicalModel):
    schema_version: Literal["public-repository-organic-report-1.0"] = "public-repository-organic-report-1.0"
    validation_id: str
    repository: str
    requested_commit_sha: str
    observed_commit_sha: str | None
    commit_verified: bool | None
    license_ref: str
    source_file_count: int = Field(ge=0)
    source_unit_count: int = Field(ge=0)
    parsed_complete: int = Field(ge=0)
    parsed_partial: int = Field(ge=0)
    parsed_blocked: int = Field(ge=0)
    opaque_count: int = Field(ge=0)
    semantic_completed: int = Field(ge=0)
    technical_scenario_count: int = Field(ge=0)
    blocked_scenario_count: int = Field(ge=0)
    first_five_pause_rule_fired: bool
    pause_reasons: tuple[str, ...]
    recurring_finding_codes: tuple[str, ...]
    commercialization_state: Literal["BLOCKED", "ORGANIC_VALIDATION_REQUIRED"]
    file_outcomes: tuple[PublicFileOutcome, ...]
    content_digest: str


class PublicRepositoryOrganicValidationService:
    """Validates third-party public source without customer custody fiction.

    Provenance is established using repository identity, a pinned commit, exact
    Git blob IDs, license evidence, and before/after content digests.
    """

    def __init__(self) -> None:
        self._parser = LarkSqlPlSpikeParser()

    def load_manifest(self, path: Path) -> PublicRepositoryValidationManifest:
        manifest = PublicRepositoryValidationManifest.model_validate_json(path.read_text(encoding="utf-8"))
        payload = manifest.model_dump(mode="python", exclude={"content_digest"})
        if manifest.content_digest != canonical_digest(payload):
            raise ValueError("Public repository manifest content_digest mismatch.")
        return manifest

    def run(
        self,
        *,
        manifest: PublicRepositoryValidationManifest,
        repository_root: Path,
        output: Path | None = None,
    ) -> PublicRepositoryOrganicReport:
        root = repository_root.resolve()
        observed_commit = self._observed_commit(root)
        commit_verified = observed_commit == manifest.commit_sha if observed_commit is not None else None
        file_outcomes: list[PublicFileOutcome] = []
        finding_counter: Counter[str] = Counter()

        for case in manifest.cases:
            source = (root / case.relative_path).resolve()
            try:
                source.relative_to(root)
            except ValueError as exc:
                raise ValueError(f"Source path escapes repository root: {case.relative_path}") from exc
            data = source.read_bytes()
            before = "sha256:" + hashlib.sha256(data).hexdigest()
            actual_blob = self._git_blob_sha(data)
            script = self._parser.parse_script_file(source)
            outcomes: list[PublicProcedureOutcome] = []
            file_opaque = 0
            for result in script.procedure_results:
                ast = result.ast
                opaque = sum(node.kind == NodeKind.OPAQUE for node in ast.nodes) if ast else 0
                file_opaque += opaque
                parse_codes = tuple(sorted(finding.code.value for finding in result.findings))
                finding_counter.update(parse_codes)
                semantic_completed = False
                technical_count = 0
                blocked_count = 0
                blocker_codes: tuple[str, ...] = ()
                if result.outcome == ParseOutcome.PARSES_COMPLETE and ast is not None:
                    semantic = Phase1SemanticAnalyzer().analyze(result)
                    semantic_completed = True
                    scenarios = ScenarioSpecCompiler().compile_all(result, semantic)
                    technical_count = len(scenarios.scenario_specs)
                    blocked_count = sum(
                        item.compilation_status.value == "BLOCKED"
                        for item in scenarios.compilation_results
                    )
                    blocker_codes = tuple(
                        sorted(
                            {
                                str(code)
                                for item in scenarios.compilation_results
                                for code in item.blockers
                            }
                        )
                    )
                    finding_counter.update(blocker_codes)
                outcomes.append(
                    PublicProcedureOutcome(
                        unit_index=len(outcomes) + 1,
                        procedure_name=ast.procedure_name if ast else None,
                        parse_outcome=result.outcome.value,
                        node_count=len(ast.nodes) if ast else 0,
                        opaque_count=opaque,
                        parse_findings=parse_codes,
                        semantic_completed=semantic_completed,
                        technical_scenario_count=technical_count,
                        blocked_scenario_count=blocked_count,
                        blocker_codes=blocker_codes,
                        declared_result_set_capacity=(ast.declared_result_set_capacity if ast else None),
                        returned_cursor_count=(len(ast.returned_cursor_declarations) if ast else 0),
                    )
                )
            after_data = source.read_bytes()
            after = "sha256:" + hashlib.sha256(after_data).hexdigest()
            expected_count = case.expected_procedure_count or script.expected_source_unit_count
            unit_count_matches = (
                script.expected_source_unit_count == script.discovered_source_unit_count == expected_count
            )
            file_outcomes.append(
                PublicFileOutcome(
                    case_id=case.case_id,
                    relative_path=case.relative_path,
                    git_blob_sha_expected=case.git_blob_sha,
                    git_blob_sha_actual=actual_blob,
                    blob_verified=actual_blob == case.git_blob_sha,
                    source_digest_before=before,
                    source_digest_after=after,
                    source_unmodified=before == after,
                    detected_terminator=script.detected_terminator,
                    expected_source_unit_count=expected_count,
                    discovered_source_unit_count=script.discovered_source_unit_count,
                    source_unit_count_matches=unit_count_matches,
                    complete_count=script.complete_count,
                    partial_count=script.partial_count,
                    blocked_count=script.blocked_count,
                    opaque_count=file_opaque,
                    procedure_outcomes=tuple(outcomes),
                    unclassified_fragment_count=script.unclassified_fragment_count,
                )
            )

        first_five = file_outcomes[:5]
        failed_first_five = sum(
            not (
                item.blob_verified
                and item.source_unmodified
                and item.source_unit_count_matches
                and item.partial_count == 0
                and item.blocked_count == 0
                and item.opaque_count == 0
            )
            for item in first_five
        )
        pause_reasons: list[str] = []
        if any(not item.blob_verified for item in file_outcomes):
            pause_reasons.append("PUBLIC_SOURCE_BLOB_MISMATCH")
        if any(not item.source_unmodified for item in file_outcomes):
            pause_reasons.append("PUBLIC_SOURCE_MODIFIED_DURING_VALIDATION")
        if any(not item.source_unit_count_matches for item in file_outcomes):
            pause_reasons.append("SOURCE_UNIT_COUNT_MISMATCH")
        if len(first_five) >= 5 and failed_first_five >= 3:
            pause_reasons.append("THREE_OF_FIRST_FIVE_FAILED_PARSE_GATE")
        recurring = tuple(sorted(code for code, count in finding_counter.items() if count >= 2))
        if recurring:
            pause_reasons.append("RECURRING_MATERIAL_BLOCKER")
        if commit_verified is False:
            pause_reasons.append("REPOSITORY_COMMIT_MISMATCH")

        procedure_outcomes = [procedure for file in file_outcomes for procedure in file.procedure_outcomes]
        without_digest = {
            "schema_version": "public-repository-organic-report-1.0",
            "validation_id": manifest.validation_id,
            "repository": manifest.repository,
            "requested_commit_sha": manifest.commit_sha,
            "observed_commit_sha": observed_commit,
            "commit_verified": commit_verified,
            "license_ref": manifest.license_ref,
            "source_file_count": len(file_outcomes),
            "source_unit_count": len(procedure_outcomes),
            "parsed_complete": sum(item.parse_outcome == "PARSES_COMPLETE" for item in procedure_outcomes),
            "parsed_partial": sum(item.parse_outcome == "PARSES_PARTIAL" for item in procedure_outcomes),
            "parsed_blocked": sum(not item.parse_outcome.startswith("PARSES") for item in procedure_outcomes),
            "opaque_count": sum(item.opaque_count for item in procedure_outcomes),
            "semantic_completed": sum(item.semantic_completed for item in procedure_outcomes),
            "technical_scenario_count": sum(item.technical_scenario_count for item in procedure_outcomes),
            "blocked_scenario_count": sum(item.blocked_scenario_count for item in procedure_outcomes),
            "first_five_pause_rule_fired": "THREE_OF_FIRST_FIVE_FAILED_PARSE_GATE" in pause_reasons,
            "pause_reasons": tuple(pause_reasons),
            "recurring_finding_codes": recurring,
            "commercialization_state": "BLOCKED" if pause_reasons else "ORGANIC_VALIDATION_REQUIRED",
            "file_outcomes": tuple(file_outcomes),
        }
        report = PublicRepositoryOrganicReport(
            **without_digest,
            content_digest=canonical_digest(without_digest),
        )
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(canonical_json_bytes(report) + b"\n")
        return report

    @staticmethod
    def _git_blob_sha(data: bytes) -> str:
        return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()

    @staticmethod
    def _observed_commit(root: Path) -> str | None:
        if not (root / ".git").exists():
            return None
        try:
            completed = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        value = completed.stdout.strip()
        return value if len(value) == 40 else None


def seal_public_manifest(payload: dict[str, object]) -> dict[str, object]:
    without_digest = dict(payload)
    without_digest.pop("content_digest", None)
    without_digest["content_digest"] = canonical_digest(without_digest)
    return without_digest


def write_public_manifest(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(seal_public_manifest(payload), indent=2, sort_keys=True) + "\n", encoding="utf-8")
