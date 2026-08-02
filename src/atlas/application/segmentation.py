from __future__ import annotations

import re
from dataclasses import dataclass

from atlas.core.models import DialectId, SemanticFinding
from atlas.dialects.db2.clp import Db2ClpScriptSegmenter
from atlas.dialects.profiles import ALL_PROFILES


@dataclass(frozen=True)
class SourceCandidate:
    text: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class SourceSegmentation:
    candidates: tuple[SourceCandidate, ...]
    findings: tuple[SemanticFinding, ...]


class AtlasSourceSegmenter:
    def segment(self, text: str, source_name: str, dialect: DialectId) -> SourceSegmentation:
        if dialect is DialectId.DB2_SQL_PL:
            return self._db2(text, source_name)
        spans = self._spans(text, dialect)
        values = tuple(
            SourceCandidate(
                text=text[start:end].strip(),
                start_line=text[:start].count("\n") + 1,
                end_line=text[:end].count("\n") + 1,
            )
            for start, end in spans
        )
        return SourceSegmentation(values, ())

    def _db2(self, text: str, source_name: str) -> SourceSegmentation:
        script = Db2ClpScriptSegmenter().segment_text(text, source_name=source_name)
        values = tuple(
            SourceCandidate(
                text=self._strip(unit.source_text, unit.terminator),
                start_line=unit.source_range.start_line,
                end_line=unit.source_range.end_line,
            )
            for unit in script.source_units
        )
        findings: list[SemanticFinding] = []
        if script.expected_source_unit_count != script.discovered_source_unit_count:
            findings.append(self._count_finding(script.expected_source_unit_count, script.discovered_source_unit_count))
        if script.unclassified_fragment_count:
            findings.append(self._fragment_finding(script.unclassified_fragment_count))
        return SourceSegmentation(values, tuple(findings))

    @staticmethod
    def _strip(source_text: str, terminator: str) -> str:
        value = source_text.rstrip()
        return value[:-len(terminator)].rstrip() if terminator and value.endswith(terminator) else value

    @staticmethod
    def _spans(text: str, dialect: DialectId) -> list[tuple[int, int]]:
        profile = next(value for value in ALL_PROFILES if value.dialect is dialect)
        starts = [match.start() for pattern in (*profile.header_patterns, *profile.function_patterns, *profile.trigger_patterns)
                  for match in re.finditer(pattern, text)]
        for pattern in (*profile.package_procedure_patterns, *profile.package_function_patterns):
            for match in re.finditer(pattern, text):
                prefix = text[max(0, match.start() - 80):match.start()]
                if not re.search(r"(?is)\bCREATE\s+(?:OR\s+REPLACE\s+)?$", prefix):
                    starts.append(match.start())
        ordered = sorted(set(starts))
        return [(start, ordered[index + 1] if index + 1 < len(ordered) else len(text)) for index, start in enumerate(ordered)]

    @staticmethod
    def _count_finding(expected: int, discovered: int) -> SemanticFinding:
        return SemanticFinding(code="SOURCE_UNIT_COUNT_MISMATCH", severity="ERROR",
            message=f"Expected {expected} Db2 procedure units but discovered {discovered}.",
            consequence="The source unit cannot claim complete routine discovery.")

    @staticmethod
    def _fragment_finding(count: int) -> SemanticFinding:
        return SemanticFinding(code="SOURCE_UNIT_UNCLASSIFIED_SCRIPT_FRAGMENTS", severity="WARNING",
            message=f"{count} non-comment CLP script fragment(s) were not classified.",
            consequence="File-level script behavior outside CREATE PROCEDURE units remains an evidence boundary.")
