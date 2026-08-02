from __future__ import annotations

import re

from atlas.core.models import DialectId, RoutineKind, RoutineParameter
from ..base import ProceduralDialectProfile
from ..vendor_support import normalized_header_window, parse_standard_parameters, routine_kind_attributes


def parse_parameters(raw: str, return_type: str | None) -> tuple[RoutineParameter, ...]:
    return parse_standard_parameters(raw, return_type)


def extract_routine_attributes(text: str, match: re.Match[str], kind: RoutineKind) -> dict[str, object]:
    header = normalized_header_window(text, match, width=1600)
    values = routine_kind_attributes(kind)
    authid = re.search(r"\bAUTHID\s+(DEFINER|CURRENT_USER)\b", header)
    values.update(
        {
            "security_mode": authid.group(1) if authid else "DEFINER_DEFAULT",
            "autonomous_transaction_declared": bool(
                re.search(r"\bPRAGMA\s+AUTONOMOUS_TRANSACTION\b", text[match.end() :], re.I)
            ),
            "pipelined": " PIPELINED" in header,
            "parallel_enable": " PARALLEL_ENABLE" in header,
            "result_cache": " RESULT_CACHE" in header,
            "deterministic": " DETERMINISTIC" in header,
            "editionable": " NONEDITIONABLE" not in header,
        }
    )
    return values


PROFILE = ProceduralDialectProfile(
    dialect=DialectId.ORACLE_PLSQL,
    adapter_id="atlas-oracle-plsql-2.2",
    header_patterns=(
        r"(?is)CREATE\s+(?:OR\s+REPLACE\s+)?PROCEDURE\s+(?P<name>(?:\"[^\"]+\"|[A-Z0-9_$#]+)(?:\.(?:\"[^\"]+\"|[A-Z0-9_$#]+))?)\s*(?:\((?P<params>.*?)\))?\s*(?:AUTHID\s+\w+\s*)?(?:IS|AS)\b",
    ),
    function_patterns=(
        r"(?is)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?P<name>(?:\"[^\"]+\"|[A-Z0-9_$#]+)(?:\.(?:\"[^\"]+\"|[A-Z0-9_$#]+))?)\s*(?:\((?P<params>.*?)\))?\s*RETURN\s+(?P<return_type>.+?)\s*(?:AUTHID\s+\w+\s*)?(?:IS|AS)\b",
    ),
    trigger_patterns=(
        r"(?is)CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\s+(?P<name>(?:\"[^\"]+\"|[A-Z0-9_$#]+)(?:\.(?:\"[^\"]+\"|[A-Z0-9_$#]+))?).*?(?:DECLARE\b|BEGIN\b)",
    ),
    package_procedure_patterns=(
        r"(?is)\bPROCEDURE\s+(?P<name>[A-Z0-9_$#]+)\s*(?:\((?P<params>.*?)\))?\s*(?:IS|AS)\b",
    ),
    package_function_patterns=(
        r"(?is)\bFUNCTION\s+(?P<name>[A-Z0-9_$#]+)\s*(?:\((?P<params>.*?)\))?\s*RETURN\s+(?P<return_type>.+?)\s*(?:IS|AS)\b",
    ),
    body_style="ORACLE_BLOCK",
    identifier_quotes=(("\"", "\""),),
    elseif_keywords=("ELSIF",),
    raise_keywords=("RAISE_APPLICATION_ERROR", "RAISE"),
    call_keywords=("CALL",),
    dynamic_keywords=("EXECUTE IMMEDIATE", "OPEN FOR"),
    result_set_markers=("PIPE ROW", "RETURN"),
    reference_urls=(
        "https://docs.oracle.com/en/database/oracle/oracle-database/26/lnpls/",
        "https://docs.oracle.com/en/database/oracle/oracle-database/26/lnpls/dynamic-sql.html",
    ),
    parameter_parser=parse_parameters,
    routine_attribute_extractor=extract_routine_attributes,
    initial_declare_section=True,
)

ORACLE = PROFILE
