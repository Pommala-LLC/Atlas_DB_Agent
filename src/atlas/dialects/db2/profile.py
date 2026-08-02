from __future__ import annotations

import re

from atlas.core.models import DialectId, RoutineKind, RoutineParameter
from ..base import ProceduralDialectProfile
from ..vendor_support import normalized_header_window, parse_standard_parameters, routine_kind_attributes


def parse_parameters(raw: str, return_type: str | None) -> tuple[RoutineParameter, ...]:
    return parse_standard_parameters(raw, return_type)


def extract_routine_attributes(text: str, match: re.Match[str], kind: RoutineKind) -> dict[str, object]:
    header = normalized_header_window(text, match, width=1800)
    values = routine_kind_attributes(kind)
    security = re.search(r"\bSQL\s+SECURITY\s+(DEFINER|INVOKER)\b", header)
    data_access = next(
        (value for value in ("NO SQL", "CONTAINS SQL", "READS SQL DATA", "MODIFIES SQL DATA") if value in header),
        "DATABASE_DEFAULT",
    )
    dynamic_sets = re.search(r"\bDYNAMIC\s+RESULT\s+SETS\s+(\d+)\b", header)
    values.update(
        {
            "security_mode": security.group(1) if security else "DATABASE_DEFAULT",
            "deterministic": " DETERMINISTIC" in header and "NOT DETERMINISTIC" not in header,
            "external_action": "EXTERNAL ACTION" in header and "NO EXTERNAL ACTION" not in header,
            "data_access": data_access,
            "called_on_null_input": "CALLED ON NULL INPUT" in header,
            "commit_on_return": "COMMIT ON RETURN YES" in header,
            "dynamic_result_sets": int(dynamic_sets.group(1)) if dynamic_sets else 0,
            "language": "SQL" if "LANGUAGE SQL" in header else "SQL_DEFAULT",
            "parameter_style": (
                re.search(r"\bPARAMETER\s+STYLE\s+([A-Z0-9_]+)", header).group(1)
                if re.search(r"\bPARAMETER\s+STYLE\s+([A-Z0-9_]+)", header)
                else "SQL_DEFAULT"
            ),
        }
    )
    return values


PROFILE = ProceduralDialectProfile(
    dialect=DialectId.DB2_SQL_PL,
    adapter_id="atlas-db2-sqlpl-2.2",
    header_patterns=(
        r"(?is)CREATE\s+(?:OR\s+REPLACE\s+)?PROCEDURE\s+(?P<name>(?:\"[^\"]+\"|[A-Z0-9_$#]+)(?:\.(?:\"[^\"]+\"|[A-Z0-9_$#]+))?)\s*\((?P<params>.*?)\).*?(?=(?:[A-Z_$#][A-Z0-9_$#]*\s*:\s*)?\bBEGIN(?:\s+(?:ATOMIC|NOT\s+ATOMIC))?\b)",
    ),
    function_patterns=(
        r"(?is)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?P<name>(?:\"[^\"]+\"|[A-Z0-9_$#]+)(?:\.(?:\"[^\"]+\"|[A-Z0-9_$#]+))?)\s*\((?P<params>.*?)\).*?RETURNS\s+(?P<return_type>.+?)(?=\s+(?:LANGUAGE|SPECIFIC|DETERMINISTIC|NOT\s+DETERMINISTIC|NO\s+SQL|CONTAINS\s+SQL|READS\s+SQL\s+DATA|MODIFIES\s+SQL\s+DATA|CALLED\s+ON\s+NULL\s+INPUT|RETURNS\s+NULL\s+ON\s+NULL\s+INPUT|SQL\s+SECURITY|BEGIN(?:\s+(?:ATOMIC|NOT\s+ATOMIC))?\b)).*?(?=(?:[A-Z_$#][A-Z0-9_$#]*\s*:\s*)?\bBEGIN(?:\s+(?:ATOMIC|NOT\s+ATOMIC))?\b)",
    ),
    trigger_patterns=(
        r"(?is)CREATE\s+(?:OR\s+REPLACE\s+)?TRIGGER\s+(?P<name>(?:\"[^\"]+\"|[A-Z0-9_$#]+)(?:\.(?:\"[^\"]+\"|[A-Z0-9_$#]+))?).*?(?=(?:[A-Z_$#][A-Z0-9_$#]*\s*:\s*)?\bBEGIN(?:\s+(?:ATOMIC|NOT\s+ATOMIC))?\b)",
    ),
    body_style="DB2_BLOCK",
    identifier_quotes=(("\"", "\""),),
    elseif_keywords=("ELSEIF",),
    raise_keywords=("RESIGNAL", "SIGNAL"),
    call_keywords=("CALL",),
    dynamic_keywords=("EXECUTE IMMEDIATE", "EXECUTE", "PREPARE"),
    result_set_markers=("WITH RETURN",),
    reference_urls=(
        "https://www.ibm.com/docs/en/db2/11.5.x?topic=procedures-sql",
        "https://www.ibm.com/docs/en/db2-for-zos/13.0.0?topic=sql-procedural-language-pl",
    ),
    parameter_parser=parse_parameters,
    routine_attribute_extractor=extract_routine_attributes,
)

DB2 = PROFILE
