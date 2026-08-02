from __future__ import annotations

import re

from atlas.core.models import DialectId, RoutineKind, RoutineParameter
from ..base import ProceduralDialectProfile
from ..vendor_support import normalized_header_window, parse_standard_parameters, routine_kind_attributes


def parse_parameters(raw: str, return_type: str | None) -> tuple[RoutineParameter, ...]:
    return parse_standard_parameters(raw, return_type)


def extract_routine_attributes(text: str, match: re.Match[str], kind: RoutineKind) -> dict[str, object]:
    header = normalized_header_window(text, match, width=1700)
    values = routine_kind_attributes(kind)
    security = re.search(r"\bSQL\s+SECURITY\s+(DEFINER|INVOKER)\b", header)
    definer = re.search(r"\bDEFINER\s*=\s*([^\s]+)", header)
    data_access = next((v for v in ("NO SQL", "CONTAINS SQL", "READS SQL DATA", "MODIFIES SQL DATA") if v in header), "CONTAINS SQL DEFAULT")
    values.update(
        {
            "security_mode": security.group(1) if security else "DEFINER_DEFAULT",
            "definer": definer.group(1) if definer else None,
            "deterministic": " DETERMINISTIC" in header and "NOT DETERMINISTIC" not in header,
            "data_access": data_access,
            "sql_data_access": data_access,
            "comment_declared": " COMMENT " in header,
        }
    )
    return values


PROFILE = ProceduralDialectProfile(
    dialect=DialectId.MYSQL_STORED_PROGRAM,
    adapter_id="atlas-mysql-stored-program-2.2",
    header_patterns=(
        r"(?is)CREATE\s+(?:DEFINER\s*=\s*[^\s]+\s+)?PROCEDURE\s+(?P<name>(?:`[^`]+`|[A-Z0-9_$]+)(?:\.(?:`[^`]+`|[A-Z0-9_$]+))?)\s*\((?P<params>.*?)\)\s*(?:(?:COMMENT\s+'.*?'|LANGUAGE\s+SQL|NOT\s+DETERMINISTIC|DETERMINISTIC|CONTAINS\s+SQL|NO\s+SQL|READS\s+SQL\s+DATA|MODIFIES\s+SQL\s+DATA|SQL\s+SECURITY\s+\w+)\s*)*(?=BEGIN\b|RETURN\b|SET\b|SELECT\b|INSERT\b|UPDATE\b|DELETE\b|CALL\b|SIGNAL\b|RESIGNAL\b|DO\b)",
    ),
    function_patterns=(
        r"(?is)CREATE\s+(?:DEFINER\s*=\s*[^\s]+\s+)?FUNCTION\s+(?P<name>(?:`[^`]+`|[A-Z0-9_$]+)(?:\.(?:`[^`]+`|[A-Z0-9_$]+))?)\s*\((?P<params>.*?)\)\s+RETURNS\s+(?P<return_type>.+?)(?=\s+(?:COMMENT\s+'|LANGUAGE\s+SQL\b|NOT\s+DETERMINISTIC\b|DETERMINISTIC\b|CONTAINS\s+SQL\b|NO\s+SQL\b|READS\s+SQL\s+DATA\b|MODIFIES\s+SQL\s+DATA\b|SQL\s+SECURITY\s+\w+\b|BEGIN\b|RETURN\b|SET\b|SELECT\b|INSERT\b|UPDATE\b|DELETE\b|CALL\b|SIGNAL\b|RESIGNAL\b))\s*(?:(?:COMMENT\s+'.*?'|LANGUAGE\s+SQL|NOT\s+DETERMINISTIC|DETERMINISTIC|CONTAINS\s+SQL|NO\s+SQL|READS\s+SQL\s+DATA|MODIFIES\s+SQL\s+DATA|SQL\s+SECURITY\s+\w+)\s*)*(?=BEGIN\b|RETURN\b|SET\b|SELECT\b|INSERT\b|UPDATE\b|DELETE\b|CALL\b|SIGNAL\b|RESIGNAL\b)",
    ),
    trigger_patterns=(
        r"(?is)CREATE\s+(?:DEFINER\s*=\s*[^\s]+\s+)?TRIGGER\s+(?P<name>(?:`[^`]+`|[A-Z0-9_$]+)(?:\.(?:`[^`]+`|[A-Z0-9_$]+))?).*?FOR\s+EACH\s+ROW\s+(?=BEGIN\b|SET\b|INSERT\b|UPDATE\b|DELETE\b|CALL\b|SIGNAL\b|RESIGNAL\b)",
    ),
    body_style="MYSQL_BODY",
    identifier_quotes=(("`", "`"),),
    elseif_keywords=("ELSEIF",),
    raise_keywords=("RESIGNAL", "SIGNAL"),
    call_keywords=("CALL",),
    dynamic_keywords=("PREPARE", "EXECUTE", "DEALLOCATE PREPARE"),
    result_set_markers=("SELECT",),
    reference_urls=(
        "https://dev.mysql.com/doc/refman/8.4/en/sql-compound-statements.html",
        "https://dev.mysql.com/doc/refman/8.4/en/cursors.html",
        "https://dev.mysql.com/doc/refman/8.4/en/declare-handler.html",
    ),
    parameter_parser=parse_parameters,
    routine_attribute_extractor=extract_routine_attributes,
)

MYSQL = PROFILE
