from __future__ import annotations

import re

from atlas.core.models import DialectId, RoutineKind, RoutineParameter
from ..base import ProceduralDialectProfile
from ..vendor_support import normalized_header_window, parse_sqlserver_parameters, routine_kind_attributes


def parse_parameters(raw: str, return_type: str | None) -> tuple[RoutineParameter, ...]:
    return parse_sqlserver_parameters(raw, return_type)


def extract_routine_attributes(text: str, match: re.Match[str], kind: RoutineKind) -> dict[str, object]:
    header = normalized_header_window(text, match, width=1600)
    values = routine_kind_attributes(kind)
    execute_as = re.search(r"\bEXECUTE\s+AS\s+(CALLER|SELF|OWNER|'[^']+'|\[[^\]]+\]|[A-Z0-9_$#]+)", header)
    values.update(
        {
            "execute_as": execute_as.group(1) if execute_as else "CALLER_DEFAULT",
            "security_mode": execute_as.group(1) if execute_as else "CALLER_DEFAULT",
            "schemabinding": "SCHEMABINDING" in header,
            "native_compilation": "NATIVE_COMPILATION" in header,
            "recompile": "RECOMPILE" in header,
            "encrypted_definition": "ENCRYPTION" in header,
            "null_input_behavior": "RETURNS NULL ON NULL INPUT" if "RETURNS NULL ON NULL INPUT" in header else "CALLED ON NULL INPUT",
        }
    )
    return values


PROFILE = ProceduralDialectProfile(
    dialect=DialectId.SQLSERVER_TSQL,
    adapter_id="atlas-sqlserver-tsql-2.2",
    header_patterns=(
        r"(?is)CREATE\s+(?:OR\s+ALTER\s+)?(?:PROC|PROCEDURE)\s+(?P<name>(?:\[[^\]]+\]|[A-Z0-9_$#]+)(?:\.(?:\[[^\]]+\]|[A-Z0-9_$#]+))?)\s*(?P<params>.*?)\bAS\b(?=\s*(?:BEGIN|SET|DECLARE|SELECT|WITH|INSERT|UPDATE|DELETE|MERGE|EXEC|IF|WHILE|RETURN|THROW|RAISERROR))",
        r"(?is)ALTER\s+(?:PROC|PROCEDURE)\s+(?P<name>(?:\[[^\]]+\]|[A-Z0-9_$#]+)(?:\.(?:\[[^\]]+\]|[A-Z0-9_$#]+))?)\s*(?P<params>.*?)\bAS\b(?=\s*(?:BEGIN|SET|DECLARE|SELECT|WITH|INSERT|UPDATE|DELETE|MERGE|EXEC|IF|WHILE|RETURN|THROW|RAISERROR))",
    ),
    function_patterns=(
        r"(?is)CREATE\s+(?:OR\s+ALTER\s+)?FUNCTION\s+(?P<name>(?:\[[^\]]+\]|[A-Z0-9_$#]+)(?:\.(?:\[[^\]]+\]|[A-Z0-9_$#]+))?)\s*\((?P<params>.*?)\)\s+RETURNS\s+(?P<return_type>.+?)\s+(?:WITH\s+.+?\s+)?AS\b",
    ),
    trigger_patterns=(
        r"(?is)CREATE\s+(?:OR\s+ALTER\s+)?TRIGGER\s+(?P<name>(?:\[[^\]]+\]|[A-Z0-9_$#]+)(?:\.(?:\[[^\]]+\]|[A-Z0-9_$#]+))?).*?\bAS\b",
    ),
    body_style="TSQL_BATCH",
    identifier_quotes=(("[", "]"), ("\"", "\"")),
    parameter_prefix="@",
    assignment_operators=("=", "+=", "-=", "*=", "/="),
    elseif_keywords=(),
    raise_keywords=("THROW", "RAISERROR"),
    call_keywords=("EXEC", "EXECUTE"),
    dynamic_keywords=("SP_EXECUTESQL", "EXEC", "EXECUTE"),
    result_set_markers=("SELECT",),
    lexical_scope_blocks=False,
    reference_urls=(
        "https://learn.microsoft.com/en-us/sql/t-sql/statements/create-procedure-transact-sql",
        "https://learn.microsoft.com/en-us/sql/t-sql/language-elements/try-catch-transact-sql",
        "https://learn.microsoft.com/en-us/sql/relational-databases/user-defined-functions/create-user-defined-functions-database-engine",
    ),
    parameter_parser=parse_parameters,
    routine_attribute_extractor=extract_routine_attributes,
)

SQLSERVER = PROFILE
