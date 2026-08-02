from __future__ import annotations

import re

from atlas.core.models import DialectId, RoutineKind, RoutineParameter
from ..base import ProceduralDialectProfile
from ..syntax import _split_csv, _strip_identifier
from ..vendor_support import normalized_header_window, routine_kind_attributes


def parse_parameters(raw: str, return_type: str | None) -> tuple[RoutineParameter, ...]:
    """Parse PostgreSQL's named and unnamed argument forms.

    CREATE FUNCTION accepts type-only arguments as well as IN/OUT/INOUT and
    VARIADIC modes. Type-only arguments receive stable ARG_n evidence names.
    """
    type_starters = {
        "BIGINT", "BIGSERIAL", "BIT", "BOOLEAN", "BOOL", "BYTEA", "CHAR", "CHARACTER",
        "DATE", "DEC", "DECIMAL", "DOUBLE", "EVENT_TRIGGER", "INET", "INT", "INT2", "INT4",
        "INT8", "INTEGER", "INTERVAL", "JSON", "JSONB", "MONEY", "NUMERIC", "REAL", "RECORD",
        "SETOF", "SMALLINT", "SMALLSERIAL", "TEXT", "TIME", "TIMESTAMP", "TRIGGER", "UUID",
        "VARBIT", "VARCHAR", "VOID", "XML",
    }
    values: list[RoutineParameter] = []
    for index, item in enumerate(_split_csv(raw), start=1):
        clean = re.sub(r"\s+", " ", item.strip())
        if not clean:
            continue
        default_text: str | None = None
        default_match = re.search(r"(?is)\s+(?:DEFAULT|=)\s+(.+)$", clean)
        if default_match:
            default_text = default_match.group(1).strip()
            clean = clean[: default_match.start()].strip()
        tokens = clean.split()
        mode = "IN"
        if tokens and tokens[0].upper() in {"IN", "OUT", "INOUT", "VARIADIC"}:
            mode = tokens.pop(0).upper()
        if not tokens:
            continue
        first = tokens[0]
        first_upper = _strip_identifier(first).upper()
        unnamed = (
            len(tokens) == 1
            or first_upper in type_starters
            or "." in first
            or "[" in first
            or "(" in first
            or first.startswith('"') and len(tokens) == 1
        )
        if unnamed:
            name = f"ARG_{index}"
            type_text = " ".join(tokens)
        else:
            name = tokens.pop(0).lstrip(":@")
            type_text = " ".join(tokens) or "UNKNOWN"
        values.append(RoutineParameter(name=name, mode=mode, type_text=type_text, default_text=default_text))
    if return_type:
        values.append(RoutineParameter(name="RETURN_VALUE", mode="RETURN", type_text=return_type.strip()))
    return tuple(values)


def extract_routine_attributes(text: str, match: re.Match[str], kind: RoutineKind) -> dict[str, object]:
    header = normalized_header_window(text, match, width=1800)
    values = routine_kind_attributes(kind)
    volatility = next((v for v in ("IMMUTABLE", "STABLE", "VOLATILE") if f" {v}" in header), "VOLATILE_DEFAULT")
    parallel = re.search(r"\bPARALLEL\s+(UNSAFE|RESTRICTED|SAFE)\b", header)
    security = "DEFINER" if "SECURITY DEFINER" in header else "INVOKER"
    values.update(
        {
            "security_mode": security,
            "volatility": volatility,
            "parallel_safety": parallel.group(1) if parallel else "UNSAFE_DEFAULT",
            "strict": " STRICT" in header or "RETURNS NULL ON NULL INPUT" in header,
            "leakproof": " LEAKPROOF" in header,
            "set_configuration": tuple(re.findall(r"\bSET\s+([A-Z0-9_.]+)\s+(?:TO|=)\s+([^\s,]+)", header)),
        }
    )
    return values


PROFILE = ProceduralDialectProfile(
    dialect=DialectId.POSTGRESQL_PLPGSQL,
    adapter_id="atlas-postgresql-plpgsql-2.2",
    header_patterns=(
        r'(?is)CREATE\s+(?:OR\s+REPLACE\s+)?PROCEDURE\s+(?P<name>(?:"[^"]+"|[A-Z_][A-Z0-9_$]*)(?:\.(?:"[^"]+"|[A-Z_][A-Z0-9_$]*))?)\s*\(',
    ),
    function_patterns=(
        r'(?is)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?P<name>(?:"[^"]+"|[A-Z_][A-Z0-9_$]*)(?:\.(?:"[^"]+"|[A-Z_][A-Z0-9_$]*))?)\s*\(',
    ),
    trigger_patterns=(),
    body_style="POSTGRES_DOLLAR_BODY",
    identifier_quotes=(("\"", "\""),),
    elseif_keywords=("ELSIF",),
    raise_keywords=("RAISE",),
    call_keywords=("CALL", "PERFORM"),
    dynamic_keywords=("RETURN QUERY EXECUTE", "EXECUTE"),
    result_set_markers=("RETURN QUERY", "RETURN NEXT"),
    reference_urls=(
        "https://www.postgresql.org/docs/current/plpgsql-control-structures.html",
        "https://www.postgresql.org/docs/current/plpgsql-statements.html",
        "https://www.postgresql.org/docs/current/plpgsql-transactions.html",
    ),
    parameter_parser=parse_parameters,
    routine_attribute_extractor=extract_routine_attributes,
    initial_declare_section=True,
)

POSTGRESQL = PROFILE
