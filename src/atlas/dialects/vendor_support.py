from __future__ import annotations

import re
from collections.abc import Iterable

from atlas.core.models import RoutineKind, RoutineParameter
from .syntax import _split_csv, _strip_identifier


def normalized_header_window(text: str, match: re.Match[str], *, width: int = 1200) -> str:
    return re.sub(r"\s+", " ", text[match.start() : min(len(text), match.end() + width)]).upper()


def parse_standard_parameters(
    raw: str,
    return_type: str | None,
    *,
    default_mode: str = "IN",
    accepted_modes: Iterable[str] = ("IN", "OUT", "INOUT"),
) -> tuple[RoutineParameter, ...]:
    allowed = {value.upper() for value in accepted_modes}
    values: list[RoutineParameter] = []
    for index, item in enumerate(_split_csv(raw), start=1):
        clean = re.sub(r"\s+", " ", item.strip())
        if not clean:
            continue
        mode = default_mode.upper()
        default_text: str | None = None
        default_match = re.search(r"(?is)\s+(?:DEFAULT|:=|=)\s+(.+)$", clean)
        if default_match:
            default_text = default_match.group(1).strip()
            clean = clean[: default_match.start()].strip()
        tokens = clean.split()
        if tokens and tokens[0].upper() in allowed:
            mode = tokens.pop(0).upper()
        name = tokens.pop(0).lstrip(":@") if tokens else f"ARG_{index}"
        if tokens and tokens[0].upper() in allowed:
            mode = tokens.pop(0).upper()
        type_text = " ".join(tokens) or "UNKNOWN"
        values.append(RoutineParameter(name=name, mode=mode, type_text=type_text, default_text=default_text))
    if return_type:
        values.append(RoutineParameter(name="RETURN_VALUE", mode="RETURN", type_text=return_type.strip()))
    return tuple(values)


def parse_sqlserver_parameters(raw: str, return_type: str | None) -> tuple[RoutineParameter, ...]:
    values: list[RoutineParameter] = []
    for index, item in enumerate(_split_csv(raw), start=1):
        clean = re.sub(r"\s+", " ", item.strip())
        if not clean:
            continue
        default_text: str | None = None
        default_match = re.search(r"(?is)\s*=\s+(.+?)(?=\s+(?:OUT|OUTPUT)\s*$|$)", clean)
        if default_match:
            default_text = default_match.group(1).strip()
            clean = (clean[: default_match.start()] + clean[default_match.end() :]).strip()
        tokens = clean.split()
        if not tokens:
            continue
        name = tokens.pop(0).lstrip("@") or f"ARG_{index}"
        mode = "IN"
        if tokens and tokens[-1].upper() in {"OUT", "OUTPUT"}:
            mode = "OUT"
            tokens.pop()
        type_text = " ".join(tokens) or "UNKNOWN"
        values.append(RoutineParameter(name=name, mode=mode, type_text=type_text, default_text=default_text))
    if return_type:
        values.append(RoutineParameter(name="RETURN_VALUE", mode="RETURN", type_text=return_type.strip()))
    return tuple(values)


def routine_kind_attributes(kind: RoutineKind) -> dict[str, object]:
    return {"routine_kind": kind.value}
