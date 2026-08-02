from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .models import DATABASE_BY_TYPE, DatabaseDescriptor, DatabaseType, ProcedureAnalysisError, SourceInput

ALLOWED_SUFFIXES = {".sql", ".db2", ".ddl", ".txt"}
MAX_FILES = 100
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_BATCH_BYTES = 10 * 1024 * 1024


def database_descriptor(value: str | DatabaseType) -> DatabaseDescriptor:
    try:
        kind = value if isinstance(value, DatabaseType) else DatabaseType(value)
    except ValueError as exc:
        raise ProcedureAnalysisError("Select one supported database type before analysis.") from exc
    return DATABASE_BY_TYPE[kind]


def safe_filename(value: str, fallback: str = "source.sql") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", Path(value or fallback).name).strip(".-")
    return cleaned or fallback


def safe_id(value: str, fallback: str = "analysis") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.")
    return cleaned[:80] or fallback


def decode_upload(name: str, payload: bytes) -> SourceInput:
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ProcedureAnalysisError(f"{name} is not valid UTF-8 text.") from exc
    return SourceInput(safe_filename(name), text, "UPLOAD")


def validate_sources(sources: Iterable[SourceInput]) -> tuple[SourceInput, ...]:
    values = tuple(sources)
    if not values:
        raise ProcedureAnalysisError("Paste a stored procedure/script or upload at least one SQL file.")
    if len(values) > MAX_FILES:
        raise ProcedureAnalysisError(f"An analysis may contain at most {MAX_FILES} source files.")
    total, seen, validated = 0, {}, []
    for source in values:
        encoded = source.text.encode("utf-8")
        _validate_one(source, encoded)
        total += len(encoded)
        name = _dedupe_name(safe_filename(source.name), seen)
        validated.append(SourceInput(name, source.text, source.intake_kind))
    if total > MAX_BATCH_BYTES:
        raise ProcedureAnalysisError(f"The analysis exceeds the {MAX_BATCH_BYTES // 1048576} MB total limit.")
    return tuple(validated)


def _validate_one(source: SourceInput, encoded: bytes) -> None:
    if not source.text.strip():
        raise ProcedureAnalysisError(f"{source.name} is empty.")
    if len(encoded) > MAX_FILE_BYTES:
        raise ProcedureAnalysisError(f"{source.name} exceeds the {MAX_FILE_BYTES // 1048576} MB per-file limit.")
    if Path(source.name).suffix.lower() not in ALLOWED_SUFFIXES:
        allowed = ", ".join(sorted(ALLOWED_SUFFIXES))
        raise ProcedureAnalysisError(f"Unsupported file type for {source.name}; use {allowed}.")


def _dedupe_name(name: str, seen: dict[str, int]) -> str:
    count = seen.get(name.casefold(), 0) + 1
    seen[name.casefold()] = count
    if count == 1:
        return name
    path = Path(name)
    return f"{path.stem}-{count}{path.suffix}"
