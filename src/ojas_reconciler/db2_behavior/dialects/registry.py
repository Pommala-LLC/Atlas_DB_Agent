from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Protocol

from ..core.canonical_json import canonical_digest
from .models import (
    DialectAdapterDescriptor,
    DialectCapability,
    DialectId,
    DialectRegistrySnapshot,
    RoutineInventory,
    RoutineParameter,
)


class DialectAdapterError(RuntimeError):
    pass


class RoutineSourceAdapter(Protocol):
    descriptor: DialectAdapterDescriptor
    def inventory(self, source: Path) -> RoutineInventory: ...


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _split_params(raw: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    i = 0
    while i < len(raw):
        ch = raw[i]
        nxt = raw[i + 1] if i + 1 < len(raw) else ""
        if quote:
            if ch == quote:
                if nxt == quote:
                    i += 1
                else:
                    quote = None
        elif ch in {"'", '"', '`'}:
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(raw[start:i].strip())
            start = i + 1
        i += 1
    if raw[start:].strip():
        parts.append(raw[start:].strip())
    return parts


def _parse_parameters(raw: str, dialect: DialectId) -> tuple[RoutineParameter, ...]:
    values: list[RoutineParameter] = []
    for index, item in enumerate(_split_params(raw), start=1):
        clean = item.strip()
        if not clean:
            continue
        mode = "IN"
        upper = clean.upper()
        if upper.startswith("INOUT "):
            mode, clean = "INOUT", clean[6:].strip()
        elif upper.startswith("OUT "):
            mode, clean = "OUT", clean[4:].strip()
        elif upper.startswith("IN "):
            mode, clean = "IN", clean[3:].strip()
        # SQL Server uses @name type [OUTPUT]. PostgreSQL/Oracle may place
        # mode after the parameter name. This inventory pass remains lexical.
        tokens = clean.split()
        if not tokens:
            continue
        name = tokens[0].strip('"`[]')
        if dialect is DialectId.SQLSERVER_TSQL:
            name = name.lstrip("@").upper()
            if tokens[-1].upper() in {"OUTPUT", "OUT"}:
                mode = "OUT"
                tokens = tokens[:-1]
        elif len(tokens) > 1 and tokens[1].upper() in {"IN", "OUT", "INOUT"}:
            mode = tokens[1].upper()
            tokens.pop(1)
        type_text = " ".join(tokens[1:]) or "UNKNOWN"
        values.append(RoutineParameter(name=name.upper() or f"ARG_{index}", mode=mode, type_text=type_text))
    return tuple(values)


class HeaderInventoryAdapter:
    def __init__(self, descriptor: DialectAdapterDescriptor) -> None:
        self.descriptor = descriptor

    def inventory(self, source: Path) -> RoutineInventory:
        text = source.read_text(encoding="utf-8")
        patterns = {
            DialectId.ORACLE_PLSQL: r"(?is)CREATE\s+(?:OR\s+REPLACE\s+)?PROCEDURE\s+((?:\"[^\"]+\"|[A-Z0-9_$#]+)(?:\.(?:\"[^\"]+\"|[A-Z0-9_$#]+))?)\s*\((.*?)\)\s*(?:AUTHID\s+\w+\s*)?(?:IS|AS)\b",
            DialectId.SQLSERVER_TSQL: r"(?is)CREATE\s+(?:OR\s+ALTER\s+)?PROCEDURE\s+((?:\[[^\]]+\]|[A-Z0-9_$#]+)(?:\.(?:\[[^\]]+\]|[A-Z0-9_$#]+))?)\s*(.*?)\bAS\b",
            DialectId.POSTGRESQL_PLPGSQL: r"(?is)CREATE\s+(?:OR\s+REPLACE\s+)?PROCEDURE\s+((?:\"[^\"]+\"|[A-Z0-9_$]+)(?:\.(?:\"[^\"]+\"|[A-Z0-9_$]+))?)\s*\((.*?)\).*?\bLANGUAGE\s+PLPGSQL\b",
            DialectId.MYSQL_STORED_PROGRAM: r"(?is)CREATE\s+PROCEDURE\s+((?:`[^`]+`|[A-Z0-9_$]+)(?:\.(?:`[^`]+`|[A-Z0-9_$]+))?)\s*\((.*?)\)\s*BEGIN\b",
        }
        pattern = patterns.get(self.descriptor.dialect)
        if not pattern:
            raise DialectAdapterError(f"No inventory pattern for {self.descriptor.dialect.value}")
        match = re.search(pattern, text)
        if not match:
            raise DialectAdapterError(f"UNSUPPORTED_SYNTAX: could not identify a {self.descriptor.dialect.value} procedure header.")
        qualified = re.sub(r"[\[\]`\"]", "", match.group(1))
        parts = qualified.split(".")
        schema = parts[0].upper() if len(parts) > 1 else None
        name = parts[-1].upper()
        parameters = _parse_parameters(match.group(2), self.descriptor.dialect)
        payload = {
            "schema_version": "routine-inventory-1.0",
            "dialect": self.descriptor.dialect,
            "schema_name": schema,
            "routine_name": name,
            "routine_kind": "PROCEDURE",
            "parameters": parameters,
            "source_digest": _digest(source),
            "body_status": "OPAQUE_REQUIRES_DIALECT_SEMANTIC_ADAPTER",
            "body_text": text[match.end():],
            "blockers": ("FULL_SEMANTIC_PIPELINE_NOT_ADMITTED",),
            "evidence_refs": (source.resolve().as_posix(), self.descriptor.adapter_id),
        }
        return RoutineInventory(**payload, content_digest=canonical_digest(payload))


class DialectAdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[DialectId, RoutineSourceAdapter] = {}

    def register(self, adapter: RoutineSourceAdapter) -> None:
        if adapter.descriptor.dialect in self._adapters:
            raise DialectAdapterError(f"Dialect already registered: {adapter.descriptor.dialect.value}")
        self._adapters[adapter.descriptor.dialect] = adapter

    def adapter(self, dialect: DialectId) -> RoutineSourceAdapter:
        try:
            return self._adapters[dialect]
        except KeyError as exc:
            raise DialectAdapterError(f"No adapter registered for {dialect.value}") from exc

    def snapshot(self) -> DialectRegistrySnapshot:
        payload = {
            "schema_version": "dialect-registry-snapshot-1.0",
            "adapters": tuple(sorted((value.descriptor for value in self._adapters.values()), key=lambda item: item.dialect.value)),
        }
        return DialectRegistrySnapshot(**payload, content_digest=canonical_digest(payload))

    @classmethod
    def default(cls) -> "DialectAdapterRegistry":
        registry = cls()
        registry.register(HeaderInventoryAdapter(DialectAdapterDescriptor(
            adapter_id="oracle-plsql-header-inventory-1.0",
            dialect=DialectId.ORACLE_PLSQL,
            version="1.0",
            capability=DialectCapability.HEADER_AND_INVENTORY,
            supported_constructs=("CREATE PROCEDURE header", "parameters", "source digest"),
            limitations=("Procedure body remains opaque; no behavior claims are emitted.",),
        )))
        registry.register(HeaderInventoryAdapter(DialectAdapterDescriptor(
            adapter_id="sqlserver-tsql-header-inventory-1.0",
            dialect=DialectId.SQLSERVER_TSQL,
            version="1.0",
            capability=DialectCapability.HEADER_AND_INVENTORY,
            supported_constructs=("CREATE/ALTER PROCEDURE header", "parameters", "source digest"),
            limitations=("Procedure body remains opaque; no behavior claims are emitted.",),
        )))
        registry.register(HeaderInventoryAdapter(DialectAdapterDescriptor(
            adapter_id="postgres-plpgsql-header-inventory-1.0",
            dialect=DialectId.POSTGRESQL_PLPGSQL,
            version="1.0",
            capability=DialectCapability.HEADER_AND_INVENTORY,
            supported_constructs=("CREATE PROCEDURE header", "parameters", "source digest"),
            limitations=("Procedure body remains opaque; no behavior claims are emitted.",),
        )))
        registry.register(HeaderInventoryAdapter(DialectAdapterDescriptor(
            adapter_id="mysql-stored-program-header-inventory-1.0",
            dialect=DialectId.MYSQL_STORED_PROGRAM,
            version="1.0",
            capability=DialectCapability.HEADER_AND_INVENTORY,
            supported_constructs=("CREATE PROCEDURE header", "parameters", "source digest"),
            limitations=("Procedure body remains opaque; no behavior claims are emitted.",),
        )))
        return registry
