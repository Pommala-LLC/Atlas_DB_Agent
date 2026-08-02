from __future__ import annotations

import hashlib
import importlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from ..core.canonical_json import canonical_digest
from ..type_system.models import (
    CanonicalSqlType,
    ColumnDefinition,
    ForeignKeyDefinition,
    RelationDefinition,
    ResolutionCompleteness,
    SqlTypeFamily,
    TemporalRole,
    TypeResolutionStatus,
)
from .models import CatalogRelation, CatalogSnapshot, CatalogSourceKind, RelationKind


class CatalogProviderError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_ref(schema: str | None, name: str) -> str:
    clean_schema = (schema or "").strip().strip('"').upper()
    clean_name = name.strip().strip('"').upper()
    return f"{clean_schema}.{clean_name}" if clean_schema else clean_name


def _family(database_type: str) -> SqlTypeFamily:
    value = database_type.upper().strip()
    if value in {"SMALLINT"}:
        return SqlTypeFamily.SMALL_INTEGER
    if value in {"INTEGER", "INT"}:
        return SqlTypeFamily.INTEGER
    if value in {"BIGINT"}:
        return SqlTypeFamily.BIG_INTEGER
    if value.startswith(("DECIMAL", "NUMERIC", "DECFLOAT")):
        return SqlTypeFamily.DECIMAL
    if value.startswith(("REAL", "DOUBLE", "FLOAT")):
        return SqlTypeFamily.FLOATING_POINT
    if value.startswith(("CHAR", "VARCHAR", "CLOB")):
        return SqlTypeFamily.LOB if value.startswith("CLOB") else SqlTypeFamily.CHARACTER
    if value.startswith(("GRAPHIC", "VARGRAPHIC", "DBCLOB")):
        return SqlTypeFamily.LOB if value.startswith("DBCLOB") else SqlTypeFamily.GRAPHIC
    if value == "DATE":
        return SqlTypeFamily.DATE
    if value == "TIME":
        return SqlTypeFamily.TIME
    if value.startswith("TIMESTAMP"):
        return SqlTypeFamily.TIMESTAMP
    if value in {"BOOLEAN"}:
        return SqlTypeFamily.BOOLEAN
    if value.startswith(("BINARY", "VARBINARY", "BLOB")):
        return SqlTypeFamily.LOB if value.startswith("BLOB") else SqlTypeFamily.BINARY
    if value.startswith("XML"):
        return SqlTypeFamily.XML
    return SqlTypeFamily.UNKNOWN


def _canonical_type(
    database_type: str,
    *,
    length: int | None = None,
    precision: int | None = None,
    scale: int | None = None,
    nullable: bool | None = None,
    source_ref: str,
) -> CanonicalSqlType:
    family = _family(database_type)
    return CanonicalSqlType(
        family=family,
        database_type=database_type.upper(),
        length=length if length and length > 0 else None,
        precision=precision if precision and precision > 0 else None,
        scale=scale if scale is not None and scale >= 0 else None,
        nullable=nullable,
        resolution_status=(TypeResolutionStatus.CATALOG_RESOLVED if family is not SqlTypeFamily.UNKNOWN else TypeResolutionStatus.UNKNOWN),
        completeness=(ResolutionCompleteness.COMPLETE if family is not SqlTypeFamily.UNKNOWN else ResolutionCompleteness.UNKNOWN),
        source_refs=(source_ref,),
    )


def _relation_definition(
    *,
    schema: str,
    name: str,
    columns: Iterable[ColumnDefinition],
    provider_ref: str,
    primary_key: Iterable[str] = (),
    unique_constraints: Iterable[Iterable[str]] = (),
    foreign_keys: Iterable[ForeignKeyDefinition] = (),
    check_constraints: Iterable[str] = (),
    temporal_kind: str = "NONE",
) -> RelationDefinition:
    payload = {
        "schema_name": schema.upper(),
        "relation_name": name.upper(),
        "columns": tuple(columns),
        "primary_key": tuple(primary_key),
        "unique_constraints": tuple(tuple(value) for value in unique_constraints),
        "foreign_keys": tuple(foreign_keys),
        "check_constraints": tuple(check_constraints),
        "temporal_kind": temporal_kind,
        "provider_ref": provider_ref,
    }
    return RelationDefinition(**payload, content_digest=canonical_digest(payload))


class JsonCatalogProvider:
    def __init__(self, path: Path) -> None:
        self.path = path.resolve()

    def load(self) -> CatalogSnapshot:
        return CatalogSnapshot.model_validate_json(self.path.read_text(encoding="utf-8"))


# Minimal SQL lexical helpers. These are deliberately bounded and retain unresolved
# constructs instead of trying to be a second SQL parser.
def _strip_comments(sql: str) -> str:
    output: list[str] = []
    i = 0
    quote: str | None = None
    while i < len(sql):
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < len(sql) else ""
        if quote:
            output.append(ch)
            if ch == quote:
                if nxt == quote:
                    output.append(nxt)
                    i += 1
                else:
                    quote = None
            i += 1
            continue
        if ch in {"'", '"'}:
            quote = ch
            output.append(ch)
            i += 1
            continue
        if ch == "-" and nxt == "-":
            i += 2
            while i < len(sql) and sql[i] not in "\r\n":
                i += 1
            output.append("\n")
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i + 1 < len(sql) and not (sql[i] == "*" and sql[i + 1] == "/"):
                i += 1
            i += 2
            output.append(" ")
            continue
        output.append(ch)
        i += 1
    return "".join(output)


def _split_statements(sql: str) -> Iterator[str]:
    sql = _strip_comments(sql)
    start = 0
    quote: str | None = None
    depth = 0
    i = 0
    while i < len(sql):
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < len(sql) else ""
        if quote:
            if ch == quote:
                if nxt == quote:
                    i += 1
                else:
                    quote = None
            i += 1
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == ";" and depth == 0:
            value = sql[start:i].strip()
            if value:
                yield value
            start = i + 1
        i += 1
    value = sql[start:].strip()
    if value:
        yield value


def _split_top_level(value: str, delimiter: str = ",") -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    i = 0
    while i < len(value):
        ch = value[i]
        nxt = value[i + 1] if i + 1 < len(value) else ""
        if quote:
            if ch == quote:
                if nxt == quote:
                    i += 1
                else:
                    quote = None
        elif ch in {"'", '"'}:
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == delimiter and depth == 0:
            parts.append(value[start:i].strip())
            start = i + 1
        i += 1
    parts.append(value[start:].strip())
    return [item for item in parts if item]


def _extract_parenthesized(value: str, start: int) -> tuple[str, int]:
    if value[start] != "(":
        raise CatalogProviderError("Expected parenthesized DDL body.")
    depth = 0
    quote: str | None = None
    i = start
    while i < len(value):
        ch = value[i]
        nxt = value[i + 1] if i + 1 < len(value) else ""
        if quote:
            if ch == quote:
                if nxt == quote:
                    i += 1
                else:
                    quote = None
        elif ch in {"'", '"'}:
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return value[start + 1 : i], i + 1
        i += 1
    raise CatalogProviderError("Unterminated parenthesized DDL body.")


def _parse_type(type_text: str, *, nullable: bool, source_ref: str) -> CanonicalSqlType:
    clean = type_text.strip()
    match = re.match(r"(?is)^([A-Z][A-Z0-9 ]*)(?:\((\d+)(?:\s*,\s*(\d+))?\))?", clean.upper())
    if not match:
        return _canonical_type(clean or "UNKNOWN", nullable=nullable, source_ref=source_ref)
    database_type = " ".join(match.group(1).split())
    first = int(match.group(2)) if match.group(2) else None
    second = int(match.group(3)) if match.group(3) else None
    family = _family(database_type)
    return _canonical_type(
        database_type,
        length=(first if family in {SqlTypeFamily.CHARACTER, SqlTypeFamily.GRAPHIC, SqlTypeFamily.BINARY, SqlTypeFamily.LOB} else None),
        precision=(first if family is SqlTypeFamily.DECIMAL else None),
        scale=(second if family is SqlTypeFamily.DECIMAL else None),
        nullable=nullable,
        source_ref=source_ref,
    )


class DdlCatalogProvider:
    """Build a catalog snapshot from CREATE TABLE/VIEW/ALIAS statements.

    The adapter supports the deterministic subset needed by fixture planning and
    view lineage. Unsupported DDL is retained in snapshot limitations.
    """

    def __init__(self, paths: Iterable[Path], *, platform: str = "DB2_LUW", provider_ref: str = "ddl-catalog") -> None:
        self.paths = tuple(Path(value).resolve() for value in paths)
        self.platform = platform
        self.provider_ref = provider_ref

    def load(self) -> CatalogSnapshot:
        relations: list[CatalogRelation] = []
        limitations: list[str] = []
        for path in self.paths:
            text = path.read_text(encoding="utf-8")
            for statement_index, statement in enumerate(_split_statements(text), start=1):
                upper = statement.upper().lstrip()
                evidence = f"{path.as_posix()}#statement-{statement_index}"
                try:
                    if re.match(r"(?is)^CREATE\s+(?:OR\s+REPLACE\s+)?TABLE\b", upper):
                        relations.append(self._parse_table(statement, evidence))
                    elif re.match(r"(?is)^CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\b", upper):
                        relations.append(self._parse_view(statement, evidence))
                    elif re.match(r"(?is)^CREATE\s+(?:ALIAS|SYNONYM)\b", upper):
                        relations.append(self._parse_synonym(statement, evidence))
                    elif "CREATE" in upper:
                        limitations.append(f"DDL_NOT_ADMITTED:{evidence}")
                except CatalogProviderError as exc:
                    limitations.append(f"DDL_PARSE_PARTIAL:{evidence}:{exc}")
        payload = {
            "schema_version": "catalog-snapshot-1.0",
            "snapshot_id": f"catalog-{hashlib.sha256('|'.join(p.as_posix() for p in self.paths).encode()).hexdigest()[:16]}",
            "platform": self.platform,
            "provider_ref": self.provider_ref,
            "source_kind": CatalogSourceKind.DDL_FILES,
            "captured_at": _now(),
            "schema_refs": tuple(sorted({item.definition.schema_name for item in relations})),
            "relations": tuple(relations),
            "unresolved_refs": (),
            "limitations": tuple(sorted(set(limitations))),
        }
        return CatalogSnapshot(**payload, content_digest=canonical_digest(payload))

    def _name_after(self, statement: str, keyword: str) -> tuple[str, str]:
        match = re.match(rf"(?is)^CREATE\s+(?:OR\s+REPLACE\s+)?{keyword}\s+((?:\"[^\"]+\"|[A-Z0-9_$#]+)(?:\s*\.\s*(?:\"[^\"]+\"|[A-Z0-9_$#]+))?)", statement.strip(), re.I)
        if not match:
            raise CatalogProviderError(f"Could not parse {keyword} name.")
        raw = re.sub(r"\s+", "", match.group(1))
        parts = [part.strip('"') for part in raw.split(".")]
        return ((parts[0] if len(parts) > 1 else "CURRENT_SCHEMA"), parts[-1])

    def _parse_table(self, statement: str, evidence: str) -> CatalogRelation:
        schema, name = self._name_after(statement, "TABLE")
        open_at = statement.find("(")
        if open_at < 0:
            raise CatalogProviderError("CREATE TABLE has no column body.")
        body, _ = _extract_parenthesized(statement, open_at)
        columns: list[ColumnDefinition] = []
        primary: list[str] = []
        uniques: list[tuple[str, ...]] = []
        foreign_keys: list[ForeignKeyDefinition] = []
        checks: list[str] = []
        for item in _split_top_level(body):
            upper = item.upper().strip()
            constraint_prefix = re.sub(r"(?is)^CONSTRAINT\s+(?:\"[^\"]+\"|[A-Z0-9_$#]+)\s+", "", item, count=1).strip()
            cupper = constraint_prefix.upper()
            if cupper.startswith("PRIMARY KEY"):
                cols, _ = _extract_parenthesized(constraint_prefix, constraint_prefix.find("("))
                primary = [part.strip().strip('"').upper() for part in _split_top_level(cols)]
                continue
            if cupper.startswith("UNIQUE"):
                cols, _ = _extract_parenthesized(constraint_prefix, constraint_prefix.find("("))
                uniques.append(tuple(part.strip().strip('"').upper() for part in _split_top_level(cols)))
                continue
            if cupper.startswith("FOREIGN KEY"):
                local, after = _extract_parenthesized(constraint_prefix, constraint_prefix.find("("))
                ref_match = re.search(r"(?is)\bREFERENCES\s+((?:\"[^\"]+\"|[A-Z0-9_$#]+)(?:\s*\.\s*(?:\"[^\"]+\"|[A-Z0-9_$#]+))?)", constraint_prefix[after:])
                if not ref_match:
                    raise CatalogProviderError("FOREIGN KEY missing REFERENCES.")
                target = re.sub(r"\s+", "", ref_match.group(1))
                target_parts = [value.strip('"') for value in target.split(".")]
                ref_start = constraint_prefix.find("(", after + ref_match.end())
                referenced, _ = _extract_parenthesized(constraint_prefix, ref_start)
                foreign_keys.append(ForeignKeyDefinition(
                    local_columns=tuple(part.strip().strip('"').upper() for part in _split_top_level(local)),
                    referenced_schema=(target_parts[0].upper() if len(target_parts) > 1 else schema.upper()),
                    referenced_relation=target_parts[-1].upper(),
                    referenced_columns=tuple(part.strip().strip('"').upper() for part in _split_top_level(referenced)),
                    source_refs=(evidence,),
                ))
                continue
            if cupper.startswith("CHECK"):
                checks.append(constraint_prefix)
                continue
            column_match = re.match(r"(?is)^((?:\"[^\"]+\"|[A-Z0-9_$#]+))\s+(.+)$", item.strip())
            if not column_match:
                raise CatalogProviderError(f"Unrecognized table item: {item[:80]}")
            column_name = column_match.group(1).strip('"').upper()
            remainder = column_match.group(2).strip()
            nullable = not bool(re.search(r"(?is)\bNOT\s+NULL\b", remainder))
            generated = bool(re.search(r"(?is)\bGENERATED\b", remainder))
            identity = bool(re.search(r"(?is)\bIDENTITY\b", remainder))
            default_match = re.search(r"(?is)\bDEFAULT\s+(.+?)(?=\s+(?:NOT\s+NULL|GENERATED|PRIMARY\s+KEY|UNIQUE|REFERENCES|CHECK)\b|$)", remainder)
            default = default_match.group(1).strip() if default_match else None
            type_text = re.split(r"(?is)\s+(?:NOT\s+NULL|DEFAULT|GENERATED|PRIMARY\s+KEY|UNIQUE|REFERENCES|CHECK)\b", remainder, maxsplit=1)[0]
            sql_type = _parse_type(type_text, nullable=nullable, source_ref=evidence)
            columns.append(ColumnDefinition(
                relation_name=name.upper(),
                column_name=column_name,
                sql_type=sql_type,
                nullable=nullable,
                default_expression=default,
                generated=generated,
                identity_column=identity,
                temporal_role=TemporalRole.NONE,
                source_refs=(evidence,),
            ))
            if re.search(r"(?is)\bPRIMARY\s+KEY\b", remainder):
                primary.append(column_name)
            if re.search(r"(?is)\bUNIQUE\b", remainder):
                uniques.append((column_name,))
        definition = _relation_definition(
            schema=schema,
            name=name,
            columns=columns,
            provider_ref=self.provider_ref,
            primary_key=primary,
            unique_constraints=uniques,
            foreign_keys=foreign_keys,
            check_constraints=checks,
        )
        return CatalogRelation(
            relation_ref=_normalize_ref(schema, name),
            relation_kind=RelationKind.TABLE,
            definition=definition,
            evidence_refs=(evidence,),
        )

    def _parse_view(self, statement: str, evidence: str) -> CatalogRelation:
        schema, name = self._name_after(statement, "VIEW")
        match = re.search(r"(?is)\bAS\b\s+(SELECT|WITH)\b", statement)
        if not match:
            raise CatalogProviderError("CREATE VIEW missing AS SELECT/WITH body.")
        body = statement[match.start(1):].strip()
        definition = _relation_definition(schema=schema, name=name, columns=(), provider_ref=self.provider_ref)
        return CatalogRelation(
            relation_ref=_normalize_ref(schema, name),
            relation_kind=RelationKind.VIEW,
            definition=definition,
            view_definition_text=body,
            evidence_refs=(evidence,),
        )

    def _parse_synonym(self, statement: str, evidence: str) -> CatalogRelation:
        match = re.match(r"(?is)^CREATE\s+(?:ALIAS|SYNONYM)\s+((?:\"[^\"]+\"|[A-Z0-9_$#]+)(?:\s*\.\s*(?:\"[^\"]+\"|[A-Z0-9_$#]+))?)\s+FOR\s+((?:\"[^\"]+\"|[A-Z0-9_$#]+)(?:\s*\.\s*(?:\"[^\"]+\"|[A-Z0-9_$#]+))?)", statement.strip())
        if not match:
            raise CatalogProviderError("Could not parse ALIAS/SYNONYM.")
        source = re.sub(r"\s+", "", match.group(1))
        target = re.sub(r"\s+", "", match.group(2))
        parts = [value.strip('"') for value in source.split(".")]
        schema, name = ((parts[0] if len(parts) > 1 else "CURRENT_SCHEMA"), parts[-1])
        target_parts = [value.strip('"') for value in target.split(".")]
        target_ref = _normalize_ref((target_parts[0] if len(target_parts) > 1 else schema), target_parts[-1])
        definition = _relation_definition(schema=schema, name=name, columns=(), provider_ref=self.provider_ref)
        return CatalogRelation(
            relation_ref=_normalize_ref(schema, name),
            relation_kind=RelationKind.SYNONYM,
            definition=definition,
            synonym_target_ref=target_ref,
            evidence_refs=(evidence,),
        )


class Db2CatalogProvider:
    """Live Db2 catalog adapter.

    `ibm_db` is imported only when `load()` is called. The adapter produces a
    canonical snapshot that can be reused offline by all downstream services.
    """

    def __init__(
        self,
        *,
        connection_string: str,
        platform: str,
        schemas: Iterable[str],
        provider_ref: str = "db2-live-catalog",
    ) -> None:
        self.connection_string = connection_string
        self.platform = platform.upper()
        self.schemas = tuple(sorted({value.upper() for value in schemas}))
        self.provider_ref = provider_ref

    def _module(self):
        try:
            return importlib.import_module("ibm_db")
        except ModuleNotFoundError as exc:
            raise CatalogProviderError(
                "CATALOG_EXTRA_REQUIRED: install atlas-procedure-intelligence[catalog]."
            ) from exc

    def _rows(self, ibm_db, connection, sql: str) -> list[dict[str, Any]]:
        statement = ibm_db.exec_immediate(connection, sql)
        values: list[dict[str, Any]] = []
        row = ibm_db.fetch_assoc(statement)
        while row:
            values.append({str(key).upper(): value for key, value in row.items()})
            row = ibm_db.fetch_assoc(statement)
        return values

    def load(self) -> CatalogSnapshot:
        if not self.schemas:
            raise CatalogProviderError("At least one schema is required for live catalog capture.")
        ibm_db = self._module()
        connection = ibm_db.connect(self.connection_string, "", "")
        try:
            if self.platform == "DB2_LUW":
                relations = self._load_luw(ibm_db, connection)
            elif self.platform == "DB2_ZOS":
                relations = self._load_zos(ibm_db, connection)
            else:
                raise CatalogProviderError(f"Unsupported Db2 platform: {self.platform}")
        finally:
            ibm_db.close(connection)
        payload = {
            "schema_version": "catalog-snapshot-1.0",
            "snapshot_id": f"catalog-live-{hashlib.sha256((self.platform+'|'+','.join(self.schemas)).encode()).hexdigest()[:16]}",
            "platform": self.platform,
            "provider_ref": self.provider_ref,
            "source_kind": (CatalogSourceKind.DB2_LUW_CATALOG if self.platform == "DB2_LUW" else CatalogSourceKind.DB2_ZOS_CATALOG),
            "captured_at": _now(),
            "schema_refs": self.schemas,
            "relations": tuple(relations),
            "unresolved_refs": (),
            "limitations": (),
        }
        return CatalogSnapshot(**payload, content_digest=canonical_digest(payload))

    def _schema_list(self) -> str:
        return ",".join("'" + value.replace("'", "''") + "'" for value in self.schemas)

    def _load_luw(self, ibm_db, connection) -> list[CatalogRelation]:
        schemas = self._schema_list()
        table_rows = self._rows(ibm_db, connection, f"SELECT TABSCHEMA, TABNAME, TYPE, TBSPACE FROM SYSCAT.TABLES WHERE TABSCHEMA IN ({schemas})")
        column_rows = self._rows(ibm_db, connection, f"SELECT TABSCHEMA, TABNAME, COLNAME, TYPENAME, LENGTH, SCALE, NULLS, DEFAULT, GENERATED, IDENTITY, CODEPAGE FROM SYSCAT.COLUMNS WHERE TABSCHEMA IN ({schemas}) ORDER BY TABSCHEMA, TABNAME, COLNO")
        view_rows = self._rows(ibm_db, connection, f"SELECT VIEWSCHEMA, VIEWNAME, TEXT FROM SYSCAT.VIEWS WHERE VIEWSCHEMA IN ({schemas})")
        synonym_rows = self._rows(ibm_db, connection, f"SELECT TABSCHEMA, TABNAME, BASE_TABSCHEMA, BASE_TABNAME FROM SYSCAT.TABLES WHERE TABSCHEMA IN ({schemas}) AND TYPE='A'")
        key_rows = self._rows(ibm_db, connection, f"SELECT K.TABSCHEMA,K.TABNAME,K.CONSTNAME,K.COLNAME,K.COLSEQ,C.TYPE FROM SYSCAT.KEYCOLUSE K JOIN SYSCAT.TABCONST C ON C.TABSCHEMA=K.TABSCHEMA AND C.TABNAME=K.TABNAME AND C.CONSTNAME=K.CONSTNAME WHERE K.TABSCHEMA IN ({schemas}) ORDER BY K.TABSCHEMA,K.TABNAME,K.CONSTNAME,K.COLSEQ")
        fk_rows = self._rows(ibm_db, connection, f"SELECT R.TABSCHEMA,R.TABNAME,R.CONSTNAME,R.REFTABSCHEMA,R.REFTABNAME,K.COLNAME,K.COLSEQ,RK.COLNAME AS REFCOLNAME FROM SYSCAT.REFERENCES R JOIN SYSCAT.KEYCOLUSE K ON K.TABSCHEMA=R.TABSCHEMA AND K.TABNAME=R.TABNAME AND K.CONSTNAME=R.CONSTNAME JOIN SYSCAT.KEYCOLUSE RK ON RK.TABSCHEMA=R.REFTABSCHEMA AND RK.TABNAME=R.REFTABNAME AND RK.CONSTNAME=R.REFKEYNAME AND RK.COLSEQ=K.COLSEQ WHERE R.TABSCHEMA IN ({schemas}) ORDER BY R.TABSCHEMA,R.TABNAME,R.CONSTNAME,K.COLSEQ")
        return self._assemble(table_rows, column_rows, view_rows, synonym_rows, key_rows, fk_rows, source="SYSCAT")

    def _load_zos(self, ibm_db, connection) -> list[CatalogRelation]:
        schemas = self._schema_list()
        table_rows = self._rows(ibm_db, connection, f"SELECT CREATOR AS TABSCHEMA, NAME AS TABNAME, TYPE, DBNAME AS TBSPACE FROM SYSIBM.SYSTABLES WHERE CREATOR IN ({schemas})")
        column_rows = self._rows(ibm_db, connection, f"SELECT TBCREATOR AS TABSCHEMA, TBNAME AS TABNAME, NAME AS COLNAME, COLTYPE AS TYPENAME, LENGTH, SCALE, NULLS, DEFAULT, DEFAULTVALUE AS GENERATED, '' AS IDENTITY, SBCS_CCSID AS CODEPAGE FROM SYSIBM.SYSCOLUMNS WHERE TBCREATOR IN ({schemas}) ORDER BY TBCREATOR,TBNAME,COLNO")
        view_rows = self._rows(ibm_db, connection, f"SELECT CREATOR AS VIEWSCHEMA, NAME AS VIEWNAME, TEXT FROM SYSIBM.SYSVIEWS WHERE CREATOR IN ({schemas})")
        synonym_rows = self._rows(ibm_db, connection, f"SELECT CREATOR AS TABSCHEMA, NAME AS TABNAME, TBCREATOR AS BASE_TABSCHEMA, TBNAME AS BASE_TABNAME FROM SYSIBM.SYSSYNONYMS WHERE CREATOR IN ({schemas})")
        key_rows = self._rows(
            ibm_db,
            connection,
            f"SELECT K.TBCREATOR AS TABSCHEMA,K.TBNAME AS TABNAME,K.CONSTNAME,K.COLNAME,K.COLSEQ,C.TYPE "
            f"FROM SYSIBM.SYSKEYCOLUSE K JOIN SYSIBM.SYSTABCONST C "
            f"ON C.TBCREATOR=K.TBCREATOR AND C.TBNAME=K.TBNAME AND C.CONSTNAME=K.CONSTNAME "
            f"WHERE K.TBCREATOR IN ({schemas}) AND C.TYPE IN ('P','U') "
            f"ORDER BY K.TBCREATOR,K.TBNAME,K.CONSTNAME,K.COLSEQ",
        )
        fk_rows = self._rows(
            ibm_db,
            connection,
            f"SELECT R.CREATOR AS TABSCHEMA,R.TBNAME AS TABNAME,R.RELNAME AS CONSTNAME,"
            f"R.REFTBCREATOR AS REFTABSCHEMA,R.REFTBNAME AS REFTABNAME,"
            f"F.COLNAME,F.COLSEQ,R.IXOWNER,R.IXNAME "
            f"FROM SYSIBM.SYSRELS R JOIN SYSIBM.SYSFOREIGNKEYS F "
            f"ON F.CREATOR=R.CREATOR AND F.TBNAME=R.TBNAME AND F.RELNAME=R.RELNAME "
            f"WHERE R.CREATOR IN ({schemas}) "
            f"ORDER BY R.CREATOR,R.TBNAME,R.RELNAME,F.COLSEQ",
        )
        index_rows = self._rows(
            ibm_db,
            connection,
            f"SELECT IXCREATOR,IXNAME,COLNAME,COLSEQ FROM SYSIBM.SYSKEYS "
            f"WHERE IXCREATOR IN ({schemas}) ORDER BY IXCREATOR,IXNAME,COLSEQ",
        )
        self._attach_zos_referenced_columns(fk_rows, key_rows, index_rows)
        return self._assemble(table_rows, column_rows, view_rows, synonym_rows, key_rows, fk_rows, source="SYSIBM")

    @staticmethod
    def _attach_zos_referenced_columns(
        fk_rows: list[dict[str, Any]],
        key_rows: list[dict[str, Any]],
        index_rows: list[dict[str, Any]],
    ) -> None:
        primary_columns: dict[tuple[str, str, int], str] = {}
        for row in key_rows:
            if str(row.get("TYPE", "")).strip().upper() != "P":
                continue
            key = (
                str(row.get("TABSCHEMA", "")).strip().upper(),
                str(row.get("TABNAME", "")).strip().upper(),
                int(row.get("COLSEQ") or 0),
            )
            primary_columns[key] = str(row.get("COLNAME", "")).strip().upper()
        index_columns: dict[tuple[str, str, int], str] = {}
        for row in index_rows:
            key = (
                str(row.get("IXCREATOR", "")).strip().upper(),
                str(row.get("IXNAME", "")).strip().upper(),
                int(row.get("COLSEQ") or 0),
            )
            index_columns[key] = str(row.get("COLNAME", "")).strip().upper()
        for row in fk_rows:
            sequence = int(row.get("COLSEQ") or 0)
            index_name = str(row.get("IXNAME") or "").strip().upper()
            if index_name:
                ref_column = index_columns.get((
                    str(row.get("IXOWNER") or row.get("REFTABSCHEMA") or "").strip().upper(),
                    index_name,
                    sequence,
                ))
            else:
                ref_column = primary_columns.get((
                    str(row.get("REFTABSCHEMA") or "").strip().upper(),
                    str(row.get("REFTABNAME") or "").strip().upper(),
                    sequence,
                ))
            row["REFCOLNAME"] = ref_column or ""

    def _assemble(
        self,
        table_rows: list[dict[str, Any]],
        column_rows: list[dict[str, Any]],
        view_rows: list[dict[str, Any]],
        synonym_rows: list[dict[str, Any]],
        key_rows: list[dict[str, Any]],
        fk_rows: list[dict[str, Any]],
        *,
        source: str,
    ) -> list[CatalogRelation]:
        columns_by: dict[tuple[str, str], list[ColumnDefinition]] = defaultdict(list)
        for row in column_rows:
            schema, name = str(row["TABSCHEMA"]).strip(), str(row["TABNAME"]).strip()
            nullable = str(row.get("NULLS", "Y")).strip().upper() != "N"
            type_name = str(row.get("TYPENAME") or "UNKNOWN").strip()
            sql_type = _canonical_type(
                type_name,
                length=int(row["LENGTH"]) if row.get("LENGTH") is not None else None,
                precision=int(row["LENGTH"]) if _family(type_name) is SqlTypeFamily.DECIMAL and row.get("LENGTH") is not None else None,
                scale=int(row["SCALE"]) if row.get("SCALE") is not None else None,
                nullable=nullable,
                source_ref=f"{source}.COLUMNS:{schema}.{name}.{row.get('COLNAME')}",
            )
            columns_by[(schema.upper(), name.upper())].append(ColumnDefinition(
                relation_name=name.upper(),
                column_name=str(row.get("COLNAME")).strip().upper(),
                sql_type=sql_type,
                nullable=nullable,
                default_expression=(str(row.get("DEFAULT")) if row.get("DEFAULT") is not None else None),
                generated=str(row.get("GENERATED", "")).strip().upper() not in {"", "N", "NEVER"},
                identity_column=str(row.get("IDENTITY", "")).strip().upper() in {"Y", "YES"},
                source_refs=(f"{source}.COLUMNS:{schema}.{name}",),
            ))
        primary_by: dict[tuple[str, str], list[str]] = defaultdict(list)
        unique_by: dict[tuple[str, str, str], list[str]] = defaultdict(list)
        for row in key_rows:
            key = (str(row["TABSCHEMA"]).strip().upper(), str(row["TABNAME"]).strip().upper())
            ctype = str(row.get("TYPE", "")).strip().upper()
            if ctype == "P":
                primary_by[key].append(str(row["COLNAME"]).strip().upper())
            elif ctype == "U":
                unique_by[(key[0], key[1], str(row.get("CONSTNAME", "")).strip().upper())].append(str(row["COLNAME"]).strip().upper())
        fk_by: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in fk_rows:
            key = (str(row["TABSCHEMA"]).strip().upper(), str(row["TABNAME"]).strip().upper(), str(row.get("CONSTNAME", "")).strip().upper())
            fk_by[key].append(row)
        views = {(str(row["VIEWSCHEMA"]).strip().upper(), str(row["VIEWNAME"]).strip().upper()): str(row.get("TEXT") or "").strip() for row in view_rows}
        synonyms = {(str(row["TABSCHEMA"]).strip().upper(), str(row["TABNAME"]).strip().upper()): _normalize_ref(str(row.get("BASE_TABSCHEMA") or "").strip(), str(row.get("BASE_TABNAME") or "").strip()) for row in synonym_rows}
        relations: list[CatalogRelation] = []
        for row in table_rows:
            schema, name = str(row["TABSCHEMA"]).strip().upper(), str(row["TABNAME"]).strip().upper()
            key = (schema, name)
            type_code = str(row.get("TYPE", "T")).strip().upper()
            kind = RelationKind.TABLE
            view_text = views.get(key)
            synonym_target = synonyms.get(key)
            if view_text is not None or type_code in {"V"}:
                kind = RelationKind.VIEW
            elif synonym_target or type_code in {"A", "S"}:
                kind = RelationKind.SYNONYM
            elif type_code in {"N"}:
                kind = RelationKind.NICKNAME
            elif type_code in {"S", "M"} and "QUERY" in str(row.get("TBSPACE", "")).upper():
                kind = RelationKind.MATERIALIZED_QUERY_TABLE
            fks: list[ForeignKeyDefinition] = []
            for (fs, fn, constraint), values in fk_by.items():
                if (fs, fn) != key:
                    continue
                fks.append(ForeignKeyDefinition(
                    constraint_name=constraint or None,
                    local_columns=tuple(str(v["COLNAME"]).strip().upper() for v in values),
                    referenced_schema=str(values[0].get("REFTABSCHEMA") or schema).strip().upper(),
                    referenced_relation=str(values[0].get("REFTABNAME") or "").strip().upper(),
                    referenced_columns=tuple(str(v.get("REFCOLNAME") or "").strip().upper() for v in values),
                    source_refs=(f"{source}.REFERENCES:{schema}.{name}.{constraint}",),
                ))
            definition = _relation_definition(
                schema=schema,
                name=name,
                columns=columns_by.get(key, ()),
                provider_ref=self.provider_ref,
                primary_key=primary_by.get(key, ()),
                unique_constraints=[values for (us, un, _), values in unique_by.items() if (us, un) == key],
                foreign_keys=fks,
            )
            status = "RESOLVED_METADATA"
            if kind in {RelationKind.VIEW, RelationKind.MATERIALIZED_QUERY_TABLE} and not view_text:
                status = "CATALOG_ONLY"
            relations.append(CatalogRelation(
                relation_ref=_normalize_ref(schema, name),
                relation_kind=kind,
                definition=definition,
                view_definition_text=view_text or None,
                synonym_target_ref=synonym_target,
                remote_source_ref=(str(row.get("TBSPACE")) if kind is RelationKind.NICKNAME and row.get("TBSPACE") else None),
                resolution_status=status,
                evidence_refs=(f"{source}.TABLES:{schema}.{name}",),
            ))
        # Some views/synonyms are not represented in the table query on every platform.
        existing = {item.relation_ref for item in relations}
        for key, text in views.items():
            ref = _normalize_ref(*key)
            if ref in existing:
                continue
            definition = _relation_definition(schema=key[0], name=key[1], columns=columns_by.get(key, ()), provider_ref=self.provider_ref)
            relations.append(CatalogRelation(relation_ref=ref, relation_kind=RelationKind.VIEW, definition=definition, view_definition_text=text, evidence_refs=(f"{source}.VIEWS:{ref}",)))
        for key, target in synonyms.items():
            ref = _normalize_ref(*key)
            if ref in existing:
                continue
            definition = _relation_definition(schema=key[0], name=key[1], columns=columns_by.get(key, ()), provider_ref=self.provider_ref)
            relations.append(CatalogRelation(relation_ref=ref, relation_kind=RelationKind.SYNONYM, definition=definition, synonym_target_ref=target, evidence_refs=(f"{source}.SYNONYMS:{ref}",)))
        return sorted(relations, key=lambda item: item.relation_ref)
