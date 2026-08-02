# Atlas dialect packages — 2.0.0rc5

## Boundary

`atlas.core` remains database-neutral. Vendor grammar recognition, routine characteristics, semantic enrichment, normalization rules and static validity findings are owned by one of five packages:

```text
atlas.dialects.db2
atlas.dialects.oracle
atlas.dialects.sqlserver
atlas.dialects.postgresql
atlas.dialects.mysql
```

Each package exports `PROFILE`, `NORMALIZER`, `CAPABILITIES`, a statement classifier, a semantic policy and an adapter. `AtlasDialectRegistry` composes those adapters. `UniversalProceduralAdapter` performs only common statement scanning, source-span preservation, structured-region tracking, CFG refinement, opaque retention and immutable IR assembly. Package-owned normalizers are invoked at every identifier/type extraction boundary.

## Package contract

| Module | Responsibility |
|---|---|
| `profile.py` | Discover procedures, functions, triggers/package routines; parse parameters; extract routine characteristics. |
| `classifier.py` | Recognize vendor statements before the common fallback classifier. |
| `semantics.py` | Add vendor execution semantics and deterministic invalid-construct findings. |
| `normalization.py` | Produce stable identifier/type comparison keys while retaining raw evidence text. |
| `capabilities.py` | Publish implemented construct families and explicit evidence boundaries. |
| `adapter.py` | Inject the package-owned classifier and policy into the shared IR builder. |

## Implemented vendor surfaces

### Db2 SQL PL

Labeled `BEGIN ATOMIC`/`BEGIN NOT ATOMIC` bodies, compound-statement handlers, `CONTINUE`/`EXIT`/`UNDO`, enclosing-scope ATOMIC constraints, `VALUES INTO`, dynamic SQL, cursors including `WITH HOLD`/`WITH RETURN`, result-set locators, diagnostics, savepoints, units of work, MERGE and sequence references.

### Oracle PL/SQL

Standalone and package routines, triggers, declarations and exception sections, `AUTHID`, autonomous transactions, dynamic SQL, `RAISE`/`RAISE_APPLICATION_ERROR`, `FORALL`, `BULK COLLECT`, cursor attributes, `RETURNING INTO`, ref cursors, pipelined results and trigger transaction restrictions.

### Microsoft SQL Server T-SQL

Procedures/functions/triggers, `EXECUTE AS`, `TRY/CATCH`, `THROW`/`RAISERROR`, transactions and registers, isolation/session settings, `EXEC`/`sp_executesql` batch scope, `OUTPUT`, temp tables, table variables, labels/GOTO and statically decidable UDF restrictions.

### PostgreSQL PL/pgSQL

Procedures/functions/trigger functions, unnamed and `VARIADIC` arguments, flexible `AS`/`LANGUAGE` option order, declarations, exception subtransactions, `FOUND`, strict/non-strict `SELECT INTO`, `EXECUTE ... USING/INTO`, assertions, diagnostics, `RETURN QUERY`, `RETURN NEXT`, ref cursors, volatility/security/parallel characteristics and transaction-control context findings.

### MySQL stored programs

Procedures/functions/triggers including legal single-statement bodies, SQL security/data-access characteristics, block-scoped declaration ordering, named conditions, handlers, diagnostics, asensitive read-only nonscrollable nonholdable cursors, prepared statements, `ON DUPLICATE KEY UPDATE`, explicit transaction restrictions and scalar-function result restrictions.

## Evidence rule

Unknown extensions are not dropped and are not inferred. They remain `OPAQUE` nodes with source spans and findings. Catalog-dependent resolution, runtime dynamic identifier values and external effects remain explicit evidence boundaries.
