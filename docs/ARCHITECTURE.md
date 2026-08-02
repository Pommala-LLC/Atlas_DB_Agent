# Atlas architecture freeze

Atlas is the canonical application identity from `2.0.0rc1`.

## Design principles

- **Modular:** database-neutral semantic contracts live in `atlas.core`; dialect syntax lives only in `atlas.dialects`.
- **Reusable:** analysis, renderers and graph outputs consume immutable `RoutineIR` artifacts rather than parser internals.
- **Loose coupling:** application services depend on dialect and renderer protocols; web and CLI are adapters.
- **High cohesion:** each module owns one capability boundary.
- **Maintainable:** legacy Ojas/Db2 namespaces remain compatibility shims until 3.0 and are not used by new Atlas semantics.

## Modules

```text
atlas.core          immutable database-neutral IR and canonical digests
atlas.dialects      Db2, Oracle, SQL Server, PostgreSQL and MySQL adapters
atlas.application   semantic orchestration and scenario compilation
atlas.renderers     Gherkin and graph projections
atlas.web           Atlas UI/API adapter
```

## Semantic coverage

Each admitted dialect maps routine headers, declarations, assignments, branches, loops, exception handlers, cursors, calls, dynamic SQL, queries, DML, transactions, result sets and returns into the common IR. No statement is discarded: unclassified syntax is represented by an explicit `OPAQUE` node and a finding.

## Procedure analysis feature

`atlas.application.AtlasSourceSegmenter` and `AtlasSourceUnitService` are the
single discovery path for UI, CLI and pipeline entry points. The canonical web
feature is `atlas.web.procedure`; the legacy commercial UI import is a
compatibility facade. See `WEB_MIGRATION.md`.
