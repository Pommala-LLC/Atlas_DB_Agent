# Atlas dialect semantic contract

The machine-readable contract is `ATLAS_DIALECT_COVERAGE.json`.

`DIALECT_BOUNDED_SEMANTICS` means:

1. Atlas discovers the admitted routine body and preserves every logical statement in immutable IR.
2. Dialect-owned grammar boundaries parse supported signatures, body forms, identifiers and types without collapsing quoted identity.
3. Atlas constructs terminator-aware branches, joins, loops, labels/GOTO, handler paths, calls and bounded data-dependency evidence.
4. Common and vendor-specific admitted constructs receive semantic attributes and deterministic validity findings.
5. Unsupported extensions remain explicit `OPAQUE` nodes with source spans and findings, which makes the report `PARTIAL`.
6. Runtime state, external implementation behavior, catalog-dependent resolution, dynamic identifiers and vendor extensions outside the admitted grammar remain evidence boundaries.

The status does not claim complete vendor-language coverage or runtime equivalence. A construct is authoritative only within its package-declared capability and evidence boundary.

## Modularity rules

- The core model cannot import a vendor parser.
- A dialect package owns routine discovery, signature parsing, classification, normalization, validity checks and semantic enrichment.
- The shared adapter orchestrates scanning and immutable IR assembly; it does not own vendor policy.
- Application services consume the dialect protocol and immutable IR.
- Renderers consume IR and reports, not parser internals.
- UI and CLI are adapters and cannot create semantic facts.
