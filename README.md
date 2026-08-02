# Atlas Procedure Intelligence — 2.0.0rc5

Atlas is a modular, database-neutral application for extracting governed technical behavior from stored procedures, functions, triggers and package routines.

## Supported dialect adapters

- Db2 SQL PL
- Oracle PL/SQL
- Microsoft SQL Server T-SQL
- PostgreSQL PL/pgSQL
- MySQL stored programs

Each adapter maps complete routine bodies into the immutable Atlas IR: routine characteristics, declarations, assignments, decisions, loops, handlers, cursors, calls, dynamic SQL, queries, DML, transactions, result sets, returns, bulk operations, locks and diagnostics. Unsupported vendor extensions are never discarded; they remain explicit `OPAQUE` nodes with source evidence.

## Architecture

```text
atlas.core          database-neutral immutable IR and digests
atlas.dialects      high-cohesion vendor syntax and semantic policies
atlas.application   orchestration and candidate-scenario services
atlas.renderers     Gherkin and graph projections
atlas.web           UI/API adapter
```

Each vendor is now a real package rather than a thin adapter module:

```text
atlas.dialects.db2/
atlas.dialects.oracle/
atlas.dialects.sqlserver/
atlas.dialects.postgresql/
atlas.dialects.mysql/
    profile.py          routine discovery, parameters, routine characteristics
    classifier.py       vendor statement classification
    semantics.py        vendor behavior enrichment and validity findings
    normalization.py    identifier/type comparison keys without rewriting source
    capabilities.py     executable surface and explicit evidence boundaries
    adapter.py          package composition into the shared Atlas IR engine
```

The shared adapter only scans statements, constructs control flow and emits immutable IR. It receives the classifier and semantic policy from the selected dialect package; it contains no vendor-policy registry switch on the execution path.

The application layer depends on dialect and renderer contracts rather than parser implementations. Legacy `ojas_reconciler.db2_behavior` capabilities remain compatibility adapters through Atlas 3.0.0 so existing artifact IDs, schemas, digests and governance records are not rewritten.

## Install

Core analyzer:

```bash
pip install atlas-procedure-intelligence
```

Analyzer and review console:

```bash
pip install "atlas-procedure-intelligence[ui]"
```

Development:

```bash
pip install -e ".[dev]"
```

## Analyze a source file

```bash
atlas analyze procedure.sql \
  --dialect oracle \
  --output reports/oracle-procedure \
  --emit-gherkin \
  --emit-graph
```

Dialect aliases: `db2`, `oracle`, `sqlserver`, `postgresql`, and `mysql`.

Outputs for one routine:

```text
source-unit-analysis.json
routine-ir.json
semantic-report.json
scenario-candidates.json
behavior-candidates.feature
routine-graph.json
```

For multiple routines, the routine artifacts are written below `routines/<routine-ref>/`.
The UI accepts `.sql`, `.db2`, `.ddl`, and `.txt` source files.

## Run the UI

```bash
atlas-console --workspace reports/atlas
```

Windows:

```text
build.bat
ATLAS_CONSOLE.bat
ATLAS_ANALYZE.bat
RUN_UI_E2E.bat
```

## Naming freeze

Atlas is the canonical product, distribution, namespace and CLI from `2.0.0rc1`:

```text
Product:       Atlas
Distribution:  atlas-procedure-intelligence
Namespace:     atlas
CLI:           atlas
UI CLI:        atlas-console
```

Legacy distribution, namespace and CLI identities remain deprecated-but-functional compatibility surfaces through 3.0.0. Existing evidence is not renamed or rehashed. See `ATLAS_NAMING_MIGRATION.json`, `ATLAS_DIALECT_COVERAGE.json`, and `docs/atlas/MIGRATION_GUIDE.md`.

## Evidence boundary

Atlas produces non-authoritative technical evidence and candidate scenarios. Public third-party repositories may be admitted as pinned organic parser evidence without customer-custody fiction, but they do not become customer authority or commercial validation. Atlas does not turn runtime observations into authority and does not silently infer unsupported vendor extensions.

For the Db2 public-source recovery gate, see `docs/DB2_ORGANIC_RECOVERY_RC5.md` and `organic/IBM_DB2_SAMPLES_PUBLIC_MANIFEST.json`.
