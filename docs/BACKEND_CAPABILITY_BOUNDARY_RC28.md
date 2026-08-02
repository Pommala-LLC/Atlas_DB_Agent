# RC28 backend capability boundary

RC28 completes the bounded in-repository backend services behind the procedure review workbench. It does not claim infrastructure, customer authority, or dialect semantics that were not exercised.

## Implemented services

### Db2 catalog and lineage

- DDL and JSON catalog ingestion.
- Optional live Db2 LUW and Db2 for z/OS catalog adapters.
- Tables, columns, primary and unique keys, foreign-key mappings, views, aliases/synonyms, and relation kinds.
- Recursive view and synonym traversal with cycle, depth, remote-source, and unavailable-definition boundaries.
- Canonical, digest-bound catalog and lineage artifacts.

Live catalog capture requires the `catalog` extra, authorized credentials, catalog privileges, and a customer environment. The release tests use mocked catalog responses rather than claiming a live Db2 result.

### Relational fixtures

- Executable setup and teardown SQL for an admitted base-table subset.
- Parent-before-child setup and reverse cleanup order.
- Identity/generated/default omission.
- Cleanup-key enforcement.
- Customer-approved value inputs.
- Explicit blocking for cycles, unsupported types, unresolved keys, views, and unacknowledged checks.

The compiler does not claim universal fixture generation. Trigger, temporal, row-security, external-effect, and customer data-policy closure require additional authoritative metadata.

### Composition

- Direct SQL `CALL` discovery from source artifacts.
- Callee and parameter mapping when target source is supplied.
- Digest-bound, non-authoritative composition candidates.
- Existing customer-approved composition-contract validation and stale-digest detection.

External sequencing, event-driven orchestration, application transactions, and implicit business precondition/postcondition proofs still require customer contracts.

### Decision evaluation

- Decision models are built from extracted predicates, behavior slices, bundles, effects, and semantic digests.
- Evaluation accepts explicit `TRUE`, `FALSE`, or `UNKNOWN` values for extracted predicate IDs.
- FIRST-match precedence is applied to the extracted model.
- Partial or unknown evidence returns `INCONCLUSIVE` rather than guessing.

This is a technical model evaluator. It does not reimplement business logic in JavaScript, accept ungoverned raw business inputs, or create a DMN authority artifact.

### Runtime reconciliation

- Verification-plan batches can be reconciled with scripted, imported, watcher-derived, IFCID-derived, or adapter-produced execution records.
- Results remain `MATCHED`, `MISMATCH`, or `INCONCLUSIVE` according to the runtime verifier.
- Mismatches generate typed `STATIC_RUNTIME_CONTRADICTION_CANDIDATE` artifacts with `RUNTIME_EVIDENCE_ONLY` authority.
- Automatic promotion is prohibited by model validation.

Live execution and production watcher capture remain adapter and deployment concerns. No live Db2 execution was performed for RC28.

### Persistent evidence graph

- Tenant-scoped SQLite WAL storage.
- Digest verification on ingestion.
- Node search.
- Bounded graph-neighborhood expansion.
- Source graph identity, authority, status, and attributes retained.

This is an evidence graph store, not a clustered enterprise graph database or proof of complete estate knowledge.

### Enterprise identity

- Fixed local identity for offline development.
- HMAC-signed trusted-header verification.
- OIDC/JWT verification using a pinned public key or JWKS document, issuer, audience, algorithm, tenant claim, and role mappings.
- Role-gated UI/API writes.

Live IdP discovery, user provisioning, group lifecycle, and customer directory administration are external integrations.

### Other database dialects

- Oracle PL/SQL, SQL Server T-SQL, PostgreSQL PL/pgSQL, and MySQL stored-program adapters inventory routine headers, parameters, source digests, and blockers.
- Bodies remain opaque with `FULL_SEMANTIC_PIPELINE_NOT_ADMITTED`.

No non-Db2 behavior, effect, transaction, or BDD claim is emitted.

## Packaging profiles

- Core analyzer dependencies exclude the web stack.
- `[ui]` adds FastAPI, Uvicorn, Jinja2, and multipart handling.
- `[dev]` declares the UI stack and TestClient backend.
- `[catalog]` and `[runtime]` add `ibm_db`.
- `[auth]` adds JWT and cryptographic verification support.
- Missing UI dependencies produce `UI_EXTRA_REQUIRED` instead of a raw import traceback.

The structured pytest plugin is the sole authoritative release-evidence path. Terminal-summary regex parsing is isolated in a deprecated compatibility module.

## External gates that source code cannot self-prove

- Customer-authorized organic-estate validation.
- Native Windows Python 3.14.
- Complete hashed offline wheelhouse installation.
- Live Db2 LUW or z/OS catalog and execution access.
- Customer IdP integration.
- Production watcher completeness and provenance.
- Full semantic adapters for Oracle, SQL Server, PostgreSQL, and MySQL.
- Final product naming, support SLA, metering, and generally available status.
