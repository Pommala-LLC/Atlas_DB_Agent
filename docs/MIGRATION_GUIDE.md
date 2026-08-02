# Atlas naming and compatibility migration

## Canonical identities from 2.0.0rc1

| Surface | Canonical identity |
|---|---|
| Product | Atlas |
| Distribution | `atlas-procedure-intelligence` |
| Python namespace | `atlas` |
| CLI | `atlas` |
| UI CLI | `atlas-console` |

## Compatibility policy

The following remain functional but deprecated until Atlas 3.0.0:

- distribution references to `db2-behavior-extraction-framework`;
- imports under `ojas_reconciler.db2_behavior`;
- `db2-behavior`, `ojas-db2-agent`, `ojas-db2-gate0` and `commercial-behavior-console` commands;
- historical Ojas/Db2 environment-variable names where Atlas replacements exist.

## Evidence invariants

Migration never:

- changes a historical schema ID;
- renames an existing artifact ID;
- recomputes an existing content digest merely because the product name changed;
- rewrites governance or baseline records;
- upgrades the authority of an existing artifact.

New artifacts use Atlas producer identity. Consumers should accept both Atlas and historical identities during the compatibility period.

## Application migration

New integrations should import from `atlas`, use `atlas analyze` or `atlas analyze-unit`, and store new reports under an Atlas-specific workspace. Existing Db2 workflows can move incrementally; no forced one-time evidence migration is required.
