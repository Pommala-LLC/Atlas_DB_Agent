# Atlas naming compatibility policy

Atlas is the canonical product identity from 2.0.0rc4. The canonical distribution is `atlas-procedure-intelligence`, the canonical Python namespace is `atlas`, and the primary commands are `atlas` and `atlas-console`.

`ojas_reconciler.db2_behavior` is a compatibility facade, not a second canonical product namespace. No new public APIs are added to that namespace. Existing imports and the historical CLI aliases remain supported through Atlas 3.0.0, subject to an explicit governed removal decision and published migration notice.

Historical artifacts are immutable evidence. Atlas reads both canonical and historical producer identities, tries the original identity before a registered alias, and verifies digests over the original serialized content. It never changes a historical schema ID, artifact ID, producer path, or content digest merely to adopt the Atlas name. New artifacts are written with Atlas producer identity.

The machine-readable authority is `ATLAS_NAMING_COMPATIBILITY_POLICY.json`. `ATLAS_NAMING_MIGRATION.json` remains the concise migration summary.
