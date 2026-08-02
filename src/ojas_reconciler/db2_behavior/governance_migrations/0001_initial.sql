PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS governance_schema_migrations (
    migration_id TEXT PRIMARY KEY,
    migration_digest TEXT NOT NULL,
    previous_migration_digest TEXT,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS governance_artifacts (
    artifact_id TEXT PRIMARY KEY,
    artifact_type TEXT NOT NULL,
    artifact_ref TEXT NOT NULL,
    content_digest TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    behavior_id TEXT,
    source_symbol_id TEXT,
    symbol_lineage_id TEXT,
    artifact_revision_id TEXT,
    parent_artifact_id TEXT REFERENCES governance_artifacts(artifact_id),
    invalidates_machine_attestation INTEGER NOT NULL DEFAULT 0 CHECK (invalidates_machine_attestation IN (0, 1)),
    platform_governance_ref TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (artifact_type, artifact_ref, content_digest)
);

CREATE INDEX IF NOT EXISTS idx_governance_artifacts_behavior
    ON governance_artifacts(behavior_id, artifact_type);

CREATE TABLE IF NOT EXISTS governance_baselines (
    registration_id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES governance_artifacts(artifact_id),
    behavior_id TEXT NOT NULL,
    authority_ref TEXT NOT NULL,
    effective_from TEXT NOT NULL,
    effective_to TEXT,
    content_digest TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_governance_baselines_behavior
    ON governance_baselines(behavior_id, effective_from, effective_to);

CREATE TABLE IF NOT EXISTS governance_comparisons (
    comparison_id TEXT PRIMARY KEY,
    candidate_artifact_id TEXT NOT NULL REFERENCES governance_artifacts(artifact_id),
    baseline_artifact_id TEXT REFERENCES governance_artifacts(artifact_id),
    behavior_id TEXT NOT NULL,
    status TEXT NOT NULL,
    candidate_signature_digest TEXT NOT NULL,
    baseline_signature_digest TEXT,
    classification_candidate TEXT,
    evidence_refs_json TEXT NOT NULL,
    compared_at TEXT NOT NULL,
    content_digest TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS governance_amendments (
    amendment_id TEXT PRIMARY KEY,
    original_artifact_id TEXT NOT NULL REFERENCES governance_artifacts(artifact_id),
    amended_artifact_id TEXT NOT NULL REFERENCES governance_artifacts(artifact_id),
    editor_ref TEXT NOT NULL,
    reason TEXT NOT NULL,
    invalidates_machine_attestation INTEGER NOT NULL CHECK (invalidates_machine_attestation = 1),
    amended_at TEXT NOT NULL,
    content_digest TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS governance_platform_decisions (
    binding_id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES governance_artifacts(artifact_id),
    artifact_digest TEXT NOT NULL,
    platform_decision_ref TEXT NOT NULL,
    decision_type TEXT NOT NULL,
    authority_ref TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL,
    content_digest TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS governance_certifications (
    certification_binding_id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL REFERENCES governance_artifacts(artifact_id),
    artifact_digest TEXT NOT NULL,
    certification_ref TEXT NOT NULL,
    certification_type TEXT NOT NULL,
    authority_ref TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT,
    evidence_refs_json TEXT NOT NULL,
    content_digest TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS governance_audit_events (
    event_id TEXT PRIMARY KEY,
    sequence INTEGER NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    actor_ref TEXT NOT NULL,
    event_at TEXT NOT NULL,
    payload_digest TEXT NOT NULL,
    previous_event_digest TEXT,
    content_digest TEXT NOT NULL
);
