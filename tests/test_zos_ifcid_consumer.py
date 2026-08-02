from __future__ import annotations

from datetime import datetime, timezone

from ojas_reconciler.db2_behavior.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.runtime_probe import ObservedStatement, StatementIdentity
from ojas_reconciler.db2_behavior.zos_ifcid_consumer import (
    IfcidCorrelationKey,
    IfcidId,
    IfcidInvocationWindow,
    IfcidObservationDeriver,
    IfcidTraceDeclaration,
    NormalizedIfcidRecord,
)


class Source:
    def adapter_ref(self) -> str:
        return "site-adapter-v1"

    def records(self, *, declaration, correlation):
        identity = StatementIdentity(
            collection="COLL",
            package="PKG",
            section=1,
            statement_number=1,
        )
        return (
            NormalizedIfcidRecord(
                ifcid=IfcidId.SQL_STATEMENT_TEXT,
                recorded_at="2026-07-29T00:00:01.000000Z",
                correlation=correlation,
                statement_identity=identity,
                statement_text="UPDATE CLAIM SET STATUS = 'X'",
                statement_kind="STATIC",
            ),
            NormalizedIfcidRecord(
                ifcid=IfcidId.SQL_STATEMENT_END,
                recorded_at="2026-07-29T00:00:02.000000Z",
                correlation=correlation,
                statement_identity=identity,
                statement_kind="STATIC",
                executions=1,
                sqlstate="00000",
            ),
        )


def test_zos_consumer_reuses_shared_observation_schema() -> None:
    from ojas_reconciler.db2_behavior import zos_ifcid_consumer

    assert zos_ifcid_consumer.ObservedStatement is ObservedStatement
    assert zos_ifcid_consumer.StatementIdentity is StatementIdentity


def test_ifcid_extract_derives_one_reconciled_statement() -> None:
    declaration_payload = {
        "declaration_id": "declaration-001",
        "subsystem_id": "DB2A",
        "db2_version": "13",
        "enabled_ifcids": (IfcidId.SQL_STATEMENT_TEXT, IfcidId.SQL_STATEMENT_END),
        "trace_started_at": "2026-07-29T00:00:00.000000Z",
        "trace_stopped_at": "2026-07-29T00:00:03.000000Z",
        "destination": "VENDOR_EXTRACT",
        "records_possibly_lost": False,
        "normalization_adapter_ref": "site-adapter-v1",
        "attestation_ref": "attestation-001",
    }
    declaration = IfcidTraceDeclaration(
        **declaration_payload,
        content_digest=canonical_digest(declaration_payload),
    )
    correlation = IfcidCorrelationKey(luwid="luwid-001")
    window = IfcidInvocationWindow(
        invocation_id="invocation-001",
        procedure_schema="CLAIMS",
        procedure_name="P",
        started_at="2026-07-29T00:00:00.500000Z",
        ended_at="2026-07-29T00:00:02.500000Z",
        correlation=correlation,
    )
    observation = IfcidObservationDeriver().derive(
        declaration=declaration,
        window=window,
        source=Source(),
        plan_ref="plan-001",
        plan_digest="sha256:plan",
        observed_at=datetime(2026, 7, 29, tzinfo=timezone.utc),
    )
    assert observation.platform.value == "DB2_ZOS"
    assert observation.capture_complete is False
    assert len(observation.dynamic_statements) == 1
    statement = observation.dynamic_statements[0]
    assert statement.statement_text == "UPDATE CLAIM SET STATUS = 'X'"
    assert statement.executions == 1
    assert observation.sqlstate == "00000"
