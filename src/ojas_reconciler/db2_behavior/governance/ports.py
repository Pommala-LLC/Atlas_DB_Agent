from __future__ import annotations

from typing import Protocol

from ojas_reconciler.db2_behavior.governance.models import CertificationEnvelope, PlatformDecisionEnvelope, StoredArtifactRecord


class PlatformGovernancePort(Protocol):
    """Connector boundary owned by the external governance platform.

    The DB2 behavior lane persists and validates envelopes but does not invent the
    remote platform's workflow, decision taxonomy, or transport.
    """

    def publish_candidate(self, *, artifact: StoredArtifactRecord, payload: bytes) -> str:
        """Publish an admitted artifact and return the external submission reference."""
        ...

    def fetch_decision(self, *, platform_decision_ref: str) -> PlatformDecisionEnvelope:
        """Retrieve a digest-bound platform decision envelope."""
        ...

    def fetch_certification(self, *, certification_ref: str) -> CertificationEnvelope:
        """Retrieve a digest-bound certification envelope."""
        ...
