"""Property-gated runtime evidence backend selection.

Blank optional references are normalized to ``None``. Missing optional adapter
properties cause a machine-readable SKIPPED outcome; they never trigger a hidden
default connection or site adapter.
"""
from __future__ import annotations

import importlib
import importlib.util
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Mapping

from pydantic import field_validator, model_validator

from ..core.models import CanonicalModel
from ..type_system.models import SqlDialect


class RuntimeEvidencePlatform(StrEnum):
    DB2_LUW = "DB2_LUW"
    DB2_ZOS = "DB2_ZOS"


class RuntimeEvidenceSource(StrEnum):
    LIVE_PROBE = "LIVE_PROBE"
    IFCID_EXTRACT = "IFCID_EXTRACT"


class RuntimeEvidenceAvailability(StrEnum):
    DISABLED = "DISABLED"
    SKIPPED = "SKIPPED"
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"


class Db2RuntimeEvidenceProperties(CanonicalModel):
    """Optional runtime evidence selection; static analysis never depends on it."""

    enabled: bool = False
    dialect: SqlDialect = SqlDialect.DB2_SQL_PL
    platform: RuntimeEvidencePlatform | None = None
    source: RuntimeEvidenceSource | None = None
    availability_attestation_ref: str | None = None
    connection_ref: str | None = None
    ifcid_adapter_ref: str | None = None

    @field_validator(
        "availability_attestation_ref",
        "connection_ref",
        "ifcid_adapter_ref",
        mode="before",
    )
    @classmethod
    def normalize_optional_refs(cls, value: object) -> object:
        if value is None:
            return None
        if isinstance(value, str):
            normalized = value.strip()
            return normalized or None
        return value

    @model_validator(mode="after")
    def validate_platform_source_pair(self) -> "Db2RuntimeEvidenceProperties":
        if not self.enabled or self.platform is None or self.source is None:
            return self
        if self.dialect is not SqlDialect.DB2_SQL_PL:
            raise ValueError("DB2 runtime evidence supports dialect=DB2_SQL_PL only.")
        if self.platform is RuntimeEvidencePlatform.DB2_LUW and self.source is not RuntimeEvidenceSource.LIVE_PROBE:
            raise ValueError("DB2_LUW runtime evidence requires source=LIVE_PROBE.")
        if self.platform is RuntimeEvidencePlatform.DB2_ZOS and self.source is not RuntimeEvidenceSource.IFCID_EXTRACT:
            raise ValueError("DB2_ZOS runtime evidence requires source=IFCID_EXTRACT.")
        return self

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Db2RuntimeEvidenceProperties":
        values = os.environ if env is None else env
        def env(primary: str, legacy: str) -> str | None:
            return values.get(primary) or values.get(legacy)

        enabled = (env("ATLAS_DB2_RUNTIME_EVIDENCE_ENABLED", "OJAS_DB2_RUNTIME_EVIDENCE_ENABLED") or "").strip().lower() in {
            "1", "true", "yes", "on",
        }
        dialect_text = (env("ATLAS_DB2_RUNTIME_EVIDENCE_DIALECT", "OJAS_DB2_RUNTIME_EVIDENCE_DIALECT") or "").strip()
        platform_text = (env("ATLAS_DB2_RUNTIME_EVIDENCE_PLATFORM", "OJAS_DB2_RUNTIME_EVIDENCE_PLATFORM") or "").strip()
        source_text = (env("ATLAS_DB2_RUNTIME_EVIDENCE_SOURCE", "OJAS_DB2_RUNTIME_EVIDENCE_SOURCE") or "").strip()
        return cls(
            enabled=enabled,
            dialect=SqlDialect(dialect_text) if dialect_text else SqlDialect.DB2_SQL_PL,
            platform=RuntimeEvidencePlatform(platform_text) if platform_text else None,
            source=RuntimeEvidenceSource(source_text) if source_text else None,
            availability_attestation_ref=env("ATLAS_DB2_RUNTIME_EVIDENCE_AVAILABILITY_ATTESTATION", "OJAS_DB2_RUNTIME_EVIDENCE_AVAILABILITY_ATTESTATION"),
            connection_ref=env("ATLAS_DB2_RUNTIME_EVIDENCE_CONNECTION_REF", "OJAS_DB2_RUNTIME_EVIDENCE_CONNECTION_REF"),
            ifcid_adapter_ref=env("ATLAS_DB2_RUNTIME_EVIDENCE_IFCID_ADAPTER_REF", "OJAS_DB2_RUNTIME_EVIDENCE_IFCID_ADAPTER_REF"),
        )

    @classmethod
    def from_json_file(cls, path: Path) -> "Db2RuntimeEvidenceProperties":
        return cls.model_validate_json(path.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class RuntimeEvidenceBackend:
    dialect: SqlDialect
    platform: RuntimeEvidencePlatform
    source: RuntimeEvidenceSource
    module_name: str
    implementation_name: str


class RuntimeEvidenceUnavailable(RuntimeError):
    pass


def runtime_evidence_status(
    properties: Db2RuntimeEvidenceProperties,
) -> tuple[RuntimeEvidenceAvailability, tuple[str, ...]]:
    if not properties.enabled:
        return RuntimeEvidenceAvailability.DISABLED, ("DB2 runtime evidence is disabled by property.",)
    if properties.platform is None or properties.source is None:
        return RuntimeEvidenceAvailability.SKIPPED, (
            "RUNTIME_PLATFORM_OR_SOURCE_NOT_PROVIDED",
        )
    if properties.availability_attestation_ref is None:
        return RuntimeEvidenceAvailability.SKIPPED, (
            "AVAILABILITY_ATTESTATION_REF_NOT_PROVIDED",
        )
    if properties.platform is RuntimeEvidencePlatform.DB2_LUW:
        if properties.connection_ref is None:
            return RuntimeEvidenceAvailability.SKIPPED, ("CONNECTION_REF_NOT_PROVIDED",)
        if importlib.util.find_spec("ibm_db") is None:
            return RuntimeEvidenceAvailability.UNAVAILABLE, (
                "DB2_LUW was selected, but the optional ibm_db driver is not installed.",
            )
        return RuntimeEvidenceAvailability.AVAILABLE, (
            "DB2_LUW live evidence is enabled and the declared connection reference is available.",
        )
    if properties.platform is RuntimeEvidencePlatform.DB2_ZOS:
        if properties.ifcid_adapter_ref is None:
            return RuntimeEvidenceAvailability.SKIPPED, ("IFCID_ADAPTER_REF_NOT_PROVIDED",)
        return RuntimeEvidenceAvailability.AVAILABLE, (
            "DB2_ZOS IFCID evidence is enabled with an attested site adapter; no live driver is loaded.",
        )
    return RuntimeEvidenceAvailability.UNAVAILABLE, ("UNSUPPORTED_DB2_RUNTIME_PLATFORM",)


def load_runtime_evidence_backend(
    properties: Db2RuntimeEvidenceProperties,
) -> RuntimeEvidenceBackend | None:
    """Lazily import only the explicitly selected DB2 adapter."""

    availability, reasons = runtime_evidence_status(properties)
    if availability in {RuntimeEvidenceAvailability.DISABLED, RuntimeEvidenceAvailability.SKIPPED}:
        return None
    if availability is not RuntimeEvidenceAvailability.AVAILABLE:
        raise RuntimeEvidenceUnavailable(" ".join(reasons))
    if properties.platform is RuntimeEvidencePlatform.DB2_LUW:
        module_name = "ojas_reconciler.db2_behavior.runtime.adapters.db2_luw"
        implementation_name = "Db2LuwProbe"
    elif properties.platform is RuntimeEvidencePlatform.DB2_ZOS:
        module_name = "ojas_reconciler.db2_behavior.runtime.adapters.db2_zos_ifcid"
        implementation_name = "IfcidObservationDeriver"
    else:
        raise RuntimeEvidenceUnavailable("Unsupported DB2 runtime evidence platform.")
    importlib.import_module(module_name)
    return RuntimeEvidenceBackend(
        dialect=properties.dialect,
        platform=properties.platform,
        source=properties.source,  # type: ignore[arg-type]
        module_name=module_name,
        implementation_name=implementation_name,
    )


__all__ = [
    "Db2RuntimeEvidenceProperties",
    "RuntimeEvidenceAvailability",
    "RuntimeEvidenceBackend",
    "RuntimeEvidencePlatform",
    "RuntimeEvidenceSource",
    "RuntimeEvidenceUnavailable",
    "load_runtime_evidence_backend",
    "runtime_evidence_status",
]
