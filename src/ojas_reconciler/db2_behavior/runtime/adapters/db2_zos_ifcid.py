"""z/OS runtime evidence from IFCID trace extracts.

Why this is not a probe.

Db2 for z/OS has no event monitor, no MON_GET_* table functions and no package
cache view. Instrumentation is IFCID records reached through the Instrumentation
Facility Interface, callable only from a program running on the subsystem.
Nothing here connects, executes, or rolls back. This module consumes an offline
extract that someone else produced and turns it into the same
RuntimeObservationRecord the LUW probe emits, so the falsifier is unchanged.

Five properties are enforced rather than noted:

1. Attribution scoping. Only IFCIDs attributable to a single thread contribute
   statements. Subsystem-wide sources (the dynamic statement cache) may be
   declared, are recorded as a gap, and are never consumed — a cache entry is
   not proof that this thread executed it, and feeding one to the falsifier
   manufactures a false DYNAMIC_VARIANT_OUTSIDE_ENUMERATION.

2. Capability gating. A fact is derived only if a declared IFCID can carry it.
   Absence of a record from a trace that was never started is not evidence of
   absence.

3. One key space. Static SQL is identified by package and section, not by text;
   text arrives from different IFCIDs than counts. Records are folded into a
   single key space and reconciled, so one statement can never surface as two
   ObservedStatement entries — a fabricated duplicate is worse than a gap.

4. Absent text is absent, not empty. statement_text is Optional and carries a
   per-statement text_resolution. An empty string is a value and would reach
   the falsifier as one.

5. Loss and coverage awareness. IFCID buffers wrap and traces start late. Both
   taint counts and are recorded; neither is inferred away.

Record layouts are version- and site-specific. This module ships no SMF/GTF
parser: records arrive normalized through IfcidRecordSource, and the mapping
from raw fields is a site adapter, not something to guess.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal, Protocol

from ojas_reconciler.db2_behavior.bdd.models import canonical_timestamp
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.parsing.models import CanonicalModel
from ojas_reconciler.db2_behavior.runtime.adapters.db2_luw import (
    ObservedStatement,
    ProbeError,
    ProbePlatform,
    ProbeRefusal,
    ProbeRefusalCode,
    RuntimeObservationRecord,
    StatementIdentity,
    TextResolution,
)

# ---------------------------------------------------------------------------
# IFCID model
# ---------------------------------------------------------------------------

class AttributionScope(StrEnum):
    """Whether a record from this IFCID can be tied to one invocation."""

    THREAD = "THREAD"
    SUBSYSTEM = "SUBSYSTEM"


class IfcidId(StrEnum):
    STATISTICS = "IFCID_0002"
    ACCOUNTING = "IFCID_0003"
    LOCK_DETAIL = "IFCID_0021"
    SQL_STATEMENT_END = "IFCID_0058"
    SQL_STATEMENT_TEXT = "IFCID_0063"
    DEADLOCK = "IFCID_0172"
    TIMEOUT = "IFCID_0196"
    DYNAMIC_CACHE_STATS = "IFCID_0316"
    DYNAMIC_CACHE_TEXT = "IFCID_0317"
    SQL_STATEMENT_STRING = "IFCID_0350"
    AUDIT_TRAIL = "IFCID_0361"
    STATIC_STATEMENT_STATS = "IFCID_0401"


class ObservationCapability(StrEnum):
    STATEMENT_TEXT = "STATEMENT_TEXT"
    STATEMENT_IDENTITY = "STATEMENT_IDENTITY"
    STATEMENT_EXECUTION_COUNT = "STATEMENT_EXECUTION_COUNT"
    STATEMENT_SQLCODE = "STATEMENT_SQLCODE"
    THREAD_ROLLUP = "THREAD_ROLLUP"
    LOCK_CONTENTION = "LOCK_CONTENTION"
    TABLE_ACCESS_AUDIT = "TABLE_ACCESS_AUDIT"
    #: Declared for completeness. Deliberately grants nothing consumable.
    SUBSYSTEM_WIDE_CACHE_PRESENT = "SUBSYSTEM_WIDE_CACHE_PRESENT"


class IfcidProfile(CanonicalModel):
    capabilities: frozenset[ObservationCapability]
    attribution: AttributionScope


#: What each IFCID grants, at what attribution scope. Conservative by intent:
#: an IFCID absent from this table grants nothing. Verify these assignments
#: against DSNWMSGS for the target Db2 version before use.
IFCID_PROFILES: dict[IfcidId, IfcidProfile] = {
    # --- thread-attributable statement evidence --------------------------
    IfcidId.SQL_STATEMENT_TEXT: IfcidProfile(
        capabilities=frozenset(
            {ObservationCapability.STATEMENT_TEXT, ObservationCapability.STATEMENT_IDENTITY}
        ),
        attribution=AttributionScope.THREAD,
    ),
    IfcidId.SQL_STATEMENT_STRING: IfcidProfile(
        capabilities=frozenset(
            {ObservationCapability.STATEMENT_TEXT, ObservationCapability.STATEMENT_IDENTITY}
        ),
        attribution=AttributionScope.THREAD,
    ),
    IfcidId.SQL_STATEMENT_END: IfcidProfile(
        capabilities=frozenset(
            {
                ObservationCapability.STATEMENT_SQLCODE,
                ObservationCapability.STATEMENT_EXECUTION_COUNT,
                ObservationCapability.STATEMENT_IDENTITY,
            }
        ),
        attribution=AttributionScope.THREAD,
    ),
    IfcidId.STATIC_STATEMENT_STATS: IfcidProfile(
        capabilities=frozenset(
            {
                ObservationCapability.STATEMENT_EXECUTION_COUNT,
                ObservationCapability.STATEMENT_IDENTITY,
            }
        ),
        attribution=AttributionScope.THREAD,
    ),
    # --- thread rollups, no statement detail -----------------------------
    IfcidId.ACCOUNTING: IfcidProfile(
        capabilities=frozenset({ObservationCapability.THREAD_ROLLUP}),
        attribution=AttributionScope.THREAD,
    ),
    IfcidId.STATISTICS: IfcidProfile(
        capabilities=frozenset({ObservationCapability.THREAD_ROLLUP}),
        attribution=AttributionScope.SUBSYSTEM,
    ),
    # --- contention -------------------------------------------------------
    IfcidId.LOCK_DETAIL: IfcidProfile(
        capabilities=frozenset({ObservationCapability.LOCK_CONTENTION}),
        attribution=AttributionScope.THREAD,
    ),
    IfcidId.DEADLOCK: IfcidProfile(
        capabilities=frozenset({ObservationCapability.LOCK_CONTENTION}),
        attribution=AttributionScope.SUBSYSTEM,
    ),
    IfcidId.TIMEOUT: IfcidProfile(
        capabilities=frozenset({ObservationCapability.LOCK_CONTENTION}),
        attribution=AttributionScope.SUBSYSTEM,
    ),
    IfcidId.AUDIT_TRAIL: IfcidProfile(
        capabilities=frozenset({ObservationCapability.TABLE_ACCESS_AUDIT}),
        attribution=AttributionScope.THREAD,
    ),
    # --- subsystem-wide dynamic statement cache: declared, never consumed --
    IfcidId.DYNAMIC_CACHE_TEXT: IfcidProfile(
        capabilities=frozenset({ObservationCapability.SUBSYSTEM_WIDE_CACHE_PRESENT}),
        attribution=AttributionScope.SUBSYSTEM,
    ),
    IfcidId.DYNAMIC_CACHE_STATS: IfcidProfile(
        capabilities=frozenset({ObservationCapability.SUBSYSTEM_WIDE_CACHE_PRESENT}),
        attribution=AttributionScope.SUBSYSTEM,
    ),
}

#: Capabilities derivable only from a thread-attributable record.
THREAD_ONLY_CAPABILITIES = frozenset(
    {
        ObservationCapability.STATEMENT_TEXT,
        ObservationCapability.STATEMENT_IDENTITY,
        ObservationCapability.STATEMENT_EXECUTION_COUNT,
        ObservationCapability.STATEMENT_SQLCODE,
    }
)


class IfcidRefusalCode(StrEnum):
    DECLARATION_DIGEST_INVALID = "DECLARATION_DIGEST_INVALID"
    NO_ENABLED_IFCID_GRANTS_ANY_CAPABILITY = "NO_ENABLED_IFCID_GRANTS_ANY_CAPABILITY"
    CORRELATION_KEY_UNRESOLVED = "CORRELATION_KEY_UNRESOLVED"
    NORMALIZATION_ADAPTER_UNDECLARED = "NORMALIZATION_ADAPTER_UNDECLARED"


class IfcidGap(StrEnum):
    """Recorded on the observation, never inferred away."""

    # structural, true of every z/OS extract
    PLATFORM_PROBES_STRUCTURALLY_ABSENT = "PLATFORM_PROBES_STRUCTURALLY_ABSENT"
    TABLE_SNAPSHOT_IMPOSSIBLE_FROM_TRACE = "TABLE_SNAPSHOT_IMPOSSIBLE_FROM_TRACE"
    OUTPUT_PARAMETERS_NOT_IN_TRACE = "OUTPUT_PARAMETERS_NOT_IN_TRACE"
    # trace conditions
    TRACE_RECORDS_POSSIBLY_LOST = "TRACE_RECORDS_POSSIBLY_LOST"
    TRACE_WINDOW_PARTIAL_COVERAGE = "TRACE_WINDOW_PARTIAL_COVERAGE"
    # capability absences
    STATEMENT_TEXT_CAPABILITY_ABSENT = "STATEMENT_TEXT_CAPABILITY_ABSENT"
    EXECUTION_COUNT_CAPABILITY_ABSENT = "EXECUTION_COUNT_CAPABILITY_ABSENT"
    SQLCODE_CAPABILITY_ABSENT = "SQLCODE_CAPABILITY_ABSENT"
    THREAD_ROLLUP_ONLY_NO_STATEMENT_DETAIL = "THREAD_ROLLUP_ONLY_NO_STATEMENT_DETAIL"
    # consumption decisions
    SUBSYSTEM_WIDE_SOURCE_NOT_CONSUMED = "SUBSYSTEM_WIDE_SOURCE_NOT_CONSUMED"
    OVERLAPPING_COUNT_SOURCES = "OVERLAPPING_COUNT_SOURCES"
    COUNTS_DISCARDED_WITHOUT_STATEMENT_KEY = "COUNTS_DISCARDED_WITHOUT_STATEMENT_KEY"
    STATEMENT_TEXT_RESOLUTION_REQUIRED = "STATEMENT_TEXT_RESOLUTION_REQUIRED"
    UNLINKED_IDENTITY_AND_TEXT_ENTRIES = "UNLINKED_IDENTITY_AND_TEXT_ENTRIES"
    # adapter contract violations
    EXTRACT_NOT_CHRONOLOGICALLY_ORDERED = "EXTRACT_NOT_CHRONOLOGICALLY_ORDERED"
    UNDECLARED_IFCID_IN_EXTRACT = "UNDECLARED_IFCID_IN_EXTRACT"


class IfcidCorrelationKey(CanonicalModel):
    """How trace records tie to one invocation. At least one strong key required."""

    luwid: str | None = None
    correlation_id: str | None = None
    thread_token: str | None = None
    plan_name: str | None = None
    package_name: str | None = None
    authid: str | None = None


class IfcidTraceDeclaration(CanonicalModel):
    """What was actually turned on. Declared by the site, never inferred."""

    declaration_id: str
    subsystem_id: str
    db2_version: str
    enabled_ifcids: tuple[IfcidId, ...]
    trace_started_at: str
    trace_stopped_at: str
    destination: Literal["SMF", "GTF", "OPX", "OPN", "VENDOR_EXTRACT"]
    records_possibly_lost: bool
    normalization_adapter_ref: str
    attestation_ref: str
    content_digest: str

    def capabilities(self) -> frozenset[ObservationCapability]:
        granted: set[ObservationCapability] = set()
        for ifcid in self.enabled_ifcids:
            profile = IFCID_PROFILES.get(ifcid)
            if profile is None:
                continue
            if profile.attribution is AttributionScope.SUBSYSTEM:
                # Subsystem-wide sources never grant thread-only capabilities.
                granted |= profile.capabilities - THREAD_ONLY_CAPABILITIES
            else:
                granted |= profile.capabilities
        return frozenset(granted)


class NormalizedIfcidRecord(CanonicalModel):
    """Site adapter output. One record, already decoded.

    Adapter contract: ``recorded_at`` is a canonical timestamp and records are
    returned in non-decreasing ``recorded_at`` order. The deriver verifies this
    rather than trusting it.

    Populate ``statement_identity`` wherever the IFCID carries it, including on
    text-bearing records. That is what lets a text record and a count record be
    recognised as the same statement.
    """

    ifcid: IfcidId
    recorded_at: str
    correlation: IfcidCorrelationKey
    statement_identity: StatementIdentity | None = None
    statement_text: str | None = None
    statement_kind: Literal["DYNAMIC", "STATIC", "UNKNOWN"] = "UNKNOWN"
    executions: int | None = None
    sqlcode: int | None = None
    sqlstate: str | None = None
    table_qualifier: str | None = None
    table_name: str | None = None


class IfcidRecordSource(Protocol):
    """Site adapter boundary. No implementation ships with this module."""

    def adapter_ref(self) -> str: ...
    def records(
        self, *, declaration: IfcidTraceDeclaration, correlation: IfcidCorrelationKey
    ) -> tuple[NormalizedIfcidRecord, ...]: ...


class IfcidInvocationWindow(CanonicalModel):
    """When the procedure ran, as reported by the caller — not by the trace."""

    invocation_id: str
    procedure_schema: str | None
    procedure_name: str
    started_at: str
    ended_at: str
    correlation: IfcidCorrelationKey


# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------

def assert_extract_admissible(
    *,
    declaration: IfcidTraceDeclaration,
    window: IfcidInvocationWindow,
    source: IfcidRecordSource,
) -> None:
    codes: list[IfcidRefusalCode] = []
    reasons: list[str] = []

    if canonical_digest(declaration.model_dump(exclude={"content_digest"})) != declaration.content_digest:
        codes.append(IfcidRefusalCode.DECLARATION_DIGEST_INVALID)
        reasons.append("Trace declaration digest does not match its content.")

    if source.adapter_ref() != declaration.normalization_adapter_ref:
        codes.append(IfcidRefusalCode.NORMALIZATION_ADAPTER_UNDECLARED)
        reasons.append(
            f"Record source adapter {source.adapter_ref()!r} is not the declared "
            f"adapter {declaration.normalization_adapter_ref!r}."
        )

    if not declaration.capabilities():
        codes.append(IfcidRefusalCode.NO_ENABLED_IFCID_GRANTS_ANY_CAPABILITY)
        reasons.append(
            "None of the enabled IFCIDs grants a consumable capability; "
            "the extract cannot support any runtime fact."
        )

    key = window.correlation
    if not any((key.luwid, key.correlation_id, key.thread_token)):
        codes.append(IfcidRefusalCode.CORRELATION_KEY_UNRESOLVED)
        reasons.append(
            "At least one of luwid, correlation_id or thread_token is required; "
            "plan or package alone cannot isolate one invocation."
        )

    if codes:
        raise ProbeError(
            ProbeRefusal(
                refusal_codes=(ProbeRefusalCode.PROBE_CAPTURE_INCOMPLETE,),
                reason=f"[{', '.join(codes)}] " + " ".join(reasons),
                plan_ref=window.invocation_id,
            )
        )


def _covers(declaration: IfcidTraceDeclaration, window: IfcidInvocationWindow) -> bool:
    return (
        declaration.trace_started_at <= window.started_at
        and declaration.trace_stopped_at >= window.ended_at
    )


def absence_inference_admissible(observation: RuntimeObservationRecord) -> bool:
    """Whether absence-based contradictions may be drawn from this observation.

    Wire into ``falsify``: MUST_EFFECT_NOT_OBSERVED and
    DYNAMIC_VARIANT_OUTSIDE_ENUMERATION are both inferences from absence, or
    from a variant set assumed exhaustive. On a partial capture neither is
    supportable. Since every z/OS observation has capture_complete=False, the
    falsifier is limited there to positive contradictions: value mismatch and
    statically-infeasible-path-observed.
    """
    return observation.capture_complete


# ---------------------------------------------------------------------------
# Key space
# ---------------------------------------------------------------------------

def _identity_key(identity: StatementIdentity) -> str:
    return "id:" + canonical_digest(identity.model_dump()).removeprefix("sha256:")[:24]


def _text_key(text: str) -> str:
    return "tx:" + canonical_digest({"text": text}).removeprefix("sha256:")[:24]


class _Entry:
    """Mutable accumulator for one statement, before reconciliation."""

    __slots__ = ("counts", "identity", "kind", "text")

    def __init__(self) -> None:
        self.identity: StatementIdentity | None = None
        self.text: str | None = None
        self.kind: str = "UNKNOWN"
        self.counts: dict[IfcidId, int] = defaultdict(int)

    def merge(self, other: _Entry) -> None:
        self.identity = self.identity or other.identity
        self.text = self.text or other.text
        if self.kind == "UNKNOWN":
            self.kind = other.kind
        for ifcid, value in other.counts.items():
            self.counts[ifcid] += value


# ---------------------------------------------------------------------------
# Derivation
# ---------------------------------------------------------------------------

class IfcidObservationDeriver:
    NAME = "zos-ifcid-deriver"
    VERSION = "1.2"

    def derive(
        self,
        *,
        declaration: IfcidTraceDeclaration,
        window: IfcidInvocationWindow,
        source: IfcidRecordSource,
        plan_ref: str,
        plan_digest: str,
        observed_at: datetime | None = None,
    ) -> RuntimeObservationRecord:
        assert_extract_admissible(declaration=declaration, window=window, source=source)

        caps = declaration.capabilities()
        gaps: set[IfcidGap] = {
            IfcidGap.PLATFORM_PROBES_STRUCTURALLY_ABSENT,
            IfcidGap.TABLE_SNAPSHOT_IMPOSSIBLE_FROM_TRACE,
            IfcidGap.OUTPUT_PARAMETERS_NOT_IN_TRACE,
        }

        if declaration.records_possibly_lost:
            gaps.add(IfcidGap.TRACE_RECORDS_POSSIBLY_LOST)
        if not _covers(declaration, window):
            gaps.add(IfcidGap.TRACE_WINDOW_PARTIAL_COVERAGE)
        if ObservationCapability.STATEMENT_TEXT not in caps:
            gaps.add(IfcidGap.STATEMENT_TEXT_CAPABILITY_ABSENT)
        if ObservationCapability.STATEMENT_EXECUTION_COUNT not in caps:
            gaps.add(IfcidGap.EXECUTION_COUNT_CAPABILITY_ABSENT)
        if ObservationCapability.STATEMENT_SQLCODE not in caps:
            gaps.add(IfcidGap.SQLCODE_CAPABILITY_ABSENT)
        if ObservationCapability.SUBSYSTEM_WIDE_CACHE_PRESENT in caps:
            gaps.add(IfcidGap.SUBSYSTEM_WIDE_SOURCE_NOT_CONSUMED)
        if ObservationCapability.STATEMENT_TEXT not in caps and (
            ObservationCapability.THREAD_ROLLUP in caps
        ):
            gaps.add(IfcidGap.THREAD_ROLLUP_ONLY_NO_STATEMENT_DETAIL)

        records = source.records(declaration=declaration, correlation=window.correlation)

        # Verify the adapter's ordering contract, then sort defensively so
        # last-write-wins fields really are last.
        if any(a.recorded_at > b.recorded_at for a, b in zip(records, records[1:], strict=False)):
            gaps.add(IfcidGap.EXTRACT_NOT_CHRONOLOGICALLY_ORDERED)
        ordered = tuple(sorted(records, key=lambda record: record.recorded_at))

        entries: dict[str, _Entry] = {}
        #: text_key -> identity_key, learned from any record carrying both.
        text_to_identity: dict[str, str] = {}
        sqlstate: str | None = None

        for record in ordered:
            if record.ifcid not in declaration.enabled_ifcids:
                gaps.add(IfcidGap.UNDECLARED_IFCID_IN_EXTRACT)
                continue
            profile = IFCID_PROFILES.get(record.ifcid)
            if profile is None:
                gaps.add(IfcidGap.UNDECLARED_IFCID_IN_EXTRACT)
                continue
            if profile.attribution is AttributionScope.SUBSYSTEM:
                continue  # declared, gap recorded, never consumed

            granted = profile.capabilities

            identity = record.statement_identity
            if identity is not None and (
                identity.is_empty() or ObservationCapability.STATEMENT_IDENTITY not in granted
            ):
                identity = None

            text = record.statement_text.strip() if record.statement_text else None
            if text is not None and ObservationCapability.STATEMENT_TEXT not in granted:
                text = None
            if text == "":
                text = None

            has_count = (
                ObservationCapability.STATEMENT_EXECUTION_COUNT in granted
                and record.executions is not None
            )

            if identity is None and text is None:
                if has_count:
                    # Counts with nothing to attach them to. Say so.
                    gaps.add(IfcidGap.COUNTS_DISCARDED_WITHOUT_STATEMENT_KEY)
                if ObservationCapability.STATEMENT_SQLCODE in granted and record.sqlstate:
                    sqlstate = record.sqlstate
                continue

            key = _identity_key(identity) if identity is not None else _text_key(text or "")
            if identity is not None and text is not None:
                text_to_identity[_text_key(text)] = key

            entry = entries.setdefault(key, _Entry())
            entry.identity = entry.identity or identity
            entry.text = entry.text or text
            if entry.kind == "UNKNOWN":
                entry.kind = record.statement_kind
            if has_count:
                entry.counts[record.ifcid] += record.executions or 0

            # SQLSTATE only from statement-capable IFCIDs, so lock and timeout
            # records cannot overwrite the procedure's end state.
            if ObservationCapability.STATEMENT_SQLCODE in granted and record.sqlstate:
                sqlstate = record.sqlstate

        # Reconcile: fold text-keyed entries into their identity when a record
        # linked the two. One statement can never surface twice.
        for text_key, identity_key in text_to_identity.items():
            if text_key in entries and identity_key in entries and text_key != identity_key:
                entries[identity_key].merge(entries.pop(text_key))

        # Text-only and identity-only entries that were never linked may or may
        # not be the same statement. Unknowable from the extract; record it.
        has_unlinked_text = any(key.startswith("tx:") for key in entries)
        has_identity = any(key.startswith("id:") for key in entries)
        if has_unlinked_text and has_identity:
            gaps.add(IfcidGap.UNLINKED_IDENTITY_AND_TEXT_ENTRIES)

        tainted = declaration.records_possibly_lost or (
            IfcidGap.TRACE_WINDOW_PARTIAL_COVERAGE in gaps
        )

        observed_statements: list[ObservedStatement] = []
        for key in sorted(entries):
            entry = entries[key]

            if len(entry.counts) > 1:
                # Two count-capable IFCIDs for one statement: the sum is
                # meaningless, so report no count rather than a wrong one.
                gaps.add(IfcidGap.OVERLAPPING_COUNT_SOURCES)
                count: int | None = None
                qualifier = "POSSIBLE_METRICS_UNAVAILABLE"
            elif len(entry.counts) == 1:
                count = next(iter(entry.counts.values()))
                qualifier = "POSSIBLE_CACHE_EVICTION_UNDERCOUNT" if tainted else "EXACT"
            else:
                count = None
                qualifier = "POSSIBLE_METRICS_UNAVAILABLE"

            if entry.text is not None:
                resolution = TextResolution.RESOLVED
            elif entry.identity is not None:
                resolution = TextResolution.CATALOG_LOOKUP_REQUIRED
                gaps.add(IfcidGap.STATEMENT_TEXT_RESOLUTION_REQUIRED)
            else:  # unreachable: an entry always has text or identity
                resolution = TextResolution.NOT_AVAILABLE

            observed_statements.append(
                ObservedStatement(
                    statement_text=entry.text,
                    statement_identity=entry.identity,
                    text_resolution=resolution,
                    executions=count,
                    section_kind=entry.kind,  # type: ignore[arg-type]
                    capture_qualifier=qualifier,  # type: ignore[arg-type]
                )
            )

        payload = {
            "schema_version": "runtime-observation-record-1.0",
            "authority_scope": "RUNTIME_EVIDENCE_ONLY",
            "platform_governance_ref": None,
            "plan_ref": plan_ref,
            "plan_digest": plan_digest,
            "invocation_ref": window.invocation_id,
            "platform": ProbePlatform.DB2_ZOS,
            "observed_at": canonical_timestamp(observed_at.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")) if observed_at else declaration.trace_stopped_at,
            "sqlstate": sqlstate,
            # Never derivable from trace; empty with a recorded gap, not omitted.
            "output_parameters": (),
            "dynamic_statements": tuple(observed_statements),
            "table_deltas": (),
            "rolled_back": False,
            "capture_complete": False,  # always: no snapshots, no OUT parameters
            "capture_gaps": tuple(sorted(gap.value for gap in gaps)),
            "probe_name": self.NAME,
            "probe_version": self.VERSION,
        }

        # content_digest covers the whole artifact, timestamp included, so it
        # remains a real integrity check. observation_id derives from a stable
        # identity tuple, so two derivations of one extract share an ID and
        # differ only in digest — which is the truth.
        identity_digest = canonical_digest(
            {
                "plan_digest": plan_digest,
                "declaration_digest": declaration.content_digest,
                "invocation_ref": window.invocation_id,
            }
        )
        return RuntimeObservationRecord(
            observation_id="runtime-observation-" + identity_digest.removeprefix("sha256:")[:20],
            content_digest=canonical_digest(payload),
            **payload,  # type: ignore[arg-type]
        )


__all__ = [
    "IFCID_PROFILES",
    "THREAD_ONLY_CAPABILITIES",
    "AttributionScope",
    "IfcidCorrelationKey",
    "IfcidGap",
    "IfcidId",
    "IfcidInvocationWindow",
    "IfcidObservationDeriver",
    "IfcidProfile",
    "IfcidRecordSource",
    "IfcidRefusalCode",
    "IfcidTraceDeclaration",
    "NormalizedIfcidRecord",
    "ObservationCapability",
    "ObservedStatement",
    "StatementIdentity",
    "TextResolution",
    "absence_inference_admissible",
    "assert_extract_admissible",
]
