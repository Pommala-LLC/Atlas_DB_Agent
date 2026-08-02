"""Phase 6 runtime probe: instrumentation capture and static-claim falsification.

Boundaries enforced by this module, not by convention:

* Observation is never authority. Records carry ``authority_scope =
  RUNTIME_EVIDENCE_ONLY`` and no code path here writes to ScenarioSpec,
  CandidateBDD, or the governance store.
* The comparator emits contradictions only. A matched expectation produces
  nothing, because non-observation is not nonexistence and observation of one
  path says nothing about the others.
* Probe facilities are LUW-only. MON_GET_PKG_CACHE_STMT and event monitors do
  not exist on Db2 for z/OS; a z/OS plan is refused rather than silently
  probed with the wrong instrument.
* No driver import at module scope. The analyzer stays engine-free; ibm_db is
  imported lazily inside the LUW probe.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal, Protocol

from ojas_reconciler.db2_behavior.bdd.models import canonical_timestamp
from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.parsing.models import CanonicalModel
from ojas_reconciler.db2_behavior.runtime.models import (
    LiveVerificationEligibility,
    RollbackContainment,
    RuntimeInvocation,
    RuntimePlanStatus,
    RuntimeSafetyAssessment,
    RuntimeVerificationPlan,
)


class ProbePlatform(StrEnum):
    DB2_LUW = "DB2_LUW"
    DB2_ZOS = "DB2_ZOS"


class ProbeKind(StrEnum):
    PACKAGE_CACHE_DYNAMIC_SQL = "PACKAGE_CACHE_DYNAMIC_SQL"
    TABLE_ROW_SNAPSHOT = "TABLE_ROW_SNAPSHOT"
    OUTPUT_PARAMETER = "OUTPUT_PARAMETER"
    SQLSTATE_DIAGNOSTIC = "SQLSTATE_DIAGNOSTIC"


class ProbeRefusalCode(StrEnum):
    PLATFORM_PROBES_UNAVAILABLE = "PLATFORM_PROBES_UNAVAILABLE"
    PLAN_DIGEST_INVALID = "PLAN_DIGEST_INVALID"
    PLAN_NOT_ELIGIBLE = "PLAN_NOT_ELIGIBLE"
    SANDBOX_ATTESTATION_MISSING = "SANDBOX_ATTESTATION_MISSING"
    MANUAL_APPROVAL_MISSING = "MANUAL_APPROVAL_MISSING"
    ROLLBACK_CONTAINMENT_UNPROVEN = "ROLLBACK_CONTAINMENT_UNPROVEN"
    NO_ROLLBACK_REQUIRES_CONTAINMENT_PROOF = "NO_ROLLBACK_REQUIRES_CONTAINMENT_PROOF"
    SNAPSHOT_SCOPE_UNDECLARED = "SNAPSHOT_SCOPE_UNDECLARED"
    PROBE_CAPTURE_INCOMPLETE = "PROBE_CAPTURE_INCOMPLETE"


class ContradictionCode(StrEnum):
    """Only these are emitted. There is deliberately no CONFIRMED code."""

    STATICALLY_INFEASIBLE_PATH_OBSERVED = "STATICALLY_INFEASIBLE_PATH_OBSERVED"
    DYNAMIC_VARIANT_OUTSIDE_ENUMERATION = "DYNAMIC_VARIANT_OUTSIDE_ENUMERATION"
    UNDECLARED_MUTATION_OBSERVED = "UNDECLARED_MUTATION_OBSERVED"
    MUST_EFFECT_NOT_OBSERVED = "MUST_EFFECT_NOT_OBSERVED"
    OUT_PARAMETER_VALUE_MISMATCH = "OUT_PARAMETER_VALUE_MISMATCH"
    SQLSTATE_MISMATCH = "SQLSTATE_MISMATCH"


class ProbeRefusal(CanonicalModel):
    refusal_codes: tuple[ProbeRefusalCode, ...]
    reason: str
    plan_ref: str
    evidence_refs: tuple[str, ...] = ()


class ProbeError(RuntimeError):
    def __init__(self, refusal: ProbeRefusal) -> None:
        super().__init__(refusal.reason)
        self.refusal = refusal


class StatementIdentity(CanonicalModel):
    """Statement identity independent of captured SQL text."""

    collection: str | None = None
    package: str | None = None
    package_version: str | None = None
    section: int | None = None
    statement_number: int | None = None
    stmt_id: int | None = None

    def is_empty(self) -> bool:
        return not any(
            (
                self.collection,
                self.package,
                self.section is not None,
                self.statement_number is not None,
                self.stmt_id is not None,
            )
        )


class TextResolution(StrEnum):
    RESOLVED = "RESOLVED"
    CATALOG_LOOKUP_REQUIRED = "CATALOG_LOOKUP_REQUIRED"
    NOT_AVAILABLE = "NOT_AVAILABLE"


class ObservedStatement(CanonicalModel):
    """One observed statement; text may be absent when only identity is captured."""

    statement_text: str | None
    statement_identity: StatementIdentity | None = None
    text_resolution: TextResolution = TextResolution.RESOLVED
    # None means executed but the count is not trustworthy.
    executions: int | None
    section_kind: Literal["DYNAMIC", "STATIC", "UNKNOWN"] = "UNKNOWN"
    capture_qualifier: Literal[
        "EXACT",
        "POSSIBLE_METRICS_UNAVAILABLE",
        "POSSIBLE_CACHE_EVICTION_UNDERCOUNT",
    ] = "EXACT"


class ObservedTableDelta(CanonicalModel):
    table_name: str
    rows_before: int
    rows_after: int
    digest_before: str
    digest_after: str


class ObservedParameter(CanonicalModel):
    parameter_name: str
    canonical_value: str | None


class ProbeCaptureConfig(CanonicalModel):
    """Declared, digest-bound capture scope. Nothing outside it is read."""

    platform: ProbePlatform
    snapshot_tables: tuple[str, ...]
    capture_package_cache: bool = True
    rollback_after_call: bool = True
    sandbox_attestation: str
    manual_approval_ref: str | None = None
    connection_ref: str


class RuntimeObservationRecord(CanonicalModel):
    schema_version: Literal["runtime-observation-record-1.0"] = "runtime-observation-record-1.0"
    authority_scope: Literal["RUNTIME_EVIDENCE_ONLY"] = "RUNTIME_EVIDENCE_ONLY"
    platform_governance_ref: None = None
    observation_id: str
    plan_ref: str
    plan_digest: str
    invocation_ref: str
    platform: ProbePlatform
    observed_at: str
    sqlstate: str | None
    output_parameters: tuple[ObservedParameter, ...]
    dynamic_statements: tuple[ObservedStatement, ...]
    table_deltas: tuple[ObservedTableDelta, ...]
    rolled_back: bool
    capture_complete: bool
    capture_gaps: tuple[str, ...]
    probe_name: str
    probe_version: str
    content_digest: str


class Contradiction(CanonicalModel):
    code: ContradictionCode
    detail: str
    plan_ref: str
    expectation_ref: str | None = None
    evidence_refs: tuple[str, ...] = ()


class FalsificationReport(CanonicalModel):
    schema_version: Literal["falsification-report-1.0"] = "falsification-report-1.0"
    authority_scope: Literal["RUNTIME_EVIDENCE_ONLY"] = "RUNTIME_EVIDENCE_ONLY"
    plan_ref: str
    observation_ref: str
    contradictions: tuple[Contradiction, ...]
    unobserved_expectation_refs: tuple[str, ...]
    note: str = (
        "Absence of contradictions is not confirmation. One execution exercises "
        "one path; unobserved paths remain unproven."
    )
    content_digest: str


# --------------------------------------------------------------------------
# Guards
# --------------------------------------------------------------------------

def assert_probe_admissible(
    *,
    plan: RuntimeVerificationPlan,
    safety: RuntimeSafetyAssessment,
    config: ProbeCaptureConfig,
) -> None:
    """Fail closed before any connection is opened."""
    codes: list[ProbeRefusalCode] = []
    reasons: list[str] = []

    if config.platform is not ProbePlatform.DB2_LUW:
        codes.append(ProbeRefusalCode.PLATFORM_PROBES_UNAVAILABLE)
        reasons.append(
            "Package-cache and event-monitor probes exist on Db2 LUW only; "
            "z/OS requires IFCID-based instrumentation that this probe does not implement."
        )

    if canonical_digest(plan.model_dump(exclude={"content_digest"})) != plan.content_digest:
        codes.append(ProbeRefusalCode.PLAN_DIGEST_INVALID)
        reasons.append("Verification plan digest does not match its content.")

    if plan.plan_status is RuntimePlanStatus.BLOCKED:
        codes.append(ProbeRefusalCode.PLAN_NOT_ELIGIBLE)
        reasons.append(f"Plan is BLOCKED: {', '.join(plan.blockers) or 'no reason recorded'}.")

    if not config.sandbox_attestation.strip():
        codes.append(ProbeRefusalCode.SANDBOX_ATTESTATION_MISSING)
        reasons.append("A non-empty sandbox attestation is required.")

    if (
        safety.live_eligibility is LiveVerificationEligibility.MANUAL_APPROVAL_REQUIRED
        and not config.manual_approval_ref
    ):
        codes.append(ProbeRefusalCode.MANUAL_APPROVAL_MISSING)
        reasons.append("Plan eligibility is MANUAL_APPROVAL_REQUIRED and no approval ref was supplied.")

    contained = safety.rollback_containment is RollbackContainment.ROLLBACK_SAFE
    if not contained:
        codes.append(ProbeRefusalCode.ROLLBACK_CONTAINMENT_UNPROVEN)
        reasons.append(
            f"rollback_containment is {safety.rollback_containment}; "
            "mutations cannot be shown to be reversible."
        )
    if not config.rollback_after_call and not contained:
        # The gap v1.0.0 leaves open: --no-rollback with UNKNOWN containment.
        codes.append(ProbeRefusalCode.NO_ROLLBACK_REQUIRES_CONTAINMENT_PROOF)
        reasons.append("Disabling rollback requires proven containment.")

    if not config.snapshot_tables:
        codes.append(ProbeRefusalCode.SNAPSHOT_SCOPE_UNDECLARED)
        reasons.append("Declare the tables to snapshot; undeclared mutations cannot be detected.")

    if codes:
        raise ProbeError(
            ProbeRefusal(
                refusal_codes=tuple(codes),
                reason=" ".join(reasons),
                plan_ref=plan.plan_id,
                evidence_refs=plan.evidence_refs,
            )
        )


# --------------------------------------------------------------------------
# Port + LUW implementation
# --------------------------------------------------------------------------

class Db2ProbePort(Protocol):
    """Everything engine-specific sits behind this."""

    def open(self, connection_ref: str) -> None: ...
    def close(self) -> None: ...
    def begin(self) -> None: ...
    def rollback(self) -> None: ...
    def snapshot_tables(self, tables: tuple[str, ...]) -> dict[str, tuple[int, str]]: ...
    def package_cache(self) -> dict[str, tuple[int, str]]: ...
    def call_procedure(
        self, invocation: RuntimeInvocation
    ) -> tuple[dict[str, str | None], str | None]: ...


class Db2LuwProbe:
    """ibm_db-backed probe, imported and initialized only after property activation."""

    NAME = "db2-luw-probe"
    VERSION = "1.1"

    def __init__(self) -> None:
        self._conn: Any = None
        self._ibm_db: Any = None

    def open(self, connection_ref: str) -> None:
        import ibm_db  # local import after property/capability gating

        self._ibm_db = ibm_db
        self._conn = ibm_db.connect(connection_ref, "", "")
        ibm_db.autocommit(self._conn, ibm_db.SQL_AUTOCOMMIT_OFF)

    def close(self) -> None:
        if self._conn is not None:
            self._ibm_db.close(self._conn)
            self._conn = None

    def begin(self) -> None:
        return None

    def rollback(self) -> None:
        self._ibm_db.rollback(self._conn)

    def _rows(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        stmt = self._ibm_db.prepare(self._conn, sql)
        self._ibm_db.execute(stmt, params)
        out: list[dict[str, Any]] = []
        row = self._ibm_db.fetch_assoc(stmt)
        while row:
            out.append(row)
            row = self._ibm_db.fetch_assoc(stmt)
        return out

    def snapshot_tables(self, tables: tuple[str, ...]) -> dict[str, tuple[int, str]]:
        result: dict[str, tuple[int, str]] = {}
        for table in tables:
            if not table.replace("_", "").replace(".", "").isalnum():
                raise ProbeError(
                    ProbeRefusal(
                        refusal_codes=(ProbeRefusalCode.SNAPSHOT_SCOPE_UNDECLARED,),
                        reason=f"Refusing unqualified or unsafe table identifier: {table!r}.",
                        plan_ref="",
                    )
                )
            rows = self._rows(f"SELECT * FROM {table}")  # noqa: S608
            digest = canonical_digest([{k: str(v) for k, v in sorted(r.items())} for r in rows])
            result[table] = (len(rows), digest)
        return result

    def package_cache(self) -> dict[str, tuple[int, str]]:
        rows = self._rows(
            "SELECT STMT_TEXT, NUM_EXEC_WITH_METRICS, SECTION_TYPE "
            "FROM TABLE(MON_GET_PKG_CACHE_STMT(NULL, NULL, NULL, -2))"
        )
        cache: dict[str, tuple[int, str]] = {}
        for row in rows:
            text = str(row.get("STMT_TEXT") or "").strip()
            if not text:
                continue
            execs = int(row.get("NUM_EXEC_WITH_METRICS") or 0)
            kind = "DYNAMIC" if str(row.get("SECTION_TYPE") or "").upper() == "D" else "STATIC"
            cache[text] = (execs, kind)
        return cache

    def call_procedure(
        self, invocation: RuntimeInvocation
    ) -> tuple[dict[str, str | None], str | None]:
        """Invoke with callproc so OUT and INOUT values are returned explicitly."""
        ibm_db = self._ibm_db
        qualified = (
            f"{invocation.procedure_schema}.{invocation.procedure_name}"
            if invocation.procedure_schema
            else invocation.procedure_name
        )
        inputs = tuple(parameter.value.canonical_value for parameter in invocation.parameters)
        out_modes = {"OUT", "INOUT"}
        sqlstate: str | None = None
        returned: tuple[Any, ...] | None = None
        try:
            result = ibm_db.callproc(self._conn, qualified, inputs)
        except Exception:  # noqa: BLE001 - SQLSTATE is runtime evidence
            sqlstate = ibm_db.stmt_error() or ibm_db.conn_error(self._conn) or None
            result = None
        if result is not None:
            if not isinstance(result, tuple):
                returned = ()
            elif len(result) == len(inputs) + 1:
                returned = tuple(result[1:])
            elif len(result) == len(inputs):
                returned = tuple(result)
        if returned is None or len(returned) != len(invocation.parameters):
            return (
                {
                    parameter.parameter_name: None
                    for parameter in invocation.parameters
                    if parameter.parameter_mode in out_modes
                },
                sqlstate or "OUTPUT_CAPTURE_UNAVAILABLE",
            )
        outputs: dict[str, str | None] = {}
        for parameter, value in zip(invocation.parameters, returned, strict=True):
            if parameter.parameter_mode in out_modes:
                outputs[parameter.parameter_name] = None if value is None else str(value)
        return outputs, sqlstate


def diff_package_cache(
    before: dict[str, tuple[int, str]],
    after: dict[str, tuple[int, str]],
) -> tuple[tuple[ObservedStatement, ...], tuple[str, ...]]:
    """Derive cache deltas without treating metric gaps as zero executions."""
    statements: list[ObservedStatement] = []
    gaps: list[str] = []
    for text in sorted(after):
        after_count, kind = after[text]
        before_count = before.get(text, (0, ""))[0]
        section: Literal["DYNAMIC", "STATIC", "UNKNOWN"] = (
            "DYNAMIC" if kind == "DYNAMIC" else "STATIC" if kind == "STATIC" else "UNKNOWN"
        )
        if after_count > before_count:
            statements.append(
                ObservedStatement(
                    statement_text=text,
                    executions=after_count - before_count,
                    section_kind=section,
                    capture_qualifier="EXACT",
                )
            )
        elif text not in before and after_count == 0:
            statements.append(
                ObservedStatement(
                    statement_text=text,
                    executions=None,
                    section_kind=section,
                    capture_qualifier="POSSIBLE_METRICS_UNAVAILABLE",
                )
            )
            gaps.append("PACKAGE_CACHE_METRICS_UNAVAILABLE")
        elif after_count < before_count:
            statements.append(
                ObservedStatement(
                    statement_text=text,
                    executions=None,
                    section_kind=section,
                    capture_qualifier="POSSIBLE_CACHE_EVICTION_UNDERCOUNT",
                )
            )
            gaps.append("PACKAGE_CACHE_EVICTION_DETECTED")
    if any(text not in after for text in before):
        gaps.append("PACKAGE_CACHE_ENTRY_DISAPPEARED")
    if not statements:
        gaps.append("PACKAGE_CACHE_DELTA_EMPTY_POSSIBLE_EVICTION")
    return tuple(statements), tuple(sorted(set(gaps)))



# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------

class ProbeSession:
    def __init__(self, probe: Db2ProbePort, *, probe_name: str, probe_version: str) -> None:
        self._probe = probe
        self._name = probe_name
        self._version = probe_version

    def run(
        self,
        *,
        plan: RuntimeVerificationPlan,
        safety: RuntimeSafetyAssessment,
        invocation: RuntimeInvocation,
        config: ProbeCaptureConfig,
        observed_at: datetime | None = None,
    ) -> RuntimeObservationRecord:
        assert_probe_admissible(plan=plan, safety=safety, config=config)

        gaps: list[str] = []
        rolled_back = False
        self._probe.open(config.connection_ref)
        try:
            self._probe.begin()
            before_tables = self._probe.snapshot_tables(config.snapshot_tables)
            before_cache = self._probe.package_cache() if config.capture_package_cache else {}

            outputs, sqlstate = self._probe.call_procedure(invocation)

            after_tables = self._probe.snapshot_tables(config.snapshot_tables)
            after_cache = self._probe.package_cache() if config.capture_package_cache else {}
            if not config.capture_package_cache:
                gaps.append("PACKAGE_CACHE_NOT_CAPTURED")

            if config.rollback_after_call:
                self._probe.rollback()
                rolled_back = True
        finally:
            self._probe.close()

        deltas = tuple(
            ObservedTableDelta(
                table_name=name,
                rows_before=before_tables[name][0],
                rows_after=after_tables[name][0],
                digest_before=before_tables[name][1],
                digest_after=after_tables[name][1],
            )
            for name in sorted(config.snapshot_tables)
            if name in before_tables and name in after_tables
        )

        if config.capture_package_cache:
            new_statements, cache_gaps = diff_package_cache(before_cache, after_cache)
            gaps.extend(cache_gaps)
        else:
            new_statements = ()

        payload = {
            "schema_version": "runtime-observation-record-1.0",
            "authority_scope": "RUNTIME_EVIDENCE_ONLY",
            "platform_governance_ref": None,
            "plan_ref": plan.plan_id,
            "plan_digest": plan.content_digest,
            "invocation_ref": invocation.invocation_id,
            "platform": config.platform,
            "observed_at": canonical_timestamp((observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")),
            "sqlstate": sqlstate,
            "output_parameters": tuple(
                ObservedParameter(parameter_name=k, canonical_value=v)
                for k, v in sorted(outputs.items())
            ),
            "dynamic_statements": new_statements,
            "table_deltas": deltas,
            "rolled_back": rolled_back,
            "capture_complete": not gaps,
            "capture_gaps": tuple(sorted(gaps)),
            "probe_name": self._name,
            "probe_version": self._version,
        }
        digest = canonical_digest(payload)
        return RuntimeObservationRecord(
            observation_id="runtime-observation-" + digest.removeprefix("sha256:")[:20],
            content_digest=digest,
            **payload,  # type: ignore[arg-type]
        )


# --------------------------------------------------------------------------
# Falsifier
# --------------------------------------------------------------------------


def absence_inference_admissible(observation: RuntimeObservationRecord) -> bool:
    """Return whether absence/exhaustiveness contradictions are licensed."""
    return observation.capture_complete

def falsify(
    *,
    plan: RuntimeVerificationPlan,
    observation: RuntimeObservationRecord,
    enumerated_dynamic_variants: tuple[str, ...] = (),
    statically_infeasible_statements: tuple[str, ...] = (),
) -> FalsificationReport:
    """Compare observation against static claims and report only contradictions.

    A matched expectation yields nothing. This function cannot promote, confirm,
    or raise the modality of any effect.
    """
    contradictions: list[Contradiction] = []
    unobserved: list[str] = []

    observed_outputs = {p.parameter_name: p.canonical_value for p in observation.output_parameters}
    observed_texts = {s.statement_text for s in observation.dynamic_statements if s.statement_text is not None}

    for expectation in plan.expected_observations:
        if expectation.observation_kind.value == "OUT_PARAMETER" and expectation.target:
            if expectation.target not in observed_outputs:
                unobserved.append(expectation.expectation_id)
                continue
            expected = expectation.expected_value.canonical_value if expectation.expected_value else None
            actual = observed_outputs[expectation.target]
            if expected is not None and actual != expected:
                contradictions.append(
                    Contradiction(
                        code=ContradictionCode.OUT_PARAMETER_VALUE_MISMATCH,
                        detail=f"{expectation.target}: static expected {expected!r}, observed {actual!r}.",
                        plan_ref=plan.plan_id,
                        expectation_ref=expectation.expectation_id,
                        evidence_refs=expectation.evidence_refs,
                    )
                )
        elif expectation.modality.value == "MUST":
            unobserved.append(expectation.expectation_id)

    for text in sorted(observed_texts):
        if text in set(statically_infeasible_statements):
            contradictions.append(
                Contradiction(
                    code=ContradictionCode.STATICALLY_INFEASIBLE_PATH_OBSERVED,
                    detail=f"Statement declared statically infeasible was executed: {text[:120]}",
                    plan_ref=plan.plan_id,
                )
            )
        if (
            absence_inference_admissible(observation)
            and enumerated_dynamic_variants
            and text not in set(enumerated_dynamic_variants)
        ):
            contradictions.append(
                Contradiction(
                    code=ContradictionCode.DYNAMIC_VARIANT_OUTSIDE_ENUMERATION,
                    detail=f"Executed statement outside the enumerated variant set: {text[:120]}",
                    plan_ref=plan.plan_id,
                )
            )

    declared_tables = {
        expectation.target
        for expectation in plan.expected_observations
        if expectation.observation_kind.value in {"ROW_CHANGE", "TABLE_MUTATION"} and expectation.target
    }
    for delta in observation.table_deltas:
        changed = delta.digest_before != delta.digest_after
        if changed and declared_tables and delta.table_name not in declared_tables:
            contradictions.append(
                Contradiction(
                    code=ContradictionCode.UNDECLARED_MUTATION_OBSERVED,
                    detail=(
                        f"{delta.table_name} changed ({delta.rows_before} -> {delta.rows_after} rows) "
                        "but no static effect declared a mutation on it."
                    ),
                    plan_ref=plan.plan_id,
                )
            )

    payload = {
        "schema_version": "falsification-report-1.0",
        "authority_scope": "RUNTIME_EVIDENCE_ONLY",
        "plan_ref": plan.plan_id,
        "observation_ref": observation.observation_id,
        "contradictions": tuple(contradictions),
        "unobserved_expectation_refs": tuple(sorted(set(unobserved))),
    }
    return FalsificationReport(content_digest=canonical_digest(payload), **payload)  # type: ignore[arg-type]


__all__ = [
    "Contradiction",
    "ContradictionCode",
    "Db2LuwProbe",
    "Db2ProbePort",
    "FalsificationReport",
    "ObservedParameter",
    "ObservedStatement",
    "ObservedTableDelta",
    "ProbeCaptureConfig",
    "ProbeError",
    "ProbeKind",
    "ProbePlatform",
    "ProbeRefusal",
    "ProbeRefusalCode",
    "ProbeSession",
    "RuntimeObservationRecord",
    "StatementIdentity",
    "TextResolution",
    "absence_inference_admissible",
    "assert_probe_admissible",
    "diff_package_cache",
    "falsify",
]
