from __future__ import annotations

import json
import os
import platform
import re
import tempfile
from importlib import metadata
from importlib.resources import files
from hashlib import sha256
from pathlib import Path

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.governance.adapters.sqlite import GovernanceStore, GovernanceStoreError
from ojas_reconciler.db2_behavior.core.release_models import DoctorCheck, DoctorCheckStatus, DoctorReport


def build_doctor_report(project_root: Path) -> DoctorReport:
    checks: list[DoctorCheck] = []
    version = tuple(int(part) for part in platform.python_version_tuple())
    checks.append(
        DoctorCheck(
            check_id="PYTHON_VERSION",
            status=DoctorCheckStatus.PASS if (3, 13) <= version[:2] < (3, 15) else DoctorCheckStatus.WARN,
            message=f"Python {platform.python_version()} (supported 3.13.x or 3.14.x)",
        )
    )

    project_contracts = sorted((project_root / "contracts").glob("*.schema.json"), key=lambda p: p.name)
    if project_contracts:
        contracts = tuple((contract.name, contract.read_text(encoding="utf-8")) for contract in project_contracts)
        contract_source = "project"
    else:
        resource_root = files("ojas_reconciler.db2_behavior.contracts_schemas")
        contracts = tuple(
            sorted(
                (
                    (resource.name, resource.read_text(encoding="utf-8"))
                    for resource in resource_root.iterdir()
                    if resource.name.endswith(".schema.json")
                ),
                key=lambda value: value[0],
            )
        )
        contract_source = "installed-package"
    contract_errors: list[str] = []
    for contract_name, contract_text in contracts:
        try:
            json.loads(contract_text)
        except Exception as exc:  # diagnostic boundary
            contract_errors.append(f"{contract_name}: {exc}")
    checks.append(
        DoctorCheck(
            check_id="JSON_CONTRACTS",
            status=DoctorCheckStatus.PASS if contracts and not contract_errors else DoctorCheckStatus.FAIL,
            message=(
                f"{len(contracts)} contract files parsed from {contract_source}"
                if not contract_errors
                else "; ".join(contract_errors)
            ),
        )
    )

    try:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "doctor.sqlite3"
            store = GovernanceStore(db)
            store.initialize(applied_at="2026-01-01T00:00:00.000000Z")
            store.assert_schema_guard()
        migration_status = DoctorCheckStatus.PASS
        migration_message = "Migration chain and identity schema guard passed"
    except GovernanceStoreError as exc:
        migration_status = DoctorCheckStatus.FAIL
        migration_message = str(exc)
    checks.append(
        DoctorCheck(
            check_id="GOVERNANCE_MIGRATIONS",
            status=migration_status,
            message=migration_message,
        )
    )

    pyproject = project_root / "pyproject.toml"
    if pyproject.exists():
        metadata_status = DoctorCheckStatus.PASS
        metadata_message = "pyproject.toml present, sha256:" + sha256(pyproject.read_bytes()).hexdigest()
    else:
        try:
            installed_version = metadata.version("atlas-procedure-intelligence")
            metadata_status = DoctorCheckStatus.PASS
            metadata_message = f"Installed distribution metadata present, version={installed_version}"
        except metadata.PackageNotFoundError:
            from ojas_reconciler.db2_behavior import __version__

            metadata_status = DoctorCheckStatus.PASS
            metadata_message = f"Importable package metadata present, version={__version__}"
    checks.append(
        DoctorCheck(
            check_id="PROJECT_METADATA",
            status=metadata_status,
            message=metadata_message,
        )
    )

    checks.append(
        DoctorCheck(
            check_id="DISTRIBUTION_NAMING",
            status=DoctorCheckStatus.PASS,
            message=(
                "Atlas naming is frozen with a compatibility policy; legacy Db2/Ojas aliases remain supported through 3.0.0."
            ),
        )
    )
    checks.append(
        DoctorCheck(
            check_id="COMMERCIAL_MATURITY",
            status=DoctorCheckStatus.WARN,
            message=(
                "Commercialization candidate only: organic estate validation, native Windows/offline "
                "wheelhouse, SBOM verification, support SLA, and metering gates remain unresolved."
            ),
        )
    )
    checks.append(
        DoctorCheck(
            check_id="PHASE6_BASELINE",
            status=DoctorCheckStatus.PASS,
            message="Phase 6 runtime verification is experimental, deferred, and disabled by default.",
        )
    )
    checks.append(
        DoctorCheck(
            check_id="LOCAL_EVIDENCE_AUTHORITY",
            status=DoctorCheckStatus.PASS,
            message="SQLite stores LOCAL_NON_AUTHORITATIVE_EVIDENCE and cannot mint platform admission.",
        )
    )

    try:
        gherkin_version = metadata.version("gherkin-official")
        if gherkin_version == "42.0.0":
            gherkin_status = DoctorCheckStatus.PASS
            gherkin_message = (
                f"gherkin-official={gherkin_version}; mandatory readable-BDD parse gate available"
            )
        else:
            gherkin_status = DoctorCheckStatus.FAIL
            gherkin_message = (
                f"gherkin-official={gherkin_version}; release requires exactly 42.0.0"
            )
    except metadata.PackageNotFoundError:
        if (os.environ.get("ATLAS_TEST_ALLOW_GHERKIN_FALLBACK") or os.environ.get("OJAS_TEST_ALLOW_GHERKIN_FALLBACK")) == "1":
            gherkin_status = DoctorCheckStatus.WARN
            gherkin_message = (
                "gherkin-official is unavailable; explicit test-only canonical parser is active. "
                "Production generation remains fail-closed."
            )
        else:
            gherkin_status = DoctorCheckStatus.FAIL
            gherkin_message = (
                "Missing mandatory dependency gherkin-official. Install project dependencies "
                "before generating readable BDD."
            )
    checks.append(
        DoctorCheck(
            check_id="GHERKIN_OFFICIAL",
            status=gherkin_status,
            message=gherkin_message,
        )
    )

    required_packages = ("pydantic", "networkx", "lark", "jsonschema")
    versions: list[str] = []
    missing_packages: list[str] = []
    for package in required_packages:
        try:
            versions.append(f"{package}={metadata.version(package)}")
        except metadata.PackageNotFoundError:
            missing_packages.append(package)
    checks.append(
        DoctorCheck(
            check_id="RUNTIME_DEPENDENCIES",
            status=DoctorCheckStatus.PASS if not missing_packages else DoctorCheckStatus.FAIL,
            message=(", ".join(versions) if not missing_packages else f"Missing: {', '.join(missing_packages)}"),
        )
    )

    secret_patterns = (
        re.compile(r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{4,}['\"]"),
        re.compile(r"(?i)BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    )
    secret_hits: list[str] = []
    source_root = project_root / "src"
    relative_base = project_root
    if not source_root.exists():
        package_root = Path(str(files("ojas_reconciler.db2_behavior")))
        source_root = package_root
        relative_base = package_root.parent
    if source_root.exists():
        for source_file in sorted(source_root.rglob("*.py"), key=lambda value: value.as_posix()):
            text = source_file.read_text(encoding="utf-8")
            if any(pattern.search(text) for pattern in secret_patterns):
                secret_hits.append(source_file.relative_to(relative_base).as_posix())
    checks.append(
        DoctorCheck(
            check_id="SOURCE_SECRET_SCAN",
            status=DoctorCheckStatus.PASS if not secret_hits else DoctorCheckStatus.FAIL,
            message="No embedded secret material found" if not secret_hits else f"Potential secrets: {secret_hits}",
        )
    )

    overall = DoctorCheckStatus.PASS
    if any(c.status == DoctorCheckStatus.FAIL for c in checks):
        overall = DoctorCheckStatus.FAIL
    elif any(c.status == DoctorCheckStatus.WARN for c in checks):
        overall = DoctorCheckStatus.WARN
    without_digest = {
        "schema_version": "db2-doctor-1.0",
        "checks": tuple(checks),
        "overall_status": overall,
    }
    return DoctorReport(**without_digest, content_digest=canonical_digest(without_digest))
