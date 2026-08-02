from pathlib import Path
import json

from jsonschema import validate

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.testkit.models import (
    BddTestCatalog,
    BddTestPackageManifest,
    ExecutionMode,
    ProcedureTestContract,
)

ROOT = Path(__file__).parents[1]


def _schema(name: str) -> dict:
    return json.loads((ROOT / "contracts" / name).read_text(encoding="utf-8"))


def test_bdd_test_package_schema_accepts_canonical_manifest() -> None:
    payload = {
        "schema_version": "bdd-test-package-manifest-1.0",
        "package_id": "sample",
        "package_version": "1.0.0",
        "source_procedure": "SAMPLE.PROC",
        "source_file": "procedure.sql",
        "source_digest": "sha256:" + "1" * 64,
        "execution_mode": ExecutionMode.SCRIPTED_MODEL,
        "adapter_factory": "sample.adapter:create_adapter",
        "feature_files": ("features/sample.feature",),
        "test_cases_file": "specs/test-cases.json",
        "dataset_files": ("data/ds.json",),
        "procedure_contract_file": "data/procedure-contract.json",
        "catalog_file": "data/catalog.json",
        "metadata_files": (),
        "generated_by": "test",
    }
    model = BddTestPackageManifest(**payload, content_digest=canonical_digest(payload))
    validate(model.model_dump(mode="json"), _schema("bdd-test-package-manifest-1.0.schema.json"))


def test_empty_catalog_and_contract_schemas_are_structurally_valid() -> None:
    catalog_payload = {
        "schema_version": "bdd-test-catalog-1.0",
        "provider_ref": "EMPTY",
        "relations": (),
    }
    catalog = BddTestCatalog(**catalog_payload, content_digest=canonical_digest(catalog_payload))
    validate(catalog.model_dump(mode="json"), _schema("bdd-test-catalog-1.0.schema.json"))

    # The contract model itself enforces parameter type/mode key equality; the
    # empty form is admitted for a no-parameter procedure.
    contract_payload = {
        "schema_version": "procedure-test-contract-1.0",
        "procedure_schema": "SAMPLE",
        "procedure_name": "NO_ARGS",
        "parameter_types": {},
        "parameter_modes": {},
    }
    contract = ProcedureTestContract(**contract_payload, content_digest=canonical_digest(contract_payload))
    validate(contract.model_dump(mode="json"), _schema("procedure-test-contract-1.0.schema.json"))
