from __future__ import annotations

from pathlib import Path

from ojas_reconciler.db2_behavior.core.canonical_json import canonical_digest
from ojas_reconciler.db2_behavior.analysis.models import CallerTransactionContract


def load_caller_transaction_contract(path: Path | None) -> CallerTransactionContract | None:
    if path is None:
        return None
    contract = CallerTransactionContract.model_validate_json(path.read_text(encoding="utf-8"))
    payload = contract.model_dump(mode="python", exclude={"content_digest"})
    expected = canonical_digest(payload)
    if expected != contract.content_digest:
        raise ValueError(
            f"Invalid caller transaction contract digest: expected {expected}, got {contract.content_digest}"
        )
    return contract
