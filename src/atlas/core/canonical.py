from __future__ import annotations

import hashlib
import json
from enum import Enum
from pathlib import Path
from typing import Any


def _normalize(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return _normalize(value.model_dump(mode="json", exclude_none=True))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_normalize(item) for item in value]
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(_normalize(value), ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()
