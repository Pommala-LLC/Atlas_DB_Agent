from __future__ import annotations

import base64
import json
import math
import unicodedata
from datetime import date, datetime, timezone
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class CanonicalJsonError(ValueError):
    """Raised when a value has no admitted canonical JSON representation."""


def _normalize_string(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _project(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _project(value.model_dump(mode="python"))
    if isinstance(value, Enum):
        return _project(value.value)
    if isinstance(value, Decimal):
        # Preserve exact decimal scale and exponent as semantic data.
        return {"$decimal": str(value)}
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise CanonicalJsonError("Naive datetime is not canonical.")
        utc = value.astimezone(timezone.utc)
        text = utc.isoformat(timespec="microseconds").replace("+00:00", "Z")
        return {"$datetime": text}
    if isinstance(value, date):
        return {"$date": value.isoformat()}
    if isinstance(value, Path):
        return {"$path": value.as_posix()}
    if isinstance(value, bytes):
        return {"$bytes": base64.b64encode(value).decode("ascii")}
    if isinstance(value, str):
        return _normalize_string(value)
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalJsonError("NaN and Infinity are not canonical.")
        # Floats are allowed only for non-DB2 measurement metadata.
        return value
    if isinstance(value, dict):
        projected: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJsonError("Canonical JSON object keys must be strings.")
            normalized_key = _normalize_string(key)
            if normalized_key in projected:
                raise CanonicalJsonError(f"Duplicate key after Unicode normalization: {key!r}")
            projected[normalized_key] = _project(item)
        return projected
    if isinstance(value, (list, tuple)):
        return [_project(item) for item in value]
    if isinstance(value, (set, frozenset)):
        items = [_project(item) for item in value]
        return sorted(items, key=lambda item: canonical_json_bytes(item))
    raise CanonicalJsonError(f"Unsupported canonical JSON type: {type(value).__qualname__}")


def canonical_json_bytes(value: Any) -> bytes:
    projected = _project(value)
    text = json.dumps(
        projected,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return text.encode("utf-8")


def canonical_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_json_bytes(value)).hexdigest()
