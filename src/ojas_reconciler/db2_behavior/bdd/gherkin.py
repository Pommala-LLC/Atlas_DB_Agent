from __future__ import annotations

import hashlib
import unicodedata


class GherkinCanonicalizationError(ValueError):
    """Raised when Gherkin text cannot be canonicalized safely."""


def canonical_gherkin_text(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip(" \t") for line in normalized.split("\n")]
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise GherkinCanonicalizationError("Gherkin artifact cannot be empty.")
    if any("\x00" in line for line in lines):
        raise GherkinCanonicalizationError("Gherkin artifact contains a NUL character.")
    return "\n".join(lines) + "\n"


def gherkin_digest(value: str) -> str:
    canonical = canonical_gherkin_text(value)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
