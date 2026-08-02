from __future__ import annotations

import re
from dataclasses import dataclass, field

from atlas.core.models import DialectId


@dataclass(frozen=True, slots=True)
class DialectNormalizer:
    """Dialect-owned canonicalization rules used at parser boundaries.

    Raw source remains on every semantic node. Canonical keys preserve quoted
    identifier spelling and delimiters so a quoted name never aliases an
    unquoted, server-folded name (most importantly in PostgreSQL).
    """

    dialect: DialectId
    quote_pairs: tuple[tuple[str, str], ...]
    unquoted_server_case: str
    canonical_case: str = "UPPER"
    type_aliases: dict[str, str] = field(default_factory=dict)

    def normalize_identifier(self, value: str) -> str:
        parts = self._split_qualified(value.strip())
        normalized = [self._normalize_identifier_part(part) for part in parts]
        return ".".join(part for part in normalized if part)

    def normalize_variable(self, value: str) -> str:
        return self.normalize_identifier(value.strip().lstrip("@:"))

    def normalize_type(self, value: str) -> str:
        compact = re.sub(r"\s+", " ", value.strip()).upper()
        # Alias the scalar base while retaining precision, array dimensions,
        # and other suffixes.  INT[] must therefore normalize to INTEGER[],
        # not remain a distinct pseudo-type.
        match = re.match(r"^(.*?)(?=\s*\(|\[\]|$)", compact)
        base = match.group(1).strip() if match else compact
        replacement = self.type_aliases.get(base)
        if replacement:
            compact = replacement + compact[len(base) :]
        return compact

    def is_quoted(self, value: str) -> bool:
        clean = value.strip()
        return any(
            clean.startswith(left)
            and clean.endswith(right)
            and len(clean) >= len(left) + len(right)
            for left, right in self.quote_pairs
        )

    def _normalize_identifier_part(self, value: str) -> str:
        clean = value.strip()
        for left, right in self.quote_pairs:
            if clean.startswith(left) and clean.endswith(right) and len(clean) >= len(left) + len(right):
                inner = clean[len(left) : len(clean) - len(right)]
                # Preserve delimiter and spelling. This is the canonical marker
                # that distinguishes quoted identifiers from folded names.
                return f"{left}{inner}{right}"
        if self.unquoted_server_case == "UPPER":
            return clean.upper()
        if self.unquoted_server_case == "LOWER":
            return clean.lower()
        if self.canonical_case == "LOWER":
            return clean.lower()
        if self.canonical_case == "PRESERVE":
            return clean
        return clean.upper()

    @staticmethod
    def _split_qualified(value: str) -> tuple[str, ...]:
        parts: list[str] = []
        current: list[str] = []
        quote_end: str | None = None
        quote_pairs = {'"': '"', '`': '`', '[': ']'}
        for char in value:
            if quote_end:
                current.append(char)
                if char == quote_end:
                    quote_end = None
                continue
            if char in quote_pairs:
                quote_end = quote_pairs[char]
                current.append(char)
            elif char == '.':
                parts.append(''.join(current))
                current = []
            else:
                current.append(char)
        parts.append(''.join(current))
        return tuple(parts)
