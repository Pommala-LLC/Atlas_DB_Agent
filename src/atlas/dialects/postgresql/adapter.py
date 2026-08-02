from __future__ import annotations

from ..adapter import UniversalProceduralAdapter
from .capabilities import CAPABILITIES
from .normalization import NORMALIZER
from .classifier import PostgreSqlStatementClassifier
from .profile import PROFILE
from .semantics import PostgreSqlSemanticPolicy


class PostgreSqlPlPgSqlAdapter(UniversalProceduralAdapter):
    capabilities = CAPABILITIES
    normalizer = NORMALIZER

    def __init__(self, atlas_version: str) -> None:
        super().__init__(PROFILE, atlas_version, classifier=PostgreSqlStatementClassifier(), semantic_policy=PostgreSqlSemanticPolicy(), normalizer=NORMALIZER)
