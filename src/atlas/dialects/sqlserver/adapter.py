from __future__ import annotations

from ..adapter import UniversalProceduralAdapter
from .capabilities import CAPABILITIES
from .normalization import NORMALIZER
from .classifier import SqlServerStatementClassifier
from .profile import PROFILE
from .semantics import SqlServerSemanticPolicy


class SqlServerTSqlAdapter(UniversalProceduralAdapter):
    capabilities = CAPABILITIES
    normalizer = NORMALIZER

    def __init__(self, atlas_version: str) -> None:
        super().__init__(PROFILE, atlas_version, classifier=SqlServerStatementClassifier(), semantic_policy=SqlServerSemanticPolicy(), normalizer=NORMALIZER)
