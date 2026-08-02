from __future__ import annotations

from ..adapter import UniversalProceduralAdapter
from .capabilities import CAPABILITIES
from .normalization import NORMALIZER
from .classifier import OracleStatementClassifier
from .profile import PROFILE
from .semantics import OracleSemanticPolicy


class OraclePlSqlAdapter(UniversalProceduralAdapter):
    capabilities = CAPABILITIES
    normalizer = NORMALIZER

    def __init__(self, atlas_version: str) -> None:
        super().__init__(
            PROFILE,
            atlas_version,
            classifier=OracleStatementClassifier(),
            semantic_policy=OracleSemanticPolicy(),
            normalizer=NORMALIZER,
        )
