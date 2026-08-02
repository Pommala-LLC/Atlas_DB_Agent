from __future__ import annotations

from ..adapter import UniversalProceduralAdapter
from .capabilities import CAPABILITIES
from .normalization import NORMALIZER
from .classifier import MySqlStatementClassifier
from .profile import PROFILE
from .semantics import MySqlSemanticPolicy


class MySqlStoredProgramAdapter(UniversalProceduralAdapter):
    capabilities = CAPABILITIES
    normalizer = NORMALIZER

    def __init__(self, atlas_version: str) -> None:
        super().__init__(PROFILE, atlas_version, classifier=MySqlStatementClassifier(), semantic_policy=MySqlSemanticPolicy(), normalizer=NORMALIZER)
