from __future__ import annotations

from ..adapter import UniversalProceduralAdapter
from .capabilities import CAPABILITIES
from .normalization import NORMALIZER
from .classifier import Db2StatementClassifier
from .profile import PROFILE
from .semantics import Db2SemanticPolicy


class Db2SqlPlAdapter(UniversalProceduralAdapter):
    capabilities = CAPABILITIES
    normalizer = NORMALIZER

    def __init__(self, atlas_version: str) -> None:
        super().__init__(
            PROFILE,
            atlas_version,
            classifier=Db2StatementClassifier(),
            semantic_policy=Db2SemanticPolicy(),
            normalizer=NORMALIZER,
        )
