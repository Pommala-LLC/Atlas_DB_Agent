"""Atlas: modular stored-routine behavior intelligence across database dialects."""

from .application import AtlasSemanticService, AtlasSourceUnitService
from .core.models import DialectId
from .naming import POLICY

__version__ = "2.0.0rc5"
__all__ = ["AtlasSemanticService", "AtlasSourceUnitService", "DialectId", "POLICY", "__version__"]
