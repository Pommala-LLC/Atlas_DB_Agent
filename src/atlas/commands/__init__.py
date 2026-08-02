from .analyze import handle as analyze
from .info import handle as info
from .public_db2 import handle as public_db2
from .serve import handle as serve

HANDLERS = (info, analyze, public_db2, serve)
