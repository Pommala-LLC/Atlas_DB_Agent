from .generate import handle as generate
from .pipeline import handle as pipeline
from .runtime import handle as runtime
from .tools import handle as tools

HANDLERS = (tools, runtime, generate, pipeline)
