"""Optional commercial web console.

The core analyzer does not import the web stack. Callers that need the UI must
install the `ui` extra.
"""
from __future__ import annotations

from typing import Any


def create_app(*args: Any, **kwargs: Any):
    try:
        from .app import create_app as implementation
    except ModuleNotFoundError as exc:
        if exc.name in {"fastapi", "starlette", "jinja2", "multipart", "uvicorn"}:
            raise RuntimeError(
                "UI_EXTRA_REQUIRED: install atlas-procedure-intelligence[ui]."
            ) from exc
        raise
    return implementation(*args, **kwargs)


def __getattr__(name: str):
    if name == "CommercialUiSettings":
        try:
            from .app import CommercialUiSettings
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "UI_EXTRA_REQUIRED: install atlas-procedure-intelligence[ui]."
            ) from exc
        return CommercialUiSettings
    raise AttributeError(name)


__all__ = ["CommercialUiSettings", "create_app"]
