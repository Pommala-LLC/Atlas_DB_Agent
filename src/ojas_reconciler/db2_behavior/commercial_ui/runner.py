"""Legacy console entry point delegated to the canonical Atlas web runner."""
from atlas.web.runner import main

__all__ = ["main"]

if __name__ == "__main__":
    raise SystemExit(main())
