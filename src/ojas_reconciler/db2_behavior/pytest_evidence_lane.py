"""Deprecated compatibility wrapper for the Atlas isolated pytest lane."""
from atlas.pytest_evidence_lane import main

if __name__ == "__main__":
    raise SystemExit(main())
