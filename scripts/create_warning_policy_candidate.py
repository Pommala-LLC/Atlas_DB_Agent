from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a review-only readable-BDD warning policy candidate from a lint report."
    )
    parser.add_argument("lint_report", type=Path)
    parser.add_argument("--procedure", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    report = json.loads(args.lint_report.read_text(encoding="utf-8"))
    fingerprints = sorted(
        {
            str(issue["fingerprint"])
            for issue in report.get("issues", [])
            if issue.get("severity") == "WARNING"
        }
    )
    policy = {
        "schema_version": "readable-bdd-warning-policy-1.0",
        "mode": "REPORT_ONLY",
        "procedure": args.procedure,
        "baseline_fingerprints": fingerprints,
        "max_warning_count": len(fingerprints),
        "waivers": [],
        "review_state": "CANDIDATE_NOT_APPROVED",
    }
    # review_state is intentionally stripped because it is not part of the executable contract.
    executable = {key: value for key, value in policy.items() if key != "review_state"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(executable, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        "Created a REPORT_ONLY policy candidate. Review the fingerprints and change mode to "
        "NO_NEW_WARNINGS only after approval."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
