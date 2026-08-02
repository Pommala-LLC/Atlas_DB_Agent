from __future__ import annotations

import importlib.util
import json
import sys
import tomllib
from dataclasses import asdict, dataclass
from importlib import metadata
from pathlib import Path
from typing import Final

TEST_REQUIREMENTS: Final[dict[str, tuple[str, str]]] = {
    "pytest": ("pytest", "9.0.2"),
    "fastapi": ("fastapi", "0.128.2"),
    "uvicorn": ("uvicorn", "0.48.0"),
    "jinja2": ("jinja2", "3.1.6"),
    "python-multipart": ("multipart", "0.0.29"),
    "httpx": ("httpx", "0.28.1"),
    "PyJWT": ("jwt", "2.13.0"),
    "cryptography": ("cryptography", "46.0.4"),
    "gherkin-official": ("gherkin", "42.0.0"),
}
QUALITY_REQUIREMENTS: Final[dict[str, tuple[str, str]]] = {
    "ruff": ("ruff", "0.16.1"),
    "mypy": ("mypy", "2.3.0"),
}


@dataclass(frozen=True)
class DependencyProbe:
    distribution: str
    import_name: str
    required_version: str
    installed_version: str | None
    import_available: bool
    exact_version_match: bool

    @property
    def status(self) -> str:
        if not self.import_available or self.installed_version is None:
            return "MISSING"
        if not self.exact_version_match:
            return "VERSION_MISMATCH"
        return "PASS"


def _probe(requirements: dict[str, tuple[str, str]]) -> list[DependencyProbe]:
    result: list[DependencyProbe] = []
    for distribution, (import_name, required_version) in requirements.items():
        try:
            installed = metadata.version(distribution)
        except metadata.PackageNotFoundError:
            installed = None
        available = importlib.util.find_spec(import_name) is not None
        result.append(
            DependencyProbe(
                distribution=distribution,
                import_name=import_name,
                required_version=required_version,
                installed_version=installed,
                import_available=available,
                exact_version_match=installed == required_version,
            )
        )
    return result


def _declared_release_requirements(root: Path) -> list[str]:
    payload = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return list(payload["project"]["optional-dependencies"]["release"])


def build_environment_report(root: Path) -> dict[str, object]:
    test = _probe(TEST_REQUIREMENTS)
    quality = _probe(QUALITY_REQUIREMENTS)
    declared = _declared_release_requirements(root)
    test_complete = all(item.status == "PASS" for item in test)
    quality_complete = all(item.status == "PASS" for item in quality)
    return {
        "schema_version": "atlas-release-environment-1.0",
        "python_version": sys.version.split()[0],
        "declared_release_requirements": declared,
        "test_dependencies": [asdict(item) | {"status": item.status} for item in test],
        "quality_dependencies": [asdict(item) | {"status": item.status} for item in quality],
        "test_dependencies_complete": test_complete,
        "quality_dependencies_complete": quality_complete,
        "status": "PASS" if test_complete and quality_complete else "INCOMPLETE",
    }


def main(argv: list[str] | None = None) -> int:
    arguments = list(argv or sys.argv[1:])
    root = Path(arguments[0]).resolve() if arguments else Path.cwd().resolve()
    payload = build_environment_report(root)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
