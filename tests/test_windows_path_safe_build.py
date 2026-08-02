from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_release_constraints_use_short_top_level_path() -> None:
    assert (ROOT / "constraints.txt").is_file()
    assert not (ROOT / "requirements" / "release-constraints.txt").exists()


def test_build_batch_uses_optional_constraint_fallback() -> None:
    text = (ROOT / "build.bat").read_text(encoding="utf-8")
    assert 'set "CONSTRAINT_FILE=!APP_ROOT!constraints.txt"' in text
    assert 'if exist "!CONSTRAINT_FILE!"' in text
    assert '"!VENV_PY!" -m pip install -e ".[release]" -c "!CONSTRAINT_FILE!"' in text
    assert '"!VENV_PY!" -m pip install -e ".[release]"' in text
    assert "requirements\\release-constraints.txt" not in text
    assert "pip install --upgrade pip" not in text
    assert '"!VENV_PY!" -m pip --version' in text
    assert '"!VENV_PY!" -m ensurepip --upgrade --default-pip' in text


def test_distribution_root_name_is_windows_path_safe() -> None:
    # The shipped source archive uses this short root directory name.
    assert ROOT.name == "atlas-procedure-ui"
    longest_relative = max(
        (str(path.relative_to(ROOT)) for path in ROOT.rglob("*") if path.is_file()),
        key=len,
    )
    # Even beneath a moderately deep plugin directory, the source layout should
    # leave useful headroom below the traditional 260-character Windows limit.
    example_parent = r"E:\Agentic AI\spring-boot-language-server\sts-5.2.0.RELEASE\dropins\ojas\plugins"
    assert len(example_parent + "\\atlas-procedure-ui\\" + longest_relative) < 260
