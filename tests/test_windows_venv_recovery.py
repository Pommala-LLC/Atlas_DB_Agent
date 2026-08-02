from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_build_detects_deep_pip_corruption_and_recreates_venv() -> None:
    script = (ROOT / "build.bat").read_text(encoding="utf-8")
    assert "pip._internal.commands.install" in script
    assert "pip._vendor.urllib3.exceptions" in script
    assert 'rmdir /s /q "!VENV_DIR!"' in script
    assert "venv --clear --without-pip" in script
    assert "ensurepip --upgrade --default-pip" in script
    assert "Pip bootstrap validation failed" in script


def test_build_is_safe_for_parenthesized_install_paths() -> None:
    script = (ROOT / "build.bat").read_text(encoding="utf-8")
    assert "EnableDelayedExpansion" in script
    assert "echo Recreating only: !VENV_DIR!" in script
    assert 'if exist "!VENV_DIR!" (' in script
    assert "%VENV_DIR%" not in script
    assert "%VENV_PY%" not in script


def test_console_checks_runtime_and_pip_before_reusing_venv() -> None:
    script = (ROOT / "ATLAS_CONSOLE.bat").read_text(encoding="utf-8")
    assert "import atlas, fastapi, uvicorn, jinja2" in script
    assert "pip._internal.commands.install" in script
    assert "pip._vendor.urllib3.exceptions" in script
    assert 'call "!APP_ROOT!build.bat"' in script
    assert "EnableDelayedExpansion" in script
    assert "%PYTHON_EXE%" not in script


def test_console_trusts_the_atlas_loopback_urls_by_default() -> None:
    script = (ROOT / "ATLAS_CONSOLE.bat").read_text(encoding="utf-8")
    assert "ATLAS_UI_ALLOWED_ORIGINS" in script
    assert "http://127.0.0.1:8765" in script
    assert "http://localhost:8765" in script
    assert "http://[::1]:8765" in script
