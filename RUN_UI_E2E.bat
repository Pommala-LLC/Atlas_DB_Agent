@echo off
setlocal
cd /d "%~dp0"
call scripts\resolve_python.bat || exit /b 1
"%PYTHON_EXE%" -m pytest -q tests\test_procedure_analysis_ui_e2e.py
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" echo Procedure UI E2E tests failed with exit code %RC%.
exit /b %RC%
