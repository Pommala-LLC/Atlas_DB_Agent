@echo off
setlocal EnableExtensions
set "_PYTHON_CMD="

rem Prefer the Windows Python launcher. "py -3" selects the newest installed
rem Python 3 and avoids hard-coding a minor version such as 3.13.
where py >nul 2>nul
if not errorlevel 1 (
  py -3 -c "import sys; raise SystemExit(0 if (3,13) <= sys.version_info[:2] < (3,15) else 1)" >nul 2>nul
  if not errorlevel 1 set "_PYTHON_CMD=py -3"
)

if not defined _PYTHON_CMD (
  where python >nul 2>nul
  if not errorlevel 1 (
    python -c "import sys; raise SystemExit(0 if (3,13) <= sys.version_info[:2] < (3,15) else 1)" >nul 2>nul
    if not errorlevel 1 set "_PYTHON_CMD=python"
  )
)

if not defined _PYTHON_CMD (
  where python3 >nul 2>nul
  if not errorlevel 1 (
    python3 -c "import sys; raise SystemExit(0 if (3,13) <= sys.version_info[:2] < (3,15) else 1)" >nul 2>nul
    if not errorlevel 1 set "_PYTHON_CMD=python3"
  )
)

if not defined _PYTHON_CMD (
  echo ERROR: A supported Python runtime was not found.
  echo.
  echo Supported versions: Python 3.13 and Python 3.14.
  echo Run "py -0p" to see the Python versions installed on this computer.
  echo Download Python from https://www.python.org/downloads/ if none is installed.
  endlocal & exit /b 3
)

for /f "delims=" %%V in ('%_PYTHON_CMD% -c "import sys; print(sys.executable + ' ^(' + '.'.join(map(str, sys.version_info[:3])) + '^)')"') do set "_PYTHON_DESCRIPTION=%%V"
echo Using Python: %_PYTHON_DESCRIPTION%

endlocal & set "ATLAS_PYTHON=%_PYTHON_CMD%" & exit /b 0
