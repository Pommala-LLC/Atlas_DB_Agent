@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "APP_ROOT=%~dp0"
set "VENV_DIR=%~dp0.venv"
set "VENV_PY=%~dp0.venv\Scripts\python.exe"
pushd "%~dp0"

call "%~dp0scripts\resolve_python.bat"
if errorlevel 1 goto :fail

set "RECREATE_VENV=0"
if exist "!VENV_PY!" (
  "!VENV_PY!" -c "import sys; raise SystemExit(0 if (3,13) <= sys.version_info[:2] < (3,15) else 1)" >nul 2>nul
  if errorlevel 1 set "RECREATE_VENV=1"

  if "!RECREATE_VENV!"=="0" (
    call :check_pip
    if errorlevel 1 set "RECREATE_VENV=1"
  )
)

if "!RECREATE_VENV!"=="1" (
  echo Existing .venv is incompatible or its pip installation is incomplete.
  echo Recreating only: !VENV_DIR!
  if exist "!VENV_DIR!" rmdir /s /q "!VENV_DIR!"
  if exist "!VENV_DIR!" (
    echo ERROR: Could not remove the damaged .venv. Close any Atlas or Python process using it, then rerun build.bat.
    goto :fail
  )
)

if not exist "!VENV_PY!" call :create_venv
if errorlevel 1 goto :fail

call :check_pip
if errorlevel 1 (
  echo Pip bootstrap validation failed. Recreating the virtual environment once more...
  if exist "!VENV_DIR!" rmdir /s /q "!VENV_DIR!"
  call :create_venv
  if errorlevel 1 goto :fail
  call :check_pip
  if errorlevel 1 (
    echo ERROR: pip remains incomplete after a clean bootstrap.
    echo Check antivirus or endpoint-security quarantine history for files under:
    echo   !VENV_DIR!\Lib\site-packages\pip\_vendor
    goto :fail
  )
)

"!VENV_PY!" -m pip --version
set "CONSTRAINT_FILE=!APP_ROOT!constraints.txt"
if exist "!CONSTRAINT_FILE!" (
  echo Installing with pinned release constraints: !CONSTRAINT_FILE!
  "!VENV_PY!" -m pip install -e ".[release]" -c "!CONSTRAINT_FILE!"
) else (
  echo WARNING: constraints.txt was not found. Installing the declared release extras without an external constraint file.
  "!VENV_PY!" -m pip install -e ".[release]"
)
if errorlevel 1 goto :fail

"!VENV_PY!" -c "import atlas, fastapi, uvicorn, jinja2; print('Atlas runtime imports verified.')"
if errorlevel 1 goto :fail

"!VENV_PY!" "!APP_ROOT!scripts\write_test_evidence.py" --output "!APP_ROOT!reports\atlas-2.0.0rc5\pytest-release-evidence.json"
set "RC=!ERRORLEVEL!"
popd
endlocal & exit /b %RC%

:check_pip
if not exist "!VENV_PY!" exit /b 1
"!VENV_PY!" -c "import pip; import pip._internal.commands.install; import pip._vendor.requests; import pip._vendor.urllib3.exceptions" >nul 2>nul
if errorlevel 1 exit /b 1
"!VENV_PY!" -m pip --version >nul 2>nul
exit /b !ERRORLEVEL!

:create_venv
!ATLAS_PYTHON! -m venv --clear --without-pip "!VENV_DIR!"
if errorlevel 1 exit /b 1
"!VENV_PY!" -m ensurepip --upgrade --default-pip
if errorlevel 1 exit /b 1
exit /b 0

:fail
set "RC=!ERRORLEVEL!"
if "!RC!"=="0" set "RC=1"
popd
endlocal & exit /b %RC%
