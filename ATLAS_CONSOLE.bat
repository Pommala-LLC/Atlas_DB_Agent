@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "APP_ROOT=%~dp0"
set "PYTHON_EXE=%~dp0.venv\Scripts\python.exe"

set "NEEDS_BUILD=0"
if not exist "!PYTHON_EXE!" set "NEEDS_BUILD=1"
if "!NEEDS_BUILD!"=="0" (
  "!PYTHON_EXE!" -c "import atlas, fastapi, uvicorn, jinja2; import pip._internal.commands.install; import pip._vendor.urllib3.exceptions" >nul 2>nul
  if errorlevel 1 set "NEEDS_BUILD=1"
)
if "!NEEDS_BUILD!"=="1" call "!APP_ROOT!build.bat"
if errorlevel 1 exit /b !ERRORLEVEL!

if not defined ATLAS_UI_WORKSPACE set "ATLAS_UI_WORKSPACE=!APP_ROOT!reports\atlas"
if not defined ATLAS_UI_TENANT set "ATLAS_UI_TENANT=tenant:local"
if not defined ATLAS_UI_ACTOR set "ATLAS_UI_ACTOR=actor:local-admin"
if not defined ATLAS_UI_ROLE set "ATLAS_UI_ROLE=ADMIN"
if not defined ATLAS_UI_ALLOWED_ORIGINS set "ATLAS_UI_ALLOWED_ORIGINS=http://127.0.0.1:8765,http://localhost:8765,http://[::1]:8765"
set "PYTHONPATH=!APP_ROOT!src;!PYTHONPATH!"
"!PYTHON_EXE!" -m atlas serve --host 127.0.0.1 --port 8765 --workspace "!ATLAS_UI_WORKSPACE!" --tenant-ref "!ATLAS_UI_TENANT!" --actor-ref "!ATLAS_UI_ACTOR!" --role "!ATLAS_UI_ROLE!"
endlocal
