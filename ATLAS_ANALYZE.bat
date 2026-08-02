@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "APP_ROOT=%~dp0"
set "SOURCE=%~1"
set "DIALECT=%~2"
set "OUTPUT=%~3"
set "PAUSE_AT_END=0"

if not defined SOURCE (
  set "PAUSE_AT_END=1"
  for /f "usebackq delims=" %%I in (`powershell -NoProfile -ExecutionPolicy Bypass -Command "Add-Type -AssemblyName System.Windows.Forms; $d=New-Object System.Windows.Forms.OpenFileDialog; $d.Filter='SQL routine (*.sql)|*.sql|All files (*.*)|*.*'; $d.Title='Choose a stored routine'; if($d.ShowDialog() -eq 'OK'){[Console]::Write($d.FileName)}"`) do set "SOURCE=%%I"
)
if not defined SOURCE exit /b 2
for %%I in ("%SOURCE%") do set "SOURCE=%%~fI"
if not exist "%SOURCE%" (
  echo SOURCE_NOT_FOUND: %SOURCE%
  exit /b 2
)
if not defined DIALECT (
  echo Select dialect:
  echo   1. Db2 SQL PL
  echo   2. Oracle PL/SQL
  echo   3. SQL Server T-SQL
  echo   4. PostgreSQL PL/pgSQL
  echo   5. MySQL stored programs
  set /p "CHOICE=Choice [1-5]: "
  if "!CHOICE!"=="1" set "DIALECT=db2"
  if "!CHOICE!"=="2" set "DIALECT=oracle"
  if "!CHOICE!"=="3" set "DIALECT=sqlserver"
  if "!CHOICE!"=="4" set "DIALECT=postgresql"
  if "!CHOICE!"=="5" set "DIALECT=mysql"
)
if not defined DIALECT (
  echo DIALECT_REQUIRED
  exit /b 2
)
if not defined OUTPUT for %%I in ("%SOURCE%") do set "OUTPUT=%%~dpnI-atlas-output"

set "PYTHON_EXE=%APP_ROOT%.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" call "%APP_ROOT%build.bat"
if errorlevel 1 exit /b %ERRORLEVEL%

"%PYTHON_EXE%" -m atlas analyze "%SOURCE%" --dialect "%DIALECT%" --output "%OUTPUT%" --emit-gherkin --emit-graph
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" start "" explorer.exe "%OUTPUT%"
if "%PAUSE_AT_END%"=="1" pause
exit /b %RC%
