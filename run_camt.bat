@echo off
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
echo CAMT startup diagnostics
echo ========================
python --version
echo.
python -m projectmanager %* 2>camt_startup_error.log
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo ========================
  echo CAMT stopped with exit code %RC%.
  echo Error log:
  type camt_startup_error.log
  echo.
  echo Logbestand: %~dp0camt_startup_error.log
  pause
)
exit /b %RC%
