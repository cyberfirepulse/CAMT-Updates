@echo off
setlocal
cd /d "%~dp0"

echo ================================================================
echo CAMT Professional Edition 1.2.0 Beta 10
echo Runtime Import Hardening - PyInstaller Build
echo ================================================================
echo.

echo [1/6] Runtime dependencies installeren...
python -m pip install -r requirements-runtime.txt
if errorlevel 1 goto :fail

echo.
echo [2/6] Runtime Import Preflight uitvoeren...
python runtime_import_preflight.py
if errorlevel 1 goto :fail

echo.
echo [3/6] NL/EN i18n resources en UI-dekking controleren...
python i18n_audit.py --strict
if errorlevel 1 goto :fail

echo.
echo [4/6] Release Readiness controleren...
python release_readiness.py
if errorlevel 1 goto :fail

echo.
echo [5/6] PyInstaller controleren/installeren...
python -m pip install --upgrade pyinstaller
if errorlevel 1 goto :fail

echo.
echo [6/6] Runtime-only distributie bouwen...
python -m PyInstaller --noconfirm --clean CAMT_B5.spec
if errorlevel 1 goto :fail

echo.
echo PyInstaller inhoud controleren...
set "ANALYSIS_TOC="
for /f "delims=" %%F in ('dir /b /s "build\Analysis-00.toc" 2^>nul') do set "ANALYSIS_TOC=%%~fF"
if not defined ANALYSIS_TOC (
    echo [FAIL] Geen bestaand PyInstaller Analysis-00.toc gevonden onder build\
    goto :fail
)
if not exist "%ANALYSIS_TOC%" (
    echo [FAIL] PyInstaller Analysis TOC pad bestaat niet: %ANALYSIS_TOC%
    goto :fail
)
echo [ OK ] Analysis TOC gevonden: %ANALYSIS_TOC%
python runtime_import_preflight.py --analysis-toc "%ANALYSIS_TOC%"
if errorlevel 1 goto :fail

echo.
echo ================================================================
echo Build gereed:
echo   dist\CAMT\CAMT.exe
echo.
echo Runtime hardening actief:
echo   - Scapy + Requests ingebouwd
echo   - tkinter.scrolledtext en overige dynamic imports expliciet
echo   - NDT dynamic-loader preflight
echo   - Windows/Linux subprocess hardening
echo   - PyInstaller Analysis TOC nacontrole
echo   - Centrale NL/EN i18n registry + runtime UI translation
echo   - Module Framework language/locale context
echo   - i18n audit voor iedere release-build
echo ================================================================
goto :eof

:fail
echo.
echo BUILD AFGEBROKEN - Runtime Import Preflight/Readiness/buildcontrole faalde.
exit /b 1

