@echo off
rem Install the angr-backed decompiler into a Ghidra installation (Windows).
rem
rem Builds the native launcher, drops it in as Ghidra's decompile.exe (backing
rem up the original), and writes the config next to it. Re-runnable and
rem reversible (--uninstall).
rem
rem   install.bat --ghidra C:\path\to\ghidra [--python C:\...\python.exe | --venv DIR]
rem
rem Run install.bat --help for all options.
rem
rem NB: intentionally label-driven rather than using ( ) command blocks, so that
rem paths containing ')' (e.g. under "Program Files (x86)") can't break parsing.
setlocal

set "REPO=%~dp0"
if "%REPO:~-1%"=="\" set "REPO=%REPO:~0,-1%"
set "LAUNCHER_DIR=%REPO%\launcher"
set "CORE=%REPO%\bin\angr-decompile"

set "GHIDRA="
set "PYTHON="
set "VENV="
set "SERVER=0"
set "UNINSTALL=0"

:parse
if "%~1"=="" goto parsed
if /I "%~1"=="--ghidra"    goto p_ghidra
if /I "%~1"=="--python"    goto p_python
if /I "%~1"=="--venv"      goto p_venv
if /I "%~1"=="--server"    goto p_server
if /I "%~1"=="--uninstall" goto p_uninstall
if /I "%~1"=="--help"      goto usage
if /I "%~1"=="-h"          goto usage
if /I "%~1"=="/?"          goto usage
echo error: unknown option %~1  (see --help)
exit /b 1
:p_ghidra
set "GHIDRA=%~2"
shift & shift & goto parse
:p_python
set "PYTHON=%~2"
shift & shift & goto parse
:p_venv
set "VENV=%~2"
shift & shift & goto parse
:p_server
set "SERVER=1"
shift & goto parse
:p_uninstall
set "UNINSTALL=1"
shift & goto parse
:parsed

rem ---- locate Ghidra ------------------------------------------------------
if not defined GHIDRA if defined GHIDRA_INSTALL_DIR set "GHIDRA=%GHIDRA_INSTALL_DIR%"
if not defined GHIDRA goto no_ghidra
if not exist "%GHIDRA%\support\analyzeHeadless.bat" goto bad_ghidra

rem ---- platform os-dir ----------------------------------------------------
set "OSNAME=win_x86_64"
if /I "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "OSNAME=win_arm_64"
set "OSDIR=%GHIDRA%\Ghidra\Features\Decompiler\os\%OSNAME%"
if not exist "%OSDIR%" goto no_osdir
set "TARGET=%OSDIR%\decompile.exe"
set "BACKUP=%OSDIR%\decompile.orig.exe"
set "CONF=%OSDIR%\angr-decompile.conf"

echo ==^> Ghidra:   %GHIDRA%
echo ==^> Platform: %OSNAME%

if "%UNINSTALL%"=="1" goto uninstall

rem ---- resolve Python -----------------------------------------------------
if defined VENV goto make_venv
if defined PYTHON goto have_python
for /f "delims=" %%i in ('where python 2^>nul') do if not defined PYTHON set "PYTHON=%%i"
if not defined PYTHON goto no_python
goto have_python

:make_venv
where python >nul 2>&1 || goto no_python_for_venv
echo ==^> Creating virtualenv at %VENV% and installing angr, pypcode, cle (this can take a while)...
python -m venv "%VENV%" || goto venv_failed
"%VENV%\Scripts\python.exe" -m pip install --upgrade pip
"%VENV%\Scripts\python.exe" -m pip install angr pypcode cle || goto pip_failed
set "PYTHON=%VENV%\Scripts\python.exe"

:have_python
"%PYTHON%" -c "import angr, pypcode, cle" >nul 2>&1
if errorlevel 1 goto bad_python
echo   ok Python:   %PYTHON%

rem ---- build the launcher -------------------------------------------------
where cargo >nul 2>&1 || goto no_cargo
echo ==^> Building the launcher...
cargo build --release --quiet --manifest-path "%LAUNCHER_DIR%\Cargo.toml" || goto build_failed
set "BUILT=%LAUNCHER_DIR%\target\release\decompile.exe"
if not exist "%BUILT%" goto build_failed
echo   ok built launcher

rem ---- back up + install --------------------------------------------------
if exist "%BACKUP%" goto skip_backup
if not exist "%TARGET%" goto skip_backup
copy /Y "%TARGET%" "%BACKUP%" >nul
echo   ok backed up original -^> %BACKUP%
:skip_backup
copy /Y "%BUILT%" "%TARGET%" >nul
echo   ok installed launcher -^> %TARGET%

rem ---- write config -------------------------------------------------------
 > "%CONF%" echo # Written by install.bat. Edit as needed; env vars override these.
>> "%CONF%" echo python     = %PYTHON%
>> "%CONF%" echo core       = %CORE%
>> "%CONF%" echo pythonpath = %REPO%
if exist "%BACKUP%"    >> "%CONF%" echo fallback   = %BACKUP%
if "%SERVER%"=="1"     >> "%CONF%" echo server     = 1
if not "%SERVER%"=="1" >> "%CONF%" echo # server   = 1   uncomment for the faster shared-server mode
echo   ok wrote config -^> %CONF%

echo ==^> Done. Restart Ghidra to use the angr decompiler.
echo ==^> To revert:  install.bat --ghidra "%GHIDRA%" --uninstall
exit /b 0

:uninstall
if not exist "%BACKUP%" goto uninstall_nobackup
move /Y "%BACKUP%" "%TARGET%" >nul
echo   ok restored original decompiler
goto uninstall_conf
:uninstall_nobackup
echo warn: no backup (%BACKUP%) found; leaving %TARGET% as-is
:uninstall_conf
if exist "%CONF%" del /Q "%CONF%"
if not exist "%CONF%" echo   ok removed config
echo ==^> Uninstalled.
exit /b 0

:no_ghidra
echo error: could not find Ghidra. Pass --ghidra C:\path\to\ghidra or set GHIDRA_INSTALL_DIR.
exit /b 1
:bad_ghidra
echo error: "%GHIDRA%" does not look like a Ghidra install (no support\analyzeHeadless.bat).
exit /b 1
:no_osdir
echo error: Ghidra has no decompiler dir for this platform: %OSDIR%
exit /b 1
:no_python
echo error: no Python found. Use --python C:\...\python.exe or --venv DIR.
exit /b 1
:no_python_for_venv
echo error: python not found (needed to create the venv).
exit /b 1
:venv_failed
echo error: virtualenv creation failed.
exit /b 1
:pip_failed
echo error: pip install of angr/pypcode/cle failed.
exit /b 1
:bad_python
echo error: "%PYTHON%" cannot import angr/pypcode/cle. Fix it, or use --venv DIR.
exit /b 1
:no_cargo
echo error: cargo (Rust) not found. Install Rust from https://rustup.rs and re-run.
exit /b 1
:build_failed
echo error: launcher build failed.
exit /b 1

:usage
echo Install the angr decompiler into a Ghidra installation.
echo.
echo Usage: install.bat [options]
echo.
echo   --ghidra DIR     Ghidra installation directory (contains support\ and Ghidra\).
echo                    Falls back to %%GHIDRA_INSTALL_DIR%%.
echo   --python PATH    Python interpreter that already has angr, pypcode and cle.
echo   --venv DIR       Create a fresh virtualenv at DIR and pip install
echo                    angr/pypcode/cle into it (use instead of --python).
echo   --server         Enable server mode (shared long-lived angr process; faster).
echo   --uninstall      Restore the original Ghidra decompiler and remove the config.
echo   -h, --help       This message.
echo.
echo Requires: a Rust toolchain (cargo) to build the launcher.
exit /b 0
