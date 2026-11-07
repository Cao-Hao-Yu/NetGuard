@echo off
setlocal EnableExtensions
chcp 65001 >nul

rem ============================================================
rem  NetGuard install script (Windows 10/11)
rem  Everything (python env / browsers / logs) stays in this folder.
rem  Edit config.json after install, then see README.md.
rem ============================================================

set "TOOL_DIR=%~dp0"
set "ENV_DIR=%TOOL_DIR%env"
set "BROWSER_DIR=%TOOL_DIR%browsers"
set "TASK_NAME=NetGuard"

rem ---------- find conda (optional); fallback: py launcher venv ----------
set "CONDAEXE="
where conda >nul 2>nul && set "CONDAEXE=conda"
if not defined CONDAEXE (
    for %%P in ("%USERPROFILE%\anaconda3\Scripts\conda.exe" "%USERPROFILE%\miniconda3\Scripts\conda.exe" "%ProgramData%\Anaconda3\Scripts\conda.exe" "%ProgramData%\miniconda3\Scripts\conda.exe") do (
        if exist %%P set "CONDAEXE=%%~P"
    )
)

if defined CONDAEXE goto :conda
echo conda not found, falling back to "py" launcher (needs Python 3.9+) ...
where py >nul 2>nul || goto :nopython
py -3 -m venv "%ENV_DIR%" || goto :fail
set "PYEXE=%ENV_DIR%\Scripts\python.exe"
goto :deps

:conda
echo [1/4] Creating python env at "%ENV_DIR%" ...
"%CONDAEXE%" create -p "%ENV_DIR%" python=3.11 -y || goto :fail
set "PYEXE=%ENV_DIR%\python.exe"

:deps
echo [2/4] Installing pip packages ...
"%PYEXE%" -m pip install --upgrade pip
"%PYEXE%" -m pip install -r "%TOOL_DIR%requirements.txt"
if errorlevel 1 (
    echo Retry pip install with Tsinghua mirror ...
    "%PYEXE%" -m pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r "%TOOL_DIR%requirements.txt" || goto :fail
)

echo [3/4] Installing Chromium into "%BROWSER_DIR%" ...
set "PLAYWRIGHT_BROWSERS_PATH=%BROWSER_DIR%"
"%PYEXE%" -m playwright install chromium
if errorlevel 1 (
    echo Retry chromium download with CN mirror ...
    set "PLAYWRIGHT_DOWNLOAD_HOST=https://cdn.npmmirror.com/binaries/playwright"
    "%PYEXE%" -m playwright install chromium || goto :fail
)

echo [4/4] Registering autostart (run at logon) ...
rem Prefer Task Scheduler (needs admin); fallback to HKCU Run key.
rem venv keeps pythonw.exe in env\Scripts, conda env in env\ root - handle both.
set "PYW=%PYEXE:python.exe=pythonw.exe%"
schtasks /Create /F /TN "%TASK_NAME%" /SC ONLOGON /RL HIGHEST /TR "\"%PYW%\" \"%TOOL_DIR%net_guard.py\"" 2>nul
if errorlevel 1 (
    echo Task Scheduler needs admin rights, falling back to HKCU Run key ...
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "%TASK_NAME%" /t REG_SZ /d "%PYW% %TOOL_DIR%net_guard.py" /f || goto :fail
)

echo.
echo Done. Next steps:
echo   1. Edit config.json  (portal_url / campus_account / campus_password)
echo   2. Test auth:        "%PYEXE%" "%TOOL_DIR%net_guard.py" --test-auth
echo   3. Inspect portal:   "%PYEXE%" "%TOOL_DIR%net_guard.py" --dump-page
echo   4. Refresh probe IPs:%PYEXE% "%TOOL_DIR%net_guard.py" --refresh-probe
echo   5. Set dry_run=false in config.json and restart the task.
pause
exit /b 0

:nopython
echo [ERROR] Neither conda nor the "py" launcher found.
echo         Install Python 3.9+ or Miniconda first, then re-run.
pause
exit /b 1

:fail
echo.
echo [ERROR] Install failed, see messages above.
pause
exit /b 1
