@echo off
setlocal
cd /d "%~dp0"
echo Starting Secure Vault...
where py >nul 2>nul
if %errorlevel%==0 (
    py -3 start.py %*
    goto done
)
where python >nul 2>nul
if %errorlevel%==0 (
    python start.py %*
    goto done
)
echo.
echo Python 3.11 or newer was not found on this computer.
echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH",
echo then double-click this file again.
:done
echo.
pause
endlocal
