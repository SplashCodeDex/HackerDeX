@echo off
echo ==================================================
echo      HACKERDEX WEB UI LAUNCHER
echo ==================================================
echo.

REM Check for Gemini API Key
if "%GEMINI_API_KEY%"=="" (
    echo [!] WARNING: GEMINI_API_KEY not set.
    echo     AI Analysis will be disabled.
    echo     To enable, run: set GEMINI_API_KEY=your_key_here
    echo.
)

echo [1] Launching HackingTool Web Interface...
echo     URL: http://localhost:8080
echo.

set ENV_CMD=
if exist .env (
    set ENV_CMD=--env-file .env
)

docker run -it --rm ^
  -p 8080:8080 ^
  %ENV_CMD% ^
  -e GEMINI_API_KEY=%GEMINI_API_KEY% ^
  --entrypoint python3 ^
  -v "%CD%":/root/hackingtool ^
  hackingtool ^
  web_ui/app.py

pause
