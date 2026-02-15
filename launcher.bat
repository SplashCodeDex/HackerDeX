@echo off
if not exist ".env" (
    echo [!] WARNING: .env file not found. AI features may not work.
    echo     Please create one from .env.example
    echo.
)

echo ==================================================
echo      HACKERDEX CLI LAUNCHER (DOCKER)
echo ==================================================
echo.
echo [1] Launching HackingTool Container...
echo     (Mounting: %CD% -> /root/hackingtool)

REM Check if gemini keys are set in current shell, otherwise let docker read .env
set ENV_ARGS=
if exist .env set ENV_ARGS=--env-file .env

docker run -it --rm ^
  -v "%CD%":/root/hackingtool ^
  %ENV_ARGS% ^
  -e GEMINI_API_KEYS=%GEMINI_API_KEYS% ^
  -e GEMINI_MODEL=%GEMINI_MODEL% ^
  --network host ^
  --privileged ^
  hackingtool

if %errorlevel% neq 0 (
    echo.
    echo [!] Launcher failed. Did you build first?
    echo     Run 'build.bat' to create the image.
    pause
)
