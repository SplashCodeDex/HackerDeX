@echo off
echo ==================================================
echo      HACKERDEX DOCKER BUILDER
echo ==================================================
echo.
echo [1] Building 'hackingtool' image...
docker build -t hackingtool .
echo.
if %errorlevel% neq 0 (
    echo [!] Build Failed!
    pause
    exit /b %errorlevel%
)
echo [2] Build Complete. You can now run the launchers.
pause
