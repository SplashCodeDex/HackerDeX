@echo off
echo ==================================================
echo      HACKERDEX SECURITY LAB LAUNCHER
echo ==================================================
echo.
echo [1] Launching HackingTool Container...
echo     (Mounting: %CD% -> /root/hackingtool)
echo.

docker run -it --rm ^
  -v "%CD%":/root/hackingtool ^
  --net=host ^
  hackingtool

pause
