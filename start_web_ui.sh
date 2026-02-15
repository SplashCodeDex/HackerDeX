#!/bin/bash

# HackingTool Web UI Launcher (Linux/WSL)

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}==================================================${NC}"
echo -e "${BLUE}      HACKERDEX WEB UI LAUNCHER                   ${NC}"
echo -e "${BLUE}==================================================${NC}"
echo ""

# Check for .env
if [ -f .env ]; then
    echo -e "${GREEN}[*] Loading environment variables from .env${NC}"
    export $(grep -v '^#' .env | xargs)
else
    echo -e "${RED}[!] WARNING: .env file not found.${NC}"
fi

# Check for venv
if [ -d "venv" ]; then
    echo -e "${GREEN}[*] Activating virtual environment...${NC}"
    source venv/bin/activate
fi

echo -e "${GREEN}[*] Launching Web Interface...${NC}"
echo -e "${GREEN}[*] Access at http://localhost:8080${NC}"
echo ""

python3 web_ui/app.py
