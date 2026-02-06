#!/bin/bash
# ================================================
# HackingTool Upgrade Script
# Run this INSIDE the Docker container to add
# modern API fuzzing and PWA crawling tools
# ================================================

echo "[*] Updating package lists..."
apt-get update

echo "[*] Installing Go and ffuf..."
apt-get install -y golang-go ffuf nmap

# Set Go environment
export GOPATH=/root/go
export PATH="${GOPATH}/bin:${PATH}"

echo "[*] Installing Katana (PWA Crawler)..."
go install github.com/projectdiscovery/katana/cmd/katana@latest

echo "[*] Installing Gospider (Web Spider)..."
go install github.com/jaeles-project/gospider@latest

echo "[*] Installing Arjun (Parameter Discovery)..."
pip3 install --break-system-packages arjun

echo ""
echo "================================================"
echo "    UPGRADE COMPLETE!"
echo "================================================"
echo "Available Tools:"
echo "  - katana  : PWA/SPA JavaScript Crawler"
echo "  - gospider: Fast Web Spider"
echo "  - arjun   : HTTP Parameter Discovery"
echo "  - ffuf    : Fast Web Fuzzer"
echo "  - nmap    : Network Scanner"
echo ""
echo "Example Usage:"
echo "  katana -u http://target.com -jc"
echo "  gospider -s http://target.com -d 2"
echo "  arjun -u http://target.com/api"
echo "================================================"
