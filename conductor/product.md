# Initial Concept
An "All in One Hacking tool For Hackers" providing a centralized menu-driven interface to install and run various security and penetration testing tools.

# Product Guide - HackerDeX

## Overview
HackerDeX (based on `hackingtool`) is an all-in-one security suite designed for ethical hackers and penetration testers who require a centralized management interface for their security workflows. It bridges the gap between raw command-line tools and professional management by providing both a robust CLI and a modern Web UI.

## Target Audience
- **Professional Ethical Hackers:** Penetration testers seeking to streamline their toolkit management and aggregate data.
- **Security Researchers:** Users who need an integrated environment to run, store, and analyze the outputs of diverse security tools.

## Core Goals
- **Unified Interface:** Provide a consistent menu-driven experience across both CLI and Web interfaces for tool installation and execution.
- **Automated Orchestration:** Simplify and automate the deployment of complex security tools on Linux-based environments.
- **Intellectual Aggregation:** Create an integrated workspace where disparate tool outputs are parsed, normalized, and stored in a central vulnerability store (VulnStore) for structured analysis.

## Key Features
- **Modern Web Interface:** A fully reactive web UI for managing the tool catalog, launching remote scans, and monitoring execution in real-time.
- **VulnStore & Parsing Engine:** A specialized back-end architecture that automatically parses raw tool data into actionable intelligence, tracking ports, technologies, and vulnerabilities.
- **AI-Powered Analysis:** Deep integration with Google Gemini (via `google-genai`) to provide intelligent summaries, risk assessments, and automated exploit verification scripts.

## Design Philosophy
- **Simplicity & Efficiency:** Prioritize clean, intuitive interfaces that allow for fast tool deployment with minimal configuration.
- **Robustness & Precision:** Maintain high reliability in tool execution and ensure high-fidelity data parsing to provide accurate security insights.

## Future Vision
- **Autonomous Security Agents:** Evolution towards AI-driven agents capable of performing complex, multi-step penetration testing workflows autonomously based on high-level objectives.
