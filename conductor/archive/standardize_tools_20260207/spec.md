# Specification: Standardize Tool Execution and Parsing

## 1. Overview
This track focuses on modernizing the core execution engine of HackerDeX to ensure all 55+ supported security tools are launched, monitored, and parsed consistently. The goal is to move away from legacy `os.system` calls to a robust `subprocess`-based architecture that supports real-time output streaming to the Web UI and accurate data capture for the `VulnStore`.

## 2. Goals
- **Unified Execution Model:** Refactor the `HackingTool` base class and its subclasses to use a standardized execution wrapper.
- **Robust Output Capture:** Ensure that stdout/stderr from all tools are captured reliably for parsing.
- **Parser Coverage:** Implement or verify parsers for the most critical tools to ensure data flows correctly into the `VulnStore`.
- **Error Handling:** Improve error detection and reporting when external tools fail or are missing.

## 3. Functional Requirements
- **Core Execution Wrapper:**
    - Create a central function/class (e.g., `ToolExecutor`) that handles `subprocess.Popen` or `subprocess.run`.
    - Support asynchronous execution to avoid blocking the UI.
    - Capture output in real-time for WebSocket streaming.
- **Tool Refactoring:**
    - Update `hackingtool.py` and `core.py` to use the new execution wrapper.
    - Systematically update tool definitions (in `tools/`) to ensure they pass correct arguments to the wrapper.
- **Parsing Integration:**
    - Ensure the `ContextInjector` and `VulnStore` receive structured data from the execution wrapper.
    - Verify parsing logic for key tools like `nmap`, `sqlmap`, `nikto`, etc.

## 4. Non-Functional Requirements
- **Performance:** Minimal overhead in the execution wrapper.
- **Stability:** The application must not crash if a subprocess fails.
- **Maintainability:** The new execution pattern must be easy to apply to future tools.

## 5. Out of Scope
- Adding new tools (focus is on existing 55+).
- Major UI redesigns (focus is on the backend logic).
