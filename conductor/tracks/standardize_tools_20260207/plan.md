# Implementation Plan - Standardize Tool Execution and Parsing

## Phase 1: Core Execution Engine Refactor [checkpoint: 76698bd]

- [x] Task: Create `ToolExecutor` class [8a1014e]
    - [x] Sub-task: Write tests for `ToolExecutor` (mocking subprocess)
    - [x] Sub-task: Implement `ToolExecutor` with `run_async` and `run_blocking` methods using `subprocess`
    - [x] Sub-task: Implement real-time output capture (yielding lines)

- [x] Task: Update `HackingTool` Base Class [5b8a31d]
    - [x] Sub-task: Write tests ensuring `HackingTool` uses `ToolExecutor`
    - [x] Sub-task: Refactor `core.py` to integrate `ToolExecutor` into the base `HackingTool` class
    - [x] Sub-task: Deprecate `os.system` usage in the base class

- [x] Task: Conductor - User Manual Verification 'Core Execution Engine Refactor' (Protocol in workflow.md)

## Phase 2: Tool Migration (Batch 1 - High Priority)

- [x] Task: Migrate Information Gathering Tools [15b9926]
    - [x] Sub-task: Write tests for Nmap and other key info gathering tool wrappers
    - [x] Sub-task: Refactor `tools/information_gathering_tools.py` to use the new execution method
    - [x] Sub-task: Verify output streaming for these tools

- [ ] Task: Migrate SQL Injection Tools
    - [ ] Sub-task: Write tests for SQLMap wrapper
    - [ ] Sub-task: Refactor `tools/sql_tools.py`
    - [ ] Sub-task: Verify output parsing for SQLMap

- [ ] Task: Conductor - User Manual Verification 'Tool Migration (Batch 1 - High Priority)' (Protocol in workflow.md)

## Phase 3: Parser & VulnStore Integration

- [ ] Task: Connect Executor to Parser Registry
    - [ ] Sub-task: Write tests for data flow from Executor to Parser
    - [ ] Sub-task: Update `web_ui/app.py` and `context_injector.py` to utilize the standardized output from `ToolExecutor`
    - [ ] Sub-task: Ensure parsed data is correctly saved to `VulnStore`

- [ ] Task: Verify Key Parsers
    - [ ] Sub-task: Create test cases with sample output for Nmap, SQLMap, and Nikto
    - [ ] Sub-task: Validate that `parsers/` correctly extract data from the new captured output format

- [ ] Task: Conductor - User Manual Verification 'Parser & VulnStore Integration' (Protocol in workflow.md)

## Phase 4: Full Suite Migration & Cleanup

- [ ] Task: Migrate Remaining Tool Categories
    - [ ] Sub-task: Refactor `tools/anonsurf.py`, `tools/ddos.py`, etc. (Iterative updates)
    - [ ] Sub-task: Ensure all 55+ tools utilize the new pattern

- [ ] Task: Cleanup Legacy Code
    - [ ] Sub-task: Remove unused `os.system` calls and legacy execution helpers
    - [ ] Sub-task: Final integration test pass

- [ ] Task: Conductor - User Manual Verification 'Full Suite Migration & Cleanup' (Protocol in workflow.md)
