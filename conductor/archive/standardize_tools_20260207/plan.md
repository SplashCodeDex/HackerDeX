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

## Phase 2: Tool Migration (Batch 1 - High Priority) [checkpoint: 0099fb2]

- [x] Task: Migrate Information Gathering Tools [15b9926]
    - [x] Sub-task: Write tests for Nmap and other key info gathering tool wrappers
    - [x] Sub-task: Refactor `tools/information_gathering_tools.py` to use the new execution method
    - [x] Sub-task: Verify output streaming for these tools

- [x] Task: Migrate SQL Injection Tools [373e619]
    - [x] Sub-task: Write tests for SQLMap wrapper
    - [x] Sub-task: Refactor `tools/sql_tools.py` to use the new execution method
    - [x] Sub-task: Verify output parsing for SQLMap

- [x] Task: Conductor - User Manual Verification 'Tool Migration (Batch 1 - High Priority)' (Protocol in workflow.md)

## Phase 3: Parser & VulnStore Integration [checkpoint: 5a0515b]

- [x] Task: Connect Executor to Parser Registry [bbb49ab]
    - [x] Sub-task: Write tests for data flow from Executor to Parser
    - [x] Sub-task: Update `web_ui/app.py` and `context_injector.py` to utilize the standardized output from `ToolExecutor`
    - [x] Sub-task: Ensure parsed data is correctly saved to `VulnStore`

- [x] Task: Verify Key Parsers [3b304f0]
    - [x] Sub-task: Create test cases with sample output for Nmap, SQLMap, and Nikto
    - [x] Sub-task: Validate that `parsers/` correctly extract data from the new captured output format

- [x] Task: Conductor - User Manual Verification 'Parser & VulnStore Integration' (Protocol in workflow.md)

## Phase 4: Full Suite Migration & Cleanup [checkpoint: 1e2b44e]

- [x] Task: Migrate Remaining Tool Categories [1c5616b]
    - [x] Sub-task: Refactor `tools/anonsurf.py`, `tools/ddos.py`, etc. (Iterative updates)
    - [x] Sub-task: Ensure all 55+ tools utilize the new pattern

- [x] Task: Cleanup Legacy Code [8275938]
    - [x] Sub-task: Remove unused `os.system` calls and legacy execution helpers
    - [x] Sub-task: Final integration test pass

- [x] Task: Conductor - User Manual Verification 'Full Suite Migration & Cleanup' (Protocol in workflow.md)
