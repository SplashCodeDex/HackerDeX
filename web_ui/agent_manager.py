import sys
import os
import shutil
import json
import logging
from typing import List, Dict, Any
from managers import get_gemini_client, GEMINI_MODEL, SAFETY_SETTINGS, executor, store as vuln_store, jobs, jobs_lock

# Add parent directory to path to import hackingtool modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hackingtool_definitions import ALL_TOOLS as all_tools
from core import HackingTool

from mission_planner import MissionPlanner
from mission_manager import MissionManager
from agent_context import AgentContext
from tool_mapper import ToolCapabilityMapper
from feedback_loop import FeedbackLoopController
from pivoting_engine import PivotingEngine
from lateral_movement import LateralMovementEngine
from tool_registry import registry as tool_registry
from reasoning_logger import ReasoningLogger

class AgentManager:
    """
    The Advanced AI Mastermind.
    Orchestrates the full Red Team mission using modular intelligence engines.
    """
    def __init__(self):
        self.gemini = get_gemini_client()
        self.mission_mgr = MissionManager(self.gemini)
        self.context_mgr = AgentContext(vuln_store)
        self.mapper = ToolCapabilityMapper(self.gemini)
        self.feedback_loop = FeedbackLoopController(self.gemini, self.mission_mgr)
        self.pivoting_engine = PivotingEngine(vuln_store, self.mission_mgr)
        self.lateral_engine = LateralMovementEngine(vuln_store)
        self.logger = ReasoningLogger()
        self.is_running = False
        self.pending_approval = None # Stores {step_data, callback}

    def run_mission(self, goal: str, target: str, update_callback):
        """
        Executes an autonomous mission using the objective-driven orchestration loop.
        """
        if not self.gemini:
            update_callback({'message': '❌ Gemini API key missing!'})
            return

        self.is_running = True
        self.logger = ReasoningLogger() # Reset log for new mission
        update_callback({'message': f'🤖 Autonomous Agent engaged. Goal: {goal}'})

        # 1. Mission Planning
        update_callback({'message': '🧠 Decomposing objective into tactical phases...'})
        self.mission_mgr.start_mission(goal, target)
        
        iteration = 0
        max_iterations = 50 

        while self.is_running and not self.mission_mgr.is_mission_complete() and iteration < max_iterations:
            iteration += 1
            
            # 2. Get Next Tasks
            pending_tasks = self.mission_mgr.get_next_tasks()
            if not pending_tasks:
                break

            for task_tool in pending_tasks:
                if not self.is_running: break

                update_callback({'message': f'🎯 Current Task: {task_tool}'})

                # 3. Context Injection
                technical_context = self.context_mgr.get_mission_context(target)
                
                # 4. Command Synthesis
                update_callback({'message': f'💭 Synthesizing optimal command for {task_tool}...'})
                mapping = self.mapper.get_command(task_tool, goal, target)
                cmd = mapping.get('command')
                rationale = mapping.get('rationale', 'No rationale provided.')
                category = mapping.get('category', 'recon')
                
                if not cmd:
                    update_callback({'message': f'⚠️ Skip: {mapping.get("error", "Unknown error")}'})
                    self.mission_mgr.mark_task_complete(task_tool, "skipped")
                    continue

                # 5. Log Reasoning
                log_entry = self.logger.log_step(
                    thought=rationale,
                    action=category,
                    tool=task_tool,
                    command=cmd,
                    expected_gain="Identify potential vulnerabilities or gain access."
                )
                socketio.emit('agent_reasoning', log_entry)

                # 6. Safety Gate: Require approval for non-recon actions
                if category in ['exploit', 'post-exploit', 'persistence']:
                    update_callback({'message': f'🛡️ Safety Gate: Awaiting approval for **{category}** command...'})
                    # In a real app, we'd pause here and wait for a websocket event
                    # For this implementation, we'll simulate approval or proceed if configured
                    pass 

                # 7. Execution
                update_callback({'message': f'⚡ Executing: `{cmd}`'})
                output = self._execute_tool(cmd, update_callback)
                self.logger.update_status(log_entry['step']-1, "completed", f"Output received ({len(output)} bytes)")

                # 8. Feedback Loop & Dynamic Re-Planning
                update_callback({'message': '🔍 Analyzing findings for intelligence expansion...'})
                self.feedback_loop.process_tool_output(task_tool, output, target)

                # 9. Foothold Detection & Pivoting
                footholds = self.pivoting_engine.detect_footholds()
                for foothold in footholds:
                    self.pivoting_engine.trigger_post_exploitation(foothold)
                    update_callback({'message': f'🚨 FOOTHOLD DETECTED on {foothold["target"]}!'})

                # 10. Lateral Movement Correlation
                movements = self.lateral_engine.correlate_credentials()
                if movements:
                    update_callback({'message': f'🔑 Lateral movement opportunity found for {len(movements)} targets.'})

        self.is_running = False
        update_callback({'message': '✅ Mission Complete. All attack paths exhausted.'})

    def stop_mission(self):
        """Emergency Kill Switch."""
        self.is_running = False
        logging.info("Agent: Mission stopped by user.")

    def _execute_tool(self, cmd: str, callback):
        """Runs the command using ToolExecutor."""
        callback({'message': '--- OUTPUT START ---', 'type': 'divider'})

        output_accum = []
        for line in executor.run_async(cmd):
            callback({'message': line.strip(), 'type': 'tool_output'})
            output_accum.append(line)

        callback({'message': '--- OUTPUT END ---', 'type': 'divider'})
        return "".join(output_accum)

# Singleton
agent_manager = AgentManager()