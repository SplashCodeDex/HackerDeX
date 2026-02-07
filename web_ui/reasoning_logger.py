import json
import logging
from datetime import datetime
from typing import Dict, Any, List

class ReasoningLogger:
    """
    Maintains a high-fidelity log of the agent's internal reasoning vs. external actions.
    This log is persistent and real-time observable.
    """

    def __init__(self):
        self.logs: List[Dict[str, Any]] = []
        self.current_step = 0

    def log_step(self, thought: str, action: str, tool: str, command: str, expected_gain: str):
        """
        Records a single tactical step.
        """
        self.current_step += 1
        entry = {
            "step": self.current_step,
            "timestamp": datetime.now().isoformat(),
            "thought": thought,
            "action": action,
            "tool": tool,
            "command": command,
            "expected_gain": expected_gain,
            "status": "pending"
        }
        self.logs.append(entry)
        return entry

    def update_status(self, step_index: int, status: str, result_summary: str = ""):
        """
        Updates the outcome of a step.
        """
        if 0 <= step_index < len(self.logs):
            self.logs[step_index]["status"] = status
            self.logs[step_index]["result_summary"] = result_summary

    def get_history(self) -> List[Dict[str, Any]]:
        return self.logs

    def export_tactical_report(self) -> str:
        """
        Generates a summary of the agent's reasoning path.
        """
        report = "# Autonomous Tactical Reasoning Report\n\n"
        for log in self.logs:
            report += f"## Step {log['step']}: {log['tool']}\n"
            report += f"- **Thought**: {log['thought']}\n"
            report += f"- **Action**: {log['action']} (`{log['command']}`)\n"
            report += f"- **Expectation**: {log['expected_gain']}\n"
            report += f"- **Outcome**: {log['status']} {log.get('result_summary', '')}\n\n"
        return report