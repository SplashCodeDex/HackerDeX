import logging
from typing import List, Dict, Any, Set
from mission_planner import MissionPlanner

class MissionManager:
    """
    Manages the lifecycle of an autonomous Red Team mission.
    Enforces 'Intellectual Exhaustion' by pursuing all tactical paths.
    """

    def __init__(self, gemini_client):
        self.planner = MissionPlanner(gemini_client)
        self.current_mission = None
        self.active_phases = []
        self.completed_tasks = set()
        self.findings = []

    def start_mission(self, goal: str, target: str):
        """Initializes a mission by decomposing the goal."""
        self.current_mission = self.planner.decompose_goal(goal, target)
        self.active_phases = self.current_mission.get("phases", [])
        self.completed_tasks = set()
        logging.info(f"Mission '{self.current_mission['mission_name']}' started with {len(self.active_phases)} phases.")

    def mark_task_complete(self, task_name: str, status: str):
        """Records task completion and keeps the mission flowing."""
        self.completed_tasks.add(task_name)
        # Update phase status if needed (future logic for sequential phases)

    def is_mission_complete(self) -> bool:
        """
        Determines if the mission is truly exhausted.
        Mission is complete ONLY when all tasks in all phases are done.
        """
        if not self.current_mission:
            return True

        all_tasks = set()
        for phase in self.active_phases:
            for task in phase.get("tasks", []):
                all_tasks.add(task)

        return all_tasks.issubset(self.completed_tasks)

    def get_next_tasks(self) -> List[str]:
        """Returns the list of tasks that can be executed now."""
        pending = []
        for phase in self.active_phases:
            for task in phase.get("tasks", []):
                if task not in self.completed_tasks:
                    pending.append(task)
        return pending
