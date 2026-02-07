from typing import List, Dict, Any
import json
import os

class SuccessWeightingEngine:
    """
    Ranks tools based on their historical effectiveness for specific tactical goals.
    Maintains a persistent 'Success Map' to learn over time.
    """

    def __init__(self):
        self.data_path = os.path.join(os.path.dirname(__file__), 'data', 'tool_success_map.json')
        os.makedirs(os.path.dirname(self.data_path), exist_ok=True)
        self.success_map: Dict[str, Dict[str, float]] = {} # {goal: {tool: total_score}}
        self._load_data()

    def record_success(self, tool_name: str, goal: str, score: float = 1.0):
        """Records a successful outcome for a tool and goal."""
        if goal not in self.success_map:
            self.success_map[goal] = {}
        
        self.success_map[goal][tool_name] = self.success_map[goal].get(tool_name, 0.0) + score
        self._save_data()

    def rank_tools(self, tool_names: List[str], goal: str) -> List[str]:
        """
        Sorts the provided tool names based on their success score for the given goal.
        """
        if goal not in self.success_map:
            return tool_names # No history, return original order

        goal_stats = self.success_map[goal]
        
        # Sort tools by score descending, tools not in map get score 0
        ranked = sorted(tool_names, key=lambda t: goal_stats.get(t, 0.0), reverse=True)
        return ranked

    def _load_data(self):
        if os.path.exists(self.data_path):
            try:
                with open(self.data_path, 'r') as f:
                    self.success_map = json.load(f)
            except Exception:
                pass

    def _save_data(self):
        try:
            with open(self.data_path, 'w') as f:
                json.dump(self.success_map, f, indent=4)
        except Exception:
            pass
