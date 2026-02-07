import unittest
import sys
import os

# Adjust path
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, 'web_ui'))

from web_ui.reasoning_logger import ReasoningLogger

class TestReasoningLogger(unittest.TestCase):

    def setUp(self):
        self.logger = ReasoningLogger()

    def test_log_step(self):
        self.logger.log_step(
            thought="Need to scan",
            action="recon",
            tool="nmap",
            command="nmap target",
            expected_gain="Open ports"
        )
        history = self.logger.get_history()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["tool"], "nmap")
        self.assertEqual(history[0]["status"], "pending")

    def test_update_status(self):
        self.logger.log_step("Thought", "Action", "Tool", "Cmd", "Expect")
        self.logger.update_status(0, "completed", "Found 2 ports")
        history = self.logger.get_history()
        self.assertEqual(history[0]["status"], "completed")
        self.assertEqual(history[0]["result_summary"], "Found 2 ports")

    def test_export_report(self):
        self.logger.log_step("T", "A", "Tool", "C", "E")
        report = self.logger.export_tactical_report()
        self.assertIn("# Autonomous Tactical Reasoning Report", report)
        self.assertIn("Tool", report)

if __name__ == '__main__':
    unittest.main()
