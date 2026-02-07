import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Adjust path to import from parent directory if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import HackingTool, ToolExecutor

class TestHackingTool(unittest.TestCase):

    @patch('core.ToolExecutor.run_blocking')
    def test_hacking_tool_run_uses_executor(self, mock_run_blocking):
        # Setup mock
        mock_run_blocking.return_value = {"stdout": "success", "stderr": "", "returncode": 0}

        class MockTool(HackingTool):
            TITLE = "Mock Tool"
            RUN_COMMANDS = ["echo 'running'"]

        tool = MockTool()
        tool.run()

        mock_run_blocking.assert_called_with("echo 'running'")

    @patch('core.ToolExecutor.run_blocking')
    def test_hacking_tool_install_uses_executor(self, mock_run_blocking):
        # Setup mock
        mock_run_blocking.return_value = {"stdout": "installed", "stderr": "", "returncode": 0}

        class MockTool(HackingTool):
            TITLE = "Mock Tool"
            INSTALL_COMMANDS = ["apt install mock"]

        tool = MockTool()
        tool.install()

        mock_run_blocking.assert_called_with("apt install mock")

if __name__ == '__main__':
    unittest.main()
