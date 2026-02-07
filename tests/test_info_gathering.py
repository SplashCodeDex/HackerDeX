import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Adjust path to import from parent directory if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.information_gathering_tools import NMAP, PortScan, Striker

class TestInfoGathering(unittest.TestCase):

    @patch('core.ToolExecutor.run_blocking')
    def test_portscan_run_uses_executor(self, mock_run_blocking):
        # Setup mock
        mock_run_blocking.return_value = {"stdout": "Scan results", "stderr": "", "returncode": 0}

        # Mock Prompt.ask to provide a target
        with patch('rich.prompt.Prompt.ask', return_value="127.0.0.1"):
            tool = PortScan()
            tool.run()

        # PortScan currently uses subprocess.run直接, so this should fail in Red phase
        mock_run_blocking.assert_called_with("sudo nmap -O -Pn 127.0.0.1")

    @patch('core.ToolExecutor.run_blocking')
    def test_striker_run_uses_executor(self, mock_run_blocking):
        # Setup mock
        mock_run_blocking.return_value = {"stdout": "Striker output", "stderr": "", "returncode": 0}

        with patch('rich.prompt.Prompt.ask', return_value="example.com"):
            with patch('os.chdir'): # Avoid actual chdir
                tool = Striker()
                tool.run()

        # Striker currently uses subprocess.run, so this should fail
        mock_run_blocking.assert_called_with("sudo python3 striker.py example.com")

if __name__ == '__main__':
    unittest.main()