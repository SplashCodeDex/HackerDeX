import unittest
from unittest.mock import MagicMock, patch
import subprocess
import sys
import os

# Adjust path to import from parent directory if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import ToolExecutor

class TestToolExecutor(unittest.TestCase):

    @patch('subprocess.Popen')
    def test_run_blocking_success(self, mock_popen):
        # Setup mock
        process_mock = MagicMock()
        process_mock.communicate.return_value = ('output', 'error')
        process_mock.returncode = 0
        mock_popen.return_value = process_mock

        executor = ToolExecutor()
        result = executor.run_blocking("echo test")

        self.assertEqual(result['stdout'], 'output')
        self.assertEqual(result['stderr'], 'error')
        self.assertEqual(result['returncode'], 0)
        mock_popen.assert_called_with(
            "echo test", 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )

    @patch('subprocess.Popen')
    def test_run_async_streaming(self, mock_popen):
        # Setup mock for streaming
        process_mock = MagicMock()
        process_mock.stdout.readline.side_effect = ['line1\n', 'line2\n', '']
        process_mock.poll.side_effect = [None, None, 0] # Running, Running, Done
        process_mock.returncode = 0
        mock_popen.return_value = process_mock

        executor = ToolExecutor()
        lines = []
        for line in executor.run_async("ping -c 2 localhost"):
            lines.append(line)

        self.assertEqual(lines, ['line1\n', 'line2\n'])
        mock_popen.assert_called_with(
            "ping -c 2 localhost",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, # Unified stream for async
            text=True,
            bufsize=1
        )

if __name__ == '__main__':
    unittest.main()
