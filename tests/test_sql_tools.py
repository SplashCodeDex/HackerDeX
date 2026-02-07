import unittest
from unittest.mock import MagicMock, patch
import sys
import os
from rich.text import Text

# Adjust path to import from parent directory if needed
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.sql_tools import Sqlmap

class TestSqlTools(unittest.TestCase):

    @patch('core.ToolExecutor.run_blocking')
    def test_sqlmap_run_uses_executor(self, mock_run_blocking):
        # Setup mock
        mock_run_blocking.return_value = {"stdout": "SQLMap output", "stderr": "", "returncode": 0}

        with patch('rich.prompt.Prompt.ask', return_value="http://example.com/vuln.php?id=1"):
            tool = Sqlmap()
            tool.run()

        mock_run_blocking.assert_called_with("sudo sqlmap -u http://example.com/vuln.php?id=1 --batch --dbs")

if __name__ == '__main__':
    unittest.main()