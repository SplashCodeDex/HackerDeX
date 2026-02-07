import unittest
import sys
import os

# Adjust path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from web_ui.script_sandbox import ScriptSandbox

class TestScriptSandbox(unittest.TestCase):

    def setUp(self):
        self.sandbox = ScriptSandbox()

    def test_safe_script(self):
        script = "import requests\nprint('Hello')"
        is_safe, reason = self.sandbox.validate_script(script)
        self.assertTrue(is_safe)

    def test_unsafe_import(self):
        script = "import os\nos.system('rm -rf /')"
        is_safe, reason = self.sandbox.validate_script(script)
        self.assertFalse(is_safe)
        self.assertIn("Importing 'os' is not allowed", reason)

    def test_unsafe_subprocess(self):
        script = "import subprocess\nsubprocess.call(['ls'])"
        is_safe, reason = self.sandbox.validate_script(script)
        self.assertFalse(is_safe)
        self.assertIn("Importing 'subprocess' is not allowed", reason)

if __name__ == '__main__':
    unittest.main()
