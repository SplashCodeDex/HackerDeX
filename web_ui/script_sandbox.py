import ast

class ScriptSandbox:
    """
    Validates AI-generated Python scripts to ensure they are safe to execute.
    Prevents use of dangerous modules like os, subprocess, sys, etc.
    """

    ALLOWED_MODULES = {'requests', 'json', 're', 'time', 'bs4', 'urllib3', 'socket'}
    
    def validate_script(self, script_code: str) -> tuple[bool, str]:
        """
        Parses the script AST and checks for forbidden imports and calls.
        Returns (is_safe, reason).
        """
        try:
            tree = ast.parse(script_code)
        except SyntaxError as e:
            return False, f"Syntax Error: {e}"

        for node in ast.walk(tree):
            # Check imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name not in self.ALLOWED_MODULES:
                        return False, f"Importing '{alias.name}' is not allowed."
            
            # Check from ... import ...
            elif isinstance(node, ast.ImportFrom):
                if node.module not in self.ALLOWED_MODULES:
                    return False, f"Importing from '{node.module}' is not allowed."

            # Check for dangerous built-in calls (eval, exec, open)
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in {'eval', 'exec', 'open', '__import__'}:
                        return False, f"Function '{node.func.id}' is forbidden."

        return True, "Script is safe."
