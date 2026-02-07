from .vuln_store import VulnStore
import shlex

class ContextInjector:
    def __init__(self):
        self.store = VulnStore()

    def get_enriched_command(self, tool_name, target_str, original_command_template):
        """
        Enriches a tool command with data from the VulnStore.
        Example: If running SQLMap and we know it's a MySQL target, add --dbms=mysql
        """
        profile = self.store.get_target_profile(target_str)
        
        # Sanitize target to prevent command injection
        # Note: Some templates might rely on target being a URL without quotes if passed as single arg,
        # but using quotes is generally safer for shell=True.
        # However, if the template is 'nmap {target}', shlex.quote('google.com') -> 'google.com' (no quotes needed)
        # shlex.quote('google.com; rm -rf /') -> "'google.com; rm -rf /'" (quoted, treated as one arg)
        safe_target = shlex.quote(target_str)
        
        if not profile:
            return original_command_template.format(target=safe_target)

        command = original_command_template.format(target=safe_target)

        # Logic for specific tools
        if tool_name.lower() in ['sqlmap', 'sql injection']:
            # Check tech for DBMS info
            for tech in profile.get('technologies', []):
                if 'mysql' in tech['name'].lower():
                    if '--dbms' not in command:
                        command += " --dbms=mysql"
                elif 'postgresql' in tech['name'].lower():
                    if '--dbms' not in command:
                        command += " --dbms=postgresql"

        return command

    def get_suggestions(self, target_str):
        """Returns helpful suggestions based on known data."""
        profile = self.store.get_target_profile(target_str)
        if not profile:
            return []

        suggestions = []
        if profile.get('ports'):
            ports = [str(p['port']) for p in profile['ports']]
            suggestions.append(f"Found open ports: {', '.join(ports)}")

        if profile.get('urls'):
            suggestions.append(f"Found {len(profile['urls'])} candidate URLs for testing")

        return suggestions

injector = ContextInjector()