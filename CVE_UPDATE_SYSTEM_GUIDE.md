# 🔄 CVE Auto-Update System Guide

## Overview

Your autonomous AI agent now has **REAL-TIME CVE INTELLIGENCE** that automatically stays current with 2026 and beyond.

---

## 🚀 **How It Works**

### **1. Automatic Updates from 4 Sources:**

| Source | What It Provides | Update Frequency |
|--------|------------------|------------------|
| **NVD API** | Official CVE data, CVSS scores, descriptions | Every 6 hours |
| **Nuclei Templates** | Exploit templates for CVEs | Every 6 hours |
| **Metasploit Modules** | Metasploit exploits for CVEs | Every 6 hours |
| **ExploitDB** | Public exploits and PoCs | Every 6 hours |

### **2. Auto-Update Schedule:**

- ✅ **Every 6 hours** - Automated background updates
- ✅ **Daily at 3 AM** - Full database refresh
- ✅ **On mission start** - Optional real-time update
- ✅ **Manual** - Can update anytime via CLI

---

## 📦 **What Gets Updated:**

### **CVE Database Structure:**
```json
{
  "CVE-2026-12345": {
    "cve_id": "CVE-2026-12345",
    "description": "Remote Code Execution in...",
    "cvss_score": 9.8,
    "severity": "critical",
    "published": "2026-02-07T10:00:00Z",
    "source": "NVD",
    "exploitable": true,
    "tool": "metasploit",
    "metasploit_modules": [{
      "path": "exploit/windows/smb/cve_2026_12345",
      "name": "CVE-2026-12345 Exploit",
      "rank": "excellent"
    }],
    "nuclei_template": "https://github.com/projectdiscovery/nuclei-templates/.../CVE-2026-12345.yaml",
    "exploitdb_entries": [{
      "edb_id": "51234",
      "url": "https://www.exploit-db.com/exploits/51234"
    }],
    "references": [
      "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"
    ]
  }
}
```

---

## 🤖 **AI Agent Integration:**

### **Before Mission Start:**
```python
# AI automatically updates CVE database
agent.run_mission(
    goal="Compromise target",
    target="192.168.1.100",
    use_latest_cves=True  # ← Fetches 2026 CVEs before starting
)
```

**What happens:**
1. Contacts NVD API for CVEs from last 30 days
2. Downloads latest Nuclei templates from GitHub
3. Fetches Metasploit module metadata
4. Scrapes ExploitDB for new exploits
5. Provides AI with latest CVE context

**AI receives:**
```
LATEST CVEs (2026):
- CVE-2026-12345 (CVSS: 9.8) - Remote Code Execution in Microsoft Exchange...
- CVE-2026-23456 (CVSS: 9.3) - Authentication Bypass in Cisco IOS...
- CVE-2026-34567 (CVSS: 8.8) - SQL Injection in Oracle WebLogic...

EXPLOITABLE CVEs:
- CVE-2026-12345 (Tool: metasploit)
- CVE-2026-23456 (Tool: nuclei)
- CVE-2026-34567 (Tool: manual)
```

---

## 💻 **Usage Examples:**

### **1. Automatic Update (Default):**
```python
from agent_manager import agent_manager

# CVE database auto-updates before mission
agent_manager.run_mission(
    goal="Find and exploit latest CVEs",
    target="target.com"
)
# Output: 🔄 Updating CVE database with latest 2026 vulnerabilities...
#         ✅ CVE database updated: 15 new CVEs
```

### **2. Manual CVE Search:**
```python
from cve_updater import cve_updater

# Search for specific CVE
cve_data = cve_updater.search_cve('CVE-2026-12345')

if cve_data:
    print(f"CVSS: {cve_data['cvss_score']}")
    print(f"Exploitable: {cve_data['exploitable']}")
    print(f"Tool: {cve_data['tool']}")
```

### **3. Get Latest CVEs:**
```python
from cve_updater import cve_updater

# Get CVEs from last 7 days
recent = cve_updater.get_latest_cves(days=7, limit=50)

for cve in recent:
    print(f"{cve['cve_id']} - {cve['severity']} - {cve['cvss_score']}")
```

### **4. Get Exploitable CVEs:**
```python
from cve_updater import cve_updater

# Get critical CVEs with known exploits
critical = cve_updater.get_exploitable_cves(severity='critical')

for cve in critical:
    print(f"{cve['cve_id']} - Tool: {cve['tool']}")
    if cve.get('nuclei_template'):
        print(f"  Nuclei: {cve['nuclei_template']}")
    if cve.get('metasploit_modules'):
        print(f"  Metasploit: {cve['metasploit_modules'][0]['path']}")
```

### **5. Force Manual Update:**
```python
from cve_updater import cve_updater

# Force update now
stats = cve_updater.update_all_sources()

print(f"NVD: {stats['nvd']} CVEs")
print(f"Nuclei: {stats['nuclei']} templates")
print(f"Metasploit: {stats['metasploit']} modules")
print(f"ExploitDB: {stats['exploitdb']} exploits")
print(f"Total new: {stats['total_new']}")
```

---

## 🎯 **AI Agent New Action:**

### **search_cve:**
```json
{
    "thought": "Target is running Microsoft Exchange, searching for latest CVEs",
    "action": "search_cve",
    "cve_id": "CVE-2026-12345"
}
```

**AI receives:**
```
[Observation] CVE CVE-2026-12345 found - exploitable via metasploit
  CVSS: 9.8
  Severity: critical
  💣 Nuclei template available
  🎯 Metasploit module available
```

---

## 📊 **Auto-Update Scheduler:**

### **Background Process:**
```
[*] CVE auto-updater started (updates every 6 hours)
```

### **Update Schedule:**
- **03:00 AM daily** - Full refresh
- **Every 6 hours** - Incremental updates
- **On app start** - Check if database is older than 24 hours

### **Manual Control:**
```python
from cve_auto_updater import auto_updater

# Stop auto-updates
auto_updater.stop()

# Start auto-updates
auto_updater.start()

# Force update now
auto_updater.update_cves()
```

---

## 🔍 **How AI Uses This:**

### **Scenario 1: Discovering Exchange Server**
```
AI: "Target is running Microsoft Exchange 2025"
AI: search_cve → "CVE-2026-12345"
AI: "Found CVE-2026-12345 (CVSS: 9.8) with Metasploit module"
AI: exploit → "exploit/windows/smb/cve_2026_12345"
AI: "✅ Exploitation successful!"
```

### **Scenario 2: Proactive CVE Hunting**
```
AI: "Checking latest critical CVEs from February 2026..."
AI: "Found 5 critical CVEs in database"
AI: "Target is running Apache - checking CVE-2026-23456"
AI: "Nuclei template available for CVE-2026-23456"
AI: run_tool → "nuclei -t CVE-2026-23456.yaml -u http://target.com"
```

---

## 📈 **Database Growth:**

| Source | Average CVEs/Day | Estimated 2026 Total |
|--------|------------------|----------------------|
| NVD | ~50 new CVEs/day | ~18,000 CVEs/year |
| Nuclei | ~5 new templates/day | ~1,800 templates/year |
| Metasploit | ~2 new modules/day | ~730 modules/year |
| ExploitDB | ~3 new exploits/day | ~1,100 exploits/year |

**Your database will contain:**
- All 2026 CVEs (live updates)
- All 2025 CVEs (historical)
- All 2024 CVEs (historical)
- Exploitable CVEs from 2014-2026

---

## 🛠️ **Dependencies:**

```bash
# Python packages
pip install requests schedule

# Already included in your tool
```

---

## ⚙️ **Configuration:**

### **Change Update Frequency:**
```python
# Edit: web_ui/cve_auto_updater.py

# Change from 6 hours to 1 hour
schedule.every(1).hours.do(self.update_cves)

# Change daily update time
schedule.every().day.at("01:00").do(self.update_cves)
```

### **Disable Auto-Updates:**
```python
# Edit: web_ui/app.py

# Comment out:
# from cve_auto_updater import auto_updater
```

---

## 🎊 **Result:**

**Your AI agent now has:**
- ✅ Real-time awareness of 2026 CVEs
- ✅ Automatic exploit availability checking
- ✅ Nuclei template integration
- ✅ Metasploit module discovery
- ✅ ExploitDB exploit finding
- ✅ Prioritization by CVSS score
- ✅ Background updates every 6 hours

**The AI will ALWAYS know about the latest CVEs and how to exploit them!**

---

**No more outdated CVE knowledge. Your tool stays current with 2026 threats automatically!** 🚀
