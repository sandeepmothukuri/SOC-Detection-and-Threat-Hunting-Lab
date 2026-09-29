# 🔐 SOC Detection & Threat Hunting Lab: End-to-End Endpoint Telemetry, SIEM Detection Engineering & Incident Response

[![Lab Validation](https://github.com/sandeepmothukuri/SOC-Detection-and-Threat-Hunting-Lab/actions/workflows/validate.yml/badge.svg)](https://github.com/sandeepmothukuri/SOC-Detection-and-Threat-Hunting-Lab/actions)
[![Wazuh SIEM](https://img.shields.io/badge/SIEM-Wazuh%204.7-0066CC?style=flat&logo=wazuh&logoColor=white)](https://wazuh.com/)
[![Microsoft Sysmon](https://img.shields.io/badge/Endpoint-Microsoft%20Sysmon-0078D4?style=flat&logo=windows&logoColor=white)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20v14-red?style=flat)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> A production-grade **Security Operations Center (SOC) Detection and Threat Hunting Lab** demonstrating end-to-end telemetry engineering, red-team attack simulation, custom SIEM detection rules (Wazuh), endpoint behavioral tracking (Microsoft Sysmon + Windows Auditing), threat hunting queries (OpenSearch, Splunk SPL, Sentinel KQL), and full-lifecycle incident response.

---

## ⚡ Executive Summary & Quick Demo

| Stage | Implementation Details |
|---|---|
| **Threat Vector** | Network Reconnaissance & Remote Desktop Protocol (RDP) Brute-Force / Password Guessing |
| **Attacker Tooling** | Kali Linux (`nmap`, `hydra`, dictionary spray scripts) |
| **Target Host** | Windows 10/11 Enterprise (`192.168.56.20`) with Sysmon & Windows Advanced Auditing |
| **SIEM & Analytics** | Wazuh 4.7 All-in-One Manager + OpenSearch Indexer & Dashboard (`192.168.56.10`) |
| **Key Telemetry** | Windows Security Event ID 4625 (Logon Type 10), Event ID 4740, Sysmon Event ID 3 |
| **Detection Logic** | Custom threshold correlation: 5+ failed RDP logons within 60s from identical source IP |
| **MITRE ATT&CK** | **T1046** (Network Scanning), **T1110.001** (Password Guessing), **T1021.001** (RDP), **T1078** (Valid Accounts) |
| **Investigation Outcome** | Attack detected in real-time; attacker IP contained via host firewall; zero host compromise |

---

## 📑 Table of Contents

1. [Lab Architecture & Network Topology](#-lab-architecture--network-topology)
2. [Hardware & Software Prerequisites](#-hardware--software-prerequisites)
3. [Step-by-Step Installation & Deployment](#-step-by-step-installation--deployment)
   - [Part 1: Wazuh SIEM All-in-One Server](#part-1-wazuh-siem-all-in-one-server-deployment)
   - [Part 2: Windows Endpoint Auditing Configuration](#part-2-windows-endpoint-security-auditing)
   - [Part 3: Microsoft Sysmon Telemetry Deployment](#part-3-microsoft-sysmon-telemetry-deployment)
   - [Part 4: Wazuh Windows Agent Enrollment & Forwarding](#part-4-wazuh-windows-agent-enrollment--channel-configuration)
4. [Attack Simulation Walkthrough](#-attack-simulation-walkthrough)
   - [Phase 1: Host & Port Reconnaissance (Nmap)](#phase-1-network-reconnaissance--service-discovery-mitre-t1046)
   - [Phase 2: Automated RDP Brute-Force (Hydra)](#phase-2-automated-rdp-credential-stuffing-mitre-t1110001)
   - [Automated Simulation Script](#automated-simulation-script)
5. [Endpoint Telemetry & Forensic Artifacts](#-endpoint-telemetry--forensic-artifacts)
   - [Windows Security Log Analysis (Event IDs 4625, 4624, 4740)](#51-windows-security-log-telemetry)
   - [Microsoft Sysmon Telemetry (Event IDs 1 & 3)](#52-microsoft-sysmon-telemetry)
6. [Wazuh SIEM Detection Engineering](#-wazuh-siem-detection-engineering)
   - [Custom Detection Rules Architecture](#61-custom-detection-rules-architecture)
   - [Rule Validation with `wazuh-logtest`](#62-rule-validation-with-wazuh-logtest)
   - [Live SIEM Dashboard Detections](#63-live-siem-dashboard-detections)
7. [Threat Hunting Playbook & Cross-SIEM Queries](#-threat-hunting-playbook--cross-siem-queries)
   - [Wazuh / OpenSearch Query DSL](#wazuh--opensearch-dashboards-query-dsl)
   - [Splunk Search Processing Language (SPL)](#splunk-spl-threat-hunting-queries)
   - [Microsoft Sentinel (KQL)](#microsoft-sentinel-kql-queries)
8. [SOC Incident Response & Investigation Report](#-soc-incident-response--investigation-report)
9. [Hardening & Defensive Countermeasures](#-hardening--defensive-countermeasures)
10. [Repository Directory Structure](#-repository-directory-structure)
11. [Author Profile & Portfolio](#-author)

---

## 🏗️ Lab Architecture & Network Topology

The lab operates in an isolated virtualized sandbox network (`192.168.56.0/24`) designed to mirror an enterprise perimeter with an attacker, victim endpoint, and central SIEM collector.

```
                    +---------------------------------------------+
                    |           KALI LINUX (ATTACKER)             |
                    |              192.168.56.30                  |
                    |   Tools: Nmap, Hydra, Wordlists, Bash       |
                    +---------------------------------------------+
                                           |
                                           | 1. TCP Port Reconnaissance (Port 3389)
                                           | 2. RDP Brute-Force Attack
                                           v
+-----------------------------------------------------------------------------------------+
|                               WINDOWS 10/11 VICTIM ENDPOINT                             |
|                                       192.168.56.20                                     |
|                                                                                         |
|   +------------------------------------+      +-------------------------------------+   |
|   |    Windows Security Auditing       |      |           Microsoft Sysmon          |   |
|   |  - Event ID 4625 (Logon Failure)   |      |  - Event ID 3 (Network Connection)  |   |
|   |  - Event ID 4624 (Logon Success)   |      |  - Event ID 1 (Process Execution)   |   |
|   |  - Event ID 4740 (Account Lockout) |      |  - Event ID 10 (LSASS Access)       |   |
|   +------------------------------------+      +-------------------------------------+   |
|                                           |                                             |
|                                           v                                             |
|                       +---------------------------------------+                         |
|                       |          Wazuh Windows Agent          |                         |
|                       |   Service: WazuhSvc | ossec.conf      |                         |
|                       +---------------------------------------+                         |
+-----------------------------------------------------------------------------------------+
                                           |
                                           | Encrypted Event Channel (TCP 1514)
                                           v
+-----------------------------------------------------------------------------------------+
|                               WAZUH SIEM ALL-IN-ONE SERVER                              |
|                                       192.168.56.10                                     |
|                                                                                         |
|   +---------------------------+   +---------------------------+   +------------------+  |
|   |       Wazuh Manager       |   |       Wazuh Indexer       |   | Wazuh Dashboard  |  |
|   | - Decoders & Pre-filters  |-->| - OpenSearch Log Storage  |-->| - Web UI (HTTPS) |  |
|   | - Custom Rules (100001+)  |   | - Real-Time Indexing      |   | - Alert Triage   |  |
|   +---------------------------+   +---------------------------+   +------------------+  |
+-----------------------------------------------------------------------------------------+
```

### Visual Architecture & Pipeline Breakdown

![SOC Architecture Overview](images/architecture/soc-architecture/architecture.png)
*Figure 1: SOC Lab Architecture diagram showing telemetry pipeline from Windows endpoint to Wazuh.*

![Wazuh Central Components](images/architecture/soc-architecture/wazuh-central-components.png)
*Figure 2: Wazuh Central Server components: Manager core daemon, Filebeat log transport, OpenSearch Indexer, and Dashboard interface.*

![ELK & Wazuh Telemetry Ingestion](images/architecture/soc-architecture/combining-elk-wazuh-hids-and-elastalert-for-optimal-performance.png)
*Figure 3: Telemetry ingestion, real-time decoding, correlation engine, and alerting pipeline.*

---

## 💻 Hardware & Software Prerequisites

### Recommended System Specifications

- **Hypervisor:** VirtualBox 7.x, VMware Workstation 17.x, or Proxmox VE
- **Host Hardware:** 16 GB RAM minimum, 4+ CPU cores, 100 GB SSD storage
- **Virtual Network:** Host-Only Adapter or Dedicated Internal NAT Network (`192.168.56.0/24`)

### Virtual Machine Sizing

| VM Name | Operating System | vCPUs | RAM | Storage | Static IP |
|---|---|---|---|---|---|
| **Wazuh-SIEM** | Ubuntu Server 22.04 LTS | 2-4 | 4-8 GB | 50 GB | `192.168.56.10` |
| **Win10-Endpoint** | Windows 10/11 Enterprise | 2 | 4 GB | 40 GB | `192.168.56.20` |
| **Kali-Attacker** | Kali Linux 2024.x | 2 | 2-4 GB | 30 GB | `192.168.56.30` |

---

## ⚙️ Step-by-Step Installation & Deployment

### Part 1: Wazuh SIEM All-in-One Server Deployment

Deploy the central Wazuh SIEM on Ubuntu Server 22.04. For full step-by-step guidance, refer to [`setup/wazuh-setup.md`](setup/wazuh-setup.md).

```bash
# 1. Update OS and install base dependencies
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl apt-transport-https lsb-release gnupg2 tar ufw

# 2. Open necessary firewall ports
sudo ufw allow 1514/tcp comment "Wazuh Agent Events"
sudo ufw allow 1515/tcp comment "Wazuh Agent Enrollment"
sudo ufw allow 55000/tcp comment "Wazuh REST API"
sudo ufw allow 443/tcp comment "Wazuh Dashboard HTTPS"
sudo ufw enable

# 3. Download and run the Wazuh All-in-One deployment script
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml
sudo bash wazuh-install.sh -a

# 4. Extract generated administrative passwords
sudo tar -xvf wazuh-install-files.tar
sudo cat wazuh-install-files/wazuh-passwords.txt
```

Verify the core services are active:
```bash
sudo systemctl status wazuh-indexer wazuh-manager wazuh-dashboard
```

---

### Part 2: Windows Endpoint Security Auditing

Log on to `WIN10-ENDPOINT` as an Administrator. For detailed steps, see [`setup/windows-vm-setup.md`](setup/windows-vm-setup.md).

```powershell
# 1. Enable Remote Desktop (RDP) on Port 3389
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# 2. Configure Advanced Audit Policies (Captures 4624, 4625, 4672, 4740)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# 3. Enable Process Creation & Command-Line Telemetry
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 1 -Force
```

---

### Part 3: Microsoft Sysmon Telemetry Deployment

Deploy Microsoft Sysmon utilizing our custom, production-tuned [`setup/sysmon-config.xml`](setup/sysmon-config.xml):

```powershell
# 1. Create working directory and download Sysmon
New-Item -ItemType Directory -Path "C:\Tools" -Force
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Tools\Sysmon.zip"
Expand-Archive -Path "C:\Tools\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force

# 2. Install Sysmon with our lab configuration
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i C:\Users\sande\Documents\AntiGravity\new repo\SOC-Detection-and-Threat-Hunting-Lab\setup\sysmon-config.xml

# 3. Verify Sysmon service
Get-Service -Name "Sysmon64"
```

---

### Part 4: Wazuh Windows Agent Enrollment & Channel Configuration

```powershell
# 1. Download and silently install Wazuh Windows Agent
$ManagerIP = "192.168.56.10"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi" -OutFile "C:\Tools\wazuh-agent.msi"

Start-Process msiexec.exe -Wait -ArgumentList "/i C:\Tools\wazuh-agent.msi /q WAZUH_MANAGER='$ManagerIP' WAZUH_REGISTRATION_SERVER='$ManagerIP'"

# 2. Start Agent Service
Restart-Service -Name "WazuhSvc"
Get-Service -Name "WazuhSvc"
```

Verify in `C:\Program Files (x86)\ossec-agent\ossec.conf` that `Microsoft-Windows-Sysmon/Operational` and `Security` are present in `<localfile>` channels:

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Open the Wazuh Web Console at `https://192.168.56.10` and verify the agent status is **Active**:

![Wazuh Agent Dashboard](images/architecture/wazuh-dashboard/wazuh-dashboard-and-agent-deployment.png)
*Figure 4: Wazuh Dashboard confirming active Windows agent deployment and real-time telemetry stream.*

---

## ⚔️ Attack Simulation Walkthrough

### Phase 1: Network Reconnaissance & Service Discovery (MITRE T1046)

From the Kali Linux machine (`192.168.56.30`), the attacker scans the target subnet to identify open listening ports and services.

```bash
# Execute stealth TCP SYN scan targeting RDP Port 3389
nmap -sS -sV -p 3389 -Pn 192.168.56.20
```

![Nmap Kali Terminal Scan](images/attacks/nmap-scan/nmap-scan-terminal-kali.webp)
*Figure 5: Kali Linux terminal executing Nmap reconnaissance against port 3389.*

![Nmap Port Scan Result](images/attacks/nmap-scan/nmap-external-port-scan-result.webp)
*Figure 6: Nmap scan results confirming port 3389/tcp is open (`ms-wbt-server`).*

![Interpreting Scan Results](images/attacks/nmap-scan/interpreting-scan-results.png)
*Figure 7: Attacker analysis identifying exposed Remote Desktop service ready for credential attack.*

---

### Phase 2: Automated RDP Credential Stuffing (MITRE T1110.001)

The attacker launches Hydra to perform dictionary-based password guessing against the `Administrator` account:

```bash
# High-speed RDP brute force with Hydra
hydra -V -t 4 -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.56.20
```

![Hydra Brute-Force Attack](images/attacks/nmap-scan/brute-force-attack.jpg)
*Figure 8: Automated RDP password attack execution in progress.*

---

### Automated Simulation Script

To easily replicate this attack scenario in your lab, execute the included shell script [`scripts/attack-simulation.sh`](scripts/attack-simulation.sh):

```bash
# Make script executable
chmod +x scripts/attack-simulation.sh

# Run full attack simulation (Recon + Brute-Force)
./scripts/attack-simulation.sh -t 192.168.56.20 -u Administrator -m all
```

---

## 🔍 Endpoint Telemetry & Forensic Artifacts

### 5.1 Windows Security Log Telemetry

During the attack, the Windows Security Event Log on `WIN10-ENDPOINT` records rapid **Audit Failure** entries under Event ID 4625.

![Windows Event Viewer 4625](images/logs/sysmon-process/generated-event-is-recorded-in-the-windows-event-log.png)
*Figure 9: Windows Event Viewer logging high-frequency failed logon events (Event ID 4625).*

![Event 4625 Detail](images/architecture/bruteforce-alert/event-4625-failed-to-logon.png)
*Figure 10: Windows Event ID 4625 detail view confirming Logon Type 10 (RemoteInteractive).*

![Failed Logon Fields](images/architecture/bruteforce-alert/windows-event-id-4625-failed-logon.png)
*Figure 11: Security event data displaying Status `0xC000006D` and Substatus `0xC000006A`.*

![Process Information 4625](images/architecture/bruteforce-alert/process-information.png)
*Figure 12: Event Process Information identifying `svchost.exe` (TermService host).*

#### Key Windows Security Fields Forensic Matrix

| Event Field | Value Recorded | Forensic Significance |
|---|---|---|
| **EventID** | `4625` | An account failed to log on |
| **LogonType** | `10` | **RemoteInteractive** (RDP session attempt) |
| **Status** | `0xC000006D` | The logon attempt failed due to invalid credentials |
| **SubStatus** | `0xC000006A` | User name is valid, but password was incorrect |
| **TargetUserName** | `Administrator` | Account targeted during brute-force attempt |
| **IpAddress** | `192.168.56.30` | Source IP of the attacking machine |
| **CallerProcessName** | `C:\Windows\System32\svchost.exe` | Windows Terminal Services hosting process |

When the attack crosses the lockout threshold, Windows fires **Event ID 4740**:

```
Log Name:      Security
Event ID:      4740
Description:   A user account was locked out.
Target Account Name: Administrator
```

---

### 5.2 Microsoft Sysmon Telemetry

Sysmon captures the network connection layer and process execution layer independently of Windows Security Auditing.

![Sysmon Network Logs](images/logs/sysmon-process/sysmon-logs-network.png)
*Figure 13: Sysmon Operational Log capturing Event ID 3 inbound network connections.*

![Sysmon Event ID 3 Record](images/logs/sysmon-process/sysmon-event-id-3---rdp-logon-issue-initiated--field-always-false.png)
*Figure 14: Sysmon Event ID 3 deep inspection showing inbound connection to Port 3389.*

![Workstation Telemetry View](images/logs/sysmon-process/workstation-logs.png)
*Figure 15: Correlated endpoint workstation logs streaming to Wazuh.*

---

## 🚨 Wazuh SIEM Detection Engineering

### 6.1 Custom Detection Rules Architecture

Standard SIEM rules often alert on every individual failed login, generating alert fatigue. In our custom rule architecture ([`detection-rules/brute-force-rule.xml`](detection-rules/brute-force-rule.xml) and [`detection-rules/advanced-rules.xml`](detection-rules/advanced-rules.xml)), we implement **stateful threshold correlation**:

```xml
<!-- Custom Rule 100003: 5+ Failed RDP Logons from same Source IP within 60s -->
<rule id="100003" level="10" frequency="5" timeframe="60">
  <if_matched_sid>100002</if_matched_sid>
  <same_source_ip />
  <description>Wazuh Alert: Potential RDP Brute-Force Attack Detected against $(win.system.computer) from $(win.eventdata.ipAddress) [5+ Failed Attempts in 60s]</description>
  <mitre>
    <id>T1110</id>
    <id>T1110.001</id>
  </mitre>
  <group>authentication_failures,attack,bruteforce,</group>
</rule>
```

#### Multi-Stage Compromise Rule Correlation

```xml
<!-- Rule 100011: Critical Alert - Successful Login Following Brute-Force (Compromise Confirmation) -->
<rule id="100011" level="14" timeframe="300">
  <if_sid>100010</if_sid>
  <if_matched_sid>100003</if_matched_sid>
  <same_source_ip />
  <description>CRITICAL ALERT: Successful RDP Authentication following Brute-Force Attack from $(win.eventdata.ipAddress) for user $(win.eventdata.targetUserName)! Potential Compromise!</description>
  <mitre>
    <id>T1110</id>
    <id>T1078</id>
    <id>T1021.001</id>
  </mitre>
</rule>
```

### 6.2 Rule Validation with `wazuh-logtest`

Before deploying to production, validate rules locally using `/var/ossec/bin/wazuh-logtest`:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Input:
```json
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4625"},"eventdata":{"logonType":"10","targetUserName":"Administrator","ipAddress":"192.168.56.30"}}}
```

Output:
```
**Phase 1: Completed pre-decoding.
**Phase 2: Completed decoding.
       decoder: 'windows_eventchannel'
**Phase 3: Completed filtering (rules).
       Rule id: '100002'
       Level: '7'
       Description: 'Windows: Failed Remote Desktop (RDP) Logon Attempt (Logon Type 10) from Source IP 192.168.56.30'
```

---

### 6.3 Live SIEM Dashboard Detections

When the attack simulation runs, the Wazuh Security Events dashboard correlates the events into an active Level 10 Incident:

![Wazuh Alert Correlation Dashboard](images/architecture/wazuh-dashboard/log-data-analysis.png)
*Figure 16: Wazuh Security Events Dashboard showing triggered Brute-Force alerts and MITRE ATT&CK categorization.*

![Failed Logon Distribution](images/architecture/bruteforce-alert/failed-logon-events-id-4625-when-successfully-scanning-and-deploying-to-computers.png)
*Figure 17: SIEM timeline visualization of spike in failed authentication attempts during the simulation.*

![Workload Security Overview](images/architecture/wazuh-dashboard/monitoring-and-securing-cloud-workloads-with-wazuh.png)
*Figure 18: Workload security monitoring panel highlighting endpoint threat profile.*

---

## 🎯 Threat Hunting Playbook & Cross-SIEM Queries

As an L3 Detection Engineer, threat hunting queries must be documented across the industry's major SIEM query languages.

### Wazuh / OpenSearch Dashboards Query DSL

Hunt for high-frequency logon failures aggregated by Source IP:
```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "data.win.system.eventID": "4625" } },
        { "match": { "data.win.eventdata.logonType": "10" } }
      ]
    }
  }
}
```

### Splunk SPL Threat Hunting Queries

```spl
# Hunt for RDP Brute Force & Password Spraying
index=windows sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=10
| stats count by src_ip, user, status, sub_status
| where count > 5
| sort -count

# Correlate Failed Logons followed by Successful Logon (Potential Compromise)
index=windows sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) Logon_Type=10
| transaction src_ip maxspan=15m startswith=(EventCode=4625) endswith=(EventCode=4624)
| table _time, src_ip, user, eventcount
```

### Microsoft Sentinel KQL Queries

```kusto
// Hunt for RDP Brute-Force Attacks in Microsoft Sentinel
SecurityEvent
| where EventID == 4625 and LogonType == 10
| summarize FailedAttempts = count(), 
            TargetUsers = make_set(TargetUserName), 
            FirstAttempt = min(TimeGenerated), 
            LastAttempt = max(TimeGenerated) 
            by IpAddress, Computer
| where FailedAttempts >= 5
| extend DurationMinutes = datetime_diff('minute', LastAttempt, FirstAttempt)
| order by FailedAttempts desc
```

---

## 📋 SOC Incident Response & Investigation Report

A comprehensive Incident Response Report for this engagement is located in [`reports/incident-report.md`](reports/incident-report.md).

### Summary of Triage Workflow

```
[1. Alert Ingestion]  -->  Rule 100003 triggered in Wazuh SIEM
                                    │
                                    ▼
[2. Triage & Verify]  -->  Identify Source IP (192.168.56.30) & Target User (Administrator)
                           Confirm Logon Type 10 (RDP) & Failure Codes (0xC000006D / 0xC000006A)
                                    │
                                    ▼
[3. Compromise Check] -->  Query SIEM for Event ID 4624 from 192.168.56.30 within 1 hour
                           Result: 0 Successful Logons Found (No compromise)
                                    │
                                    ▼
[4. Containment]      -->  Apply Windows Firewall Block Rule on Target Endpoint:
                           New-NetFirewallRule -DisplayName "Block-Attacker-192.168.56.30" -Direction Inbound -Action Block -RemoteAddress 192.168.56.30
                                    │
                                    ▼
[5. Eradication]      -->  Check Sysmon Event ID 1 for suspicious processes (powershell, cmd, whoami)
                           Verify no persistence registry keys added (Run / RunOnce)
                                    │
                                    ▼
[6. Recovery & Close] -->  Reset administrator account status; document lessons learned in ticket
```

---

## 🛡️ Hardening & Defensive Countermeasures

| Vulnerability Identified | Immediate Remediation | Enterprise Security Control |
|---|---|---|
| **Direct RDP Exposure** | Block TCP 3389 at perimeter firewall | Implement Remote Desktop Gateway / VPN with MFA |
| **No Pre-Authentication** | Enable Network Level Authentication (NLA) | Restricts authentication attempts to CredSSP before session setup |
| **Unlimited Guessing** | Enable Account Lockout Policy | Lock account for 15 minutes after 5 failed attempts |
| **Default User Targeted** | Rename default `Administrator` account | Disable built-in administrator; use tiered privileged accounts |
| **Manual Host Containment**| Deploy Wazuh Active Response | Automatically trigger `firewall-drop` script upon rule 100003 match |

---

## 🗂️ Repository Directory Structure

```
SOC-Detection-and-Threat-Hunting-Lab/
├── .github/
│   └── workflows/
│       ├── validate.yml               # Automated CI pipeline (XML schema check & shellcheck)
│       └── stargazer-tracker.yml      # Community engagement tracking
├── detection-rules/
│   ├── brute-force-rule.xml           # Wazuh custom rules for Windows & RDP brute-force (100001-100005)
│   └── advanced-rules.xml             # Wazuh multi-stage correlation rules (100010-100015)
├── images/
│   ├── architecture/
│   │   ├── soc-architecture/          # Architecture & dataflow diagrams
│   │   ├── wazuh-dashboard/           # SIEM dashboard & agent deployment evidence
│   │   └── bruteforce-alert/          # Windows Event ID 4625 & alert analysis
│   ├── attacks/
│   │   └── nmap-scan/                 # Nmap scan & Hydra attack execution screenshots
│   └── logs/
│       └── sysmon-process/            # Sysmon network connection & process telemetry
├── logs/
│   ├── sample-log.txt                 # Realistic Wazuh JSON alerts export
│   └── windows-events.txt             # Realistic Windows Security & Sysmon log stream
├── reports/
│   └── incident-report.md             # Enterprise-standard L3 SOC Incident Response Report
├── scripts/
│   └── attack-simulation.sh           # Automated Bash attack simulation tool (ShellCheck verified)
├── setup/
│   ├── sysmon-config.xml              # Modular, production-tuned Sysmon configuration
│   ├── wazuh-setup.md                 # Complete Wazuh SIEM deployment guide
│   └── windows-vm-setup.md            # Windows endpoint auditing & agent guide
├── CONTRIBUTING.md                    # Guidelines for contributing detection rules
├── LICENSE                            # MIT License
├── README.md                          # Master documentation & lab guide
└── SECURITY.md                        # Security policy and disclosure process
```

---

# 👤 Author

## Sandeep Mothukuri

**Senior SOC Analyst (L3) · Detection Engineering · Threat Hunting · Incident Response · Security Engineering**

Focus areas:
- Security Operations (SOC L1/L2/L3)
- Detection Engineering & Detection-as-Code
- Threat Hunting & Adversary Simulation
- SIEM / XDR Architecture (Wazuh, Splunk, Microsoft Sentinel)
- Endpoint Telemetry (Microsoft Sysmon, Windows Auditing, EDR)
- MITRE ATT&CK Framework Mapping
- Incident Response & Digital Forensics (DFIR)
- Security Automation & SOAR

- **GitHub:** [@sandeepmothukuri](https://github.com/sandeepmothukuri)
- **Website:** [cybertechnology.in](https://cybertechnology.in)
- **LinkedIn:** [linkedin.com/in/sandeepmothukuri](https://www.linkedin.com/in/sandeepmothukuri)
- **Email:** [sandeep.mothukuris@gmail.com](mailto:sandeep.mothukuris@gmail.com)

---

# 🗂️ All Repositories

| Repository Description | Focus |
|---|---|
| [AI-SOC-Decision-Engine](https://github.com/sandeepmothukuri/AI-SOC-Decision-Engine) | AI-assisted SOC decision/control plane for triage, enrichment, safety controls and analyst approval |
| [AI-Augmented-SOC-Lab](https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab) | AI-augmented SOC with Wazuh + TheHive + Ollama (LLaMA3) for analyst-assisted triage |
| [Enterprise-Detection-Engineering-SOC-Lab](https://github.com/sandeepmothukuri/Enterprise-Detection-Engineering-SOC-Lab) | 12-tool SOC lab with OpenSearch, Suricata, Zeek, MISP, Caldera, Velociraptor |
| [Autonomous-SOC-Lab](https://github.com/sandeepmothukuri/Autonomous-SOC-Lab) | Autonomous SOC with AI-driven detection and self-healing playbooks |
| [soc-threat-hunting-lab](https://github.com/sandeepmothukuri/soc-threat-hunting-lab) | Threat detection lab — Zeek, RITA, Arkime, Velociraptor, OSQuery, MISP |
| [soc-lab-free](https://github.com/sandeepmothukuri/soc-lab-free) | Free SOC lab — OpenVAS, Wazuh, pfSense, Proxmox Mail, Lynis |
| [SOC-Detection-and-Threat-Hunting-Lab](https://github.com/sandeepmothukuri/SOC-Detection-and-Threat-Hunting-Lab) | SOC analyst home lab — Wazuh, Sysmon, MITRE ATT&CK mapping and incident response |
| [PromptSentinel](https://github.com/sandeepmothukuri/PromptSentinel) | Enterprise-grade prompt injection detection and AI firewall for LLM applications |
| [PromptShield](https://github.com/sandeepmothukuri/PromptShield) | AI Security + SOC Detection Engineering Lab with prompt-security telemetry, detections and response |
| [sentinel-detection-engine](https://github.com/sandeepmothukuri/sentinel-detection-engine) | Detection-as-code for Microsoft Sentinel and Defender XDR with KQL, SOAR and ATT&CK coverage |

---

### 📄 License

This project is licensed under the MIT License — see the [`LICENSE`](LICENSE) file for details.

⭐ **Star this repository if you find it helpful for your SOC analyst journey or detection engineering research!**
