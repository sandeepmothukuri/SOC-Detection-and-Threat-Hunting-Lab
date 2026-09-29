# 🔐 Enterprise SOC Detection & Threat Hunting Lab
### Advanced Endpoint Telemetry Engineering, Custom SIEM Detection, Adversary Simulation & Full-Lifecycle Incident Response

<p align="center">
  <a href="https://github.com/sandeepmothukuri/SOC-Detection-and-Threat-Hunting-Lab/actions/workflows/validate.yml">
    <img src="https://github.com/sandeepmothukuri/SOC-Detection-and-Threat-Hunting-Lab/actions/workflows/validate.yml/badge.svg" alt="Lab Validation">
  </a>
  <a href="https://wazuh.com/">
    <img src="https://img.shields.io/badge/SIEM-Wazuh%20v4.7-0066CC?style=for-the-badge&logo=wazuh&logoColor=white" alt="Wazuh SIEM">
  </a>
  <a href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon">
    <img src="https://img.shields.io/badge/Endpoint-Microsoft%20Sysmon%20v15-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Microsoft Sysmon">
  </a>
  <a href="https://attack.mitre.org/">
    <img src="https://img.shields.io/badge/MITRE%20ATT%26CK-v14.1%20Coverage-ED1C24?style=for-the-badge" alt="MITRE ATT&CK">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-success?style=for-the-badge" alt="License: MIT">
  </a>
</p>

---

## 📌 Executive Overview

This repository documents an enterprise-grade **Security Operations Center (SOC) Detection and Threat Hunting Lab**. Designed and engineered by an L3 Senior SOC Analyst, this environment demonstrates the complete security operations lifecycle: from baseline telemetry engineering and adversary simulation to custom SIEM correlation rule authoring, multi-platform threat hunting, and tactical incident response.

The core scenario targets a critical real-world attack vector: **Automated Network Service Discovery and Remote Desktop Protocol (RDP) Credential Stuffing / Brute-Force**. Using granular telemetry sources (**Microsoft Sysmon** and **Windows Advanced Security Auditing**), the lab correlates low-level endpoint signals into high-fidelity detection alerts in **Wazuh SIEM**, eliminating false positives while ensuring zero breach exposure.

> [!NOTE]  
> All detection rules, Sysmon configurations, automated simulation scripts, and forensic exhibits in this project are validated, reproducible, and ready for immediate deployment in local lab or enterprise test environments.

---

## ⚡ Quick Reference: Detection & Simulation Matrix

| Operational Phase | Technical Details | Telemetry Artifact |
|:---|:---|:---|
| **Adversary Platform** | Kali Linux (`192.168.56.30`) | `nmap`, `hydra`, bash simulation harnesses |
| **Attack Vector** | TCP Port Reconnaissance & RDP Password Spraying | MITRE ATT&CK: **T1046**, **T1110.001**, **T1021.001** |
| **Target Host** | Windows 10/11 Enterprise (`192.168.56.20`) | Microsoft Sysmon v15 + Windows Security Auditing |
| **SIEM & Analytics** | Wazuh 4.7 Central Manager + OpenSearch Indexer (`192.168.56.10`) | Real-time eventchannel decoder + correlation engine |
| **Endpoint Telemetry** | High-frequency Logon Failures (Logon Type 10) & Inbound TCP | Windows Event ID **4625**, **4740**, Sysmon Event ID **3**, **1** |
| **Detection Engine** | Stateful correlation: 5+ failed RDP attempts within 60s from same IP | Wazuh Custom Rule **100003** (Level 10 Alert) |
| **Active Response** | Automated host isolation / dynamic IP drop on attacker | Wazuh `firewall-drop` script execution |
| **Incident Outcome** | Real-time alert generation; automatic account lockout; attacker IP contained | **Zero Compromise** (No Event ID 4624 generated) |

---

## 📑 Table of Contents

1. [Lab Architecture & Network Topology](#1-lab-architecture--network-topology)
2. [Hardware Sizing & Environment Prerequisites](#2-hardware-sizing--environment-prerequisites)
3. [Step-by-Step Installation & Deployment](#3-step-by-step-installation--deployment)
   - [3.1 Wazuh SIEM Central Server Deployment](#31-wazuh-siem-central-server-deployment)
   - [3.2 Windows Endpoint Security Auditing Configuration](#32-windows-endpoint-security-auditing-configuration)
   - [3.3 Microsoft Sysmon Deployment & Configuration](#33-microsoft-sysmon-deployment--configuration)
   - [3.4 Wazuh Windows Agent Silent Enrollment](#34-wazuh-windows-agent-silent-enrollment)
4. [Red-Team Attack Simulation](#4-red-team-attack-simulation)
   - [Phase 1: Network Reconnaissance & Port Scanning (T1046)](#phase-1-network-reconnaissance--port-scanning-mitre-t1046)
   - [Phase 2: Automated RDP Brute-Force Attack (T1110.001)](#phase-2-automated-rdp-brute-force-attack-mitre-t1110001)
   - [Automated Attack Script Execution](#automated-attack-script-execution)
5. [Blue-Team Endpoint Telemetry & Forensic Artifacts](#5-blue-team-endpoint-telemetry--forensic-artifacts)
   - [5.1 Windows Security Event Log Forensics (4625, 4624, 4740)](#51-windows-security-event-log-forensics)
   - [5.2 Deep-Dive: NTSTATUS Failure Codes & User Enumeration](#52-deep-dive-ntstatus-failure-codes--user-enumeration)
   - [5.3 Deep-Dive: Logon Type 10 (RemoteInteractive) vs Logon Type 3 (Network)](#53-deep-dive-logon-type-10-remoteinteractive-vs-logon-type-3-network)
   - [5.4 Microsoft Sysmon Network & Process Telemetry (EID 3, EID 1)](#54-microsoft-sysmon-network--process-telemetry-eid-3-eid-1)
6. [SIEM Detection Engineering (Wazuh Rules)](#6-siem-detection-engineering-wazuh-rules)
   - [6.1 Custom Detection Rule Architecture](#61-custom-detection-rule-architecture)
   - [6.2 Rule Testing & Verification with `wazuh-logtest`](#62-rule-testing--verification-with-wazuh-logtest)
   - [6.3 Live SIEM Dashboard & Alert Triage](#63-live-siem-dashboard--alert-triage)
   - [6.4 Automated Active Response (Auto-Block Attacker IP)](#64-automated-active-response-auto-block-attacker-ip)
7. [Threat Hunting Playbook & Multi-SIEM Queries](#7-threat-hunting-playbook--multi-siem-queries)
   - [Wazuh / OpenSearch Query DSL](#wazuh--opensearch-query-dsl)
   - [Splunk Search Processing Language (SPL)](#splunk-search-processing-language-spl)
   - [Microsoft Sentinel KQL](#microsoft-sentinel-kql)
8. [SOC Incident Response & Investigation Playbook](#8-soc-incident-response--investigation-playbook)
9. [Hardening & Defensive Countermeasures](#9-hardening--defensive-countermeasures)
10. [Operational Troubleshooting & Verification FAQ](#10-operational-troubleshooting--verification-faq)
11. [Senior SOC Analyst Interview & Defense Guide](#11-senior-soc-analyst-interview--defense-guide)
12. [📸 Complete Visual Evidence Gallery](#12--complete-visual-evidence-gallery)
13. [Repository Structure](#13-repository-structure)
14. [Author Profile & Portfolio](#14-author)

---

## 1. Lab Architecture & Network Topology

The lab operates inside an isolated, non-routed virtual network (`192.168.56.0/24`) designed to replicate an enterprise branch subnet. The architecture isolates attacker traffic while maintaining full visibility via centralized log forwarding.

```
                             +---------------------------------------------+
                             |           KALI LINUX (ATTACKER)             |
                             |              192.168.56.30                  |
                             |      Tools: Nmap, Hydra, Wordlists          |
                             +---------------------------------------------+
                                                    |
                                                    | [1] TCP Port Scan (Port 3389)
                                                    | [2] RDP Brute-Force Password Spray
                                                    v
+---------------------------------------------------------------------------------------------------+
|                                  WINDOWS 10/11 VICTIM ENDPOINT                                    |
|                                          192.168.56.20                                            |
|                                                                                                   |
|   +---------------------------------------+       +-------------------------------------------+   |
|   |       Windows Security Auditing       |       |             Microsoft Sysmon              |   |
|   |  - Event ID 4625 (Logon Failure)      |       |  - Event ID 3 (Network Connection to 3389)|   |
|   |  - Event ID 4624 (Logon Success)      |       |  - Event ID 1 (Process Execution)         |   |
|   |  - Event ID 4740 (Account Lockout)    |       |  - Event ID 10 (LSASS Memory Access)      |   |
|   +---------------------------------------+       +-------------------------------------------+   |
|                                           |                                                       |
|                                           | Forward via Windows Event Channel                     |
|                                           v                                                       |
|                         +-----------------------------------+                                     |
|                         |        Wazuh Windows Agent        |                                     |
|                         |    ossec-agent (Encrypted 1514)   |                                     |
|                         +-----------------------------------+                                     |
+---------------------------------------------------------------------------------------------------+
                                                    |
                                                    | TLS-Encrypted Log Forwarding (TCP 1514)
                                                    v
+---------------------------------------------------------------------------------------------------+
|                                    WAZUH SIEM CENTRAL SERVER                                      |
|                                          192.168.56.10                                            |
|                                                                                                   |
|   +-------------------------------+   +-------------------------------+   +-------------------+   |
|   |         Wazuh Manager         |   |         Wazuh Indexer         |   |  Wazuh Dashboard  |   |
|   |  - XML Decoders & Pre-filters |-->|  - OpenSearch Log Store       |-->|  - Web UI (HTTPS) |   |
|   |  - Custom Correlation Rules   |   |  - Real-time Alert Indexing   |   |  - Alert Triage   |   |
|   +-------------------------------+   +-------------------------------+   +-------------------+   |
+---------------------------------------------------------------------------------------------------+
```

### Visual Architecture & Components

<p align="center">
  <img src="images/architecture/soc-architecture/architecture.png" width="850" alt="SOC Lab Architecture" />
  <br>
  <em><b>Figure 1:</b> High-level SOC Lab Architecture and telemetry ingestion pipeline from endpoint to SIEM.</em>
</p>

<p align="center">
  <img src="images/architecture/soc-architecture/wazuh-central-components.png" width="850" alt="Wazuh Central Components" />
  <br>
  <em><b>Figure 2:</b> Wazuh Server core daemons: Manager analysis engine, Filebeat log shipper, and OpenSearch Indexer.</em>
</p>

<p align="center">
  <img src="images/architecture/soc-architecture/combining-elk-wazuh-hids-and-elastalert-for-optimal-performance.png" width="850" alt="ELK and Wazuh Pipeline" />
  <br>
  <em><b>Figure 3:</b> End-to-end data processing: Event decoding, rule threshold matching, and alerting.</em>
</p>

<p align="center">
  <img src="images/architecture/soc-architecture/elastic-stack-integration.png" width="850" alt="Elastic Stack Integration" />
  <br>
  <em><b>Figure 4:</b> Distributed OpenSearch / Elastic stack schema mapping for endpoint telemetry events.</em>
</p>

---

## 2. Hardware Sizing & Environment Prerequisites

| Node Role | Operating System | vCPUs | RAM | Storage | Static IP Address |
|:---|:---|:---:|:---:|:---:|:---|
| **SIEM Server** | Ubuntu Server 22.04 LTS (64-bit) | 4 | 8 GB | 60 GB SSD | `192.168.56.10` |
| **Victim Host** | Windows 10/11 Enterprise | 2 | 4 GB | 40 GB SSD | `192.168.56.20` |
| **Attacker** | Kali Linux 2024.x | 2 | 2 GB | 30 GB SSD | `192.168.56.30` |

### Required Network Firewall Ports

- **TCP 1514:** Wazuh Agent secure event forwarding.
- **TCP 1515:** Wazuh Agent enrollment daemon (`authd`).
- **TCP 55000:** Wazuh RESTful Management API.
- **TCP 443:** Wazuh Web Console (HTTPS).
- **TCP 3389:** Windows Remote Desktop Protocol (target service).

---

## 3. Step-by-Step Installation & Deployment

### 3.1 Wazuh SIEM Central Server Deployment

For exhaustive manual configuration steps, refer to [`setup/wazuh-setup.md`](setup/wazuh-setup.md).

```bash
# 1. Update OS packages and install core utilities
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl apt-transport-https lsb-release gnupg2 tar ufw

# 2. CRITICAL: Configure Kernel Memory Map Count for OpenSearch/Wazuh Indexer
# Wazuh Indexer requires vm.max_map_count >= 262144 to prevent fatal startup crashes
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# 3. Configure Host Firewall (UFW)
sudo ufw allow 1514/tcp comment "Wazuh Agent Events"
sudo ufw allow 1515/tcp comment "Wazuh Agent Enrollment"
sudo ufw allow 55000/tcp comment "Wazuh REST API"
sudo ufw allow 443/tcp comment "Wazuh Dashboard Web UI"
sudo ufw enable

# 4. Deploy Wazuh All-in-One Architecture via Automated Assistant
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml
sudo bash wazuh-install.sh -a

# 5. Extract generated cluster credentials
sudo tar -xvf wazuh-install-files.tar
sudo cat wazuh-install-files/wazuh-passwords.txt
```

Verify that all central services are running:
```bash
sudo systemctl status wazuh-indexer wazuh-manager wazuh-dashboard
```

---

### 3.2 Windows Endpoint Security Auditing Configuration

For complete endpoint preparation commands, see [`setup/windows-vm-setup.md`](setup/windows-vm-setup.md).

Open an elevated PowerShell terminal (`Run as Administrator`) on `WIN10-ENDPOINT`:

```powershell
# 1. Enable Remote Desktop (Port 3389) and configure firewall
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# 2. Configure Network Level Authentication (NLA)
# Simulation Option: Disable NLA so brute-force tools generate Logon Type 10 (RemoteInteractive)
(Get-WmiObject -Class Win32_TSGeneralSetting -Namespace root\cimv2\TerminalServices -Filter "TerminalName='RDP-Tcp'").SetUserAuthenticationRequired(0)

# 3. Configure Advanced Audit Policies (Captures 4624, 4625, 4672, 4740)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# 4. Enable Process Creation and Command-Line Auditing
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 1 -Force
```

---

### 3.3 Microsoft Sysmon Deployment & Configuration

Deploy Microsoft Sysmon with our production-tuned configuration [`setup/sysmon-config.xml`](setup/sysmon-config.xml):

```powershell
# 1. Create staging directory and download Sysmon
New-Item -ItemType Directory -Path "C:\Tools" -Force
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Tools\Sysmon.zip"
Expand-Archive -Path "C:\Tools\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force

# 2. Install Sysmon using the lab configuration
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i C:\Users\sande\Documents\AntiGravity\new repo\SOC-Detection-and-Threat-Hunting-Lab\setup\sysmon-config.xml

# 3. Verify running driver service
Get-Service -Name "Sysmon64"
```

---

### 3.4 Wazuh Windows Agent Silent Enrollment

```powershell
# 1. Verify Network Connectivity to Wazuh Manager Port 1514 (Agent Telemetry)
Test-NetConnection -ComputerName "192.168.56.10" -Port 1514

# 2. Download and silently install Wazuh Agent MSI
$ManagerIP = "192.168.56.10"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi" -OutFile "C:\Tools\wazuh-agent.msi"

Start-Process msiexec.exe -Wait -ArgumentList "/i C:\Tools\wazuh-agent.msi /q WAZUH_MANAGER='$ManagerIP' WAZUH_REGISTRATION_SERVER='$ManagerIP'"

# 3. Ensure ossec.conf includes Security and Sysmon channels
# Path: C:\Program Files (x86)\ossec-agent\ossec.conf

# 4. Start Agent Service
Restart-Service -Name "WazuhSvc"
Get-Service -Name "WazuhSvc"
```

Verify that the agent registers as **Active** in the Wazuh Dashboard:

<p align="center">
  <img src="images/architecture/wazuh-dashboard/wazuh-dashboard-and-agent-deployment.png" width="850" alt="Wazuh Agent Dashboard" />
  <br>
  <em><b>Figure 5:</b> Wazuh SIEM Dashboard confirming active agent connection and continuous log transmission.</em>
</p>

---

## 4. Red-Team Attack Simulation

### Phase 1: Network Reconnaissance & Port Scanning (MITRE T1046)

From the Kali Linux terminal (`192.168.56.30`), the attacker executes a stealth TCP SYN scan targeting the exposed Remote Desktop port:

```bash
# Stealth TCP SYN scan targeting Port 3389
nmap -sS -sV -p 3389 -Pn 192.168.56.20
```

<p align="center">
  <img src="images/attacks/nmap-scan/nmap-scan-terminal-kali.webp" width="850" alt="Nmap Reconnaissance in Kali" />
  <br>
  <em><b>Figure 6:</b> Kali Linux attacker terminal launching Nmap port scan against the target endpoint.</em>
</p>

<p align="center">
  <img src="images/attacks/nmap-scan/nmap-external-port-scan-result.webp" width="850" alt="Nmap Port Scan Result" />
  <br>
  <em><b>Figure 7:</b> Nmap scan output confirming port 3389/tcp is OPEN (Service: ms-wbt-server).</em>
</p>

<p align="center">
  <img src="images/attacks/nmap-scan/interpreting-scan-results.png" width="850" alt="Interpreting Nmap Results" />
  <br>
  <em><b>Figure 8:</b> Reconnaissance assessment confirming direct RDP exposure ready for credential brute-forcing.</em>
</p>

---

### Phase 2: Automated RDP Brute-Force Attack (MITRE T1110.001)

The attacker prepares the dictionary wordlist and launches an automated password guessing attack using Hydra:

```bash
# Decompress rockyou wordlist if compressed in standard Kali installation
[ -f /usr/share/wordlists/rockyou.txt ] || sudo gzip -d -k /usr/share/wordlists/rockyou.txt.gz

# Execute automated RDP password spraying against Administrator
hydra -V -t 4 -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.56.20
```

<p align="center">
  <img src="images/attacks/nmap-scan/brute-force-attack.jpg" width="850" alt="Hydra Brute-Force Execution" />
  <br>
  <em><b>Figure 9:</b> Hydra automated RDP credential attack in progress against target endpoint.</em>
</p>

---

### Automated Attack Script Execution

To streamline replication, use the included production script [`scripts/attack-simulation.sh`](scripts/attack-simulation.sh):

```bash
# Grant execution permissions
chmod +x scripts/attack-simulation.sh

# Run end-to-end simulation (Reconnaissance + Brute-Force)
./scripts/attack-simulation.sh -t 192.168.56.20 -u Administrator -m all
```

---

## 5. Blue-Team Endpoint Telemetry & Forensic Artifacts

### 5.1 Windows Security Event Log Forensics

The brute-force attack generates rapid **Audit Failure** entries under **Event ID 4625** in the Windows Security Log.

<p align="center">
  <img src="images/logs/sysmon-process/generated-event-is-recorded-in-the-windows-event-log.png" width="850" alt="Windows Security Log Stream" />
  <br>
  <em><b>Figure 10:</b> Windows Event Viewer showing rapid burst of failed logon entries (Event ID 4625).</em>
</p>

<p align="center">
  <img src="images/architecture/bruteforce-alert/event-4625-failed-to-logon.png" width="850" alt="Event ID 4625 Details" />
  <br>
  <em><b>Figure 11:</b> Forensic details of Event ID 4625 confirming Logon Type 10 (RemoteInteractive).</em>
</p>

<p align="center">
  <img src="images/architecture/bruteforce-alert/windows-event-id-4625-failed-logon.png" width="850" alt="Failure Status Codes" />
  <br>
  <em><b>Figure 12:</b> Security event parameters showing Status 0xC000006D and Substatus 0xC000006A.</em>
</p>

<p align="center">
  <img src="images/architecture/bruteforce-alert/process-information.png" width="850" alt="Process Information 4625" />
  <br>
  <em><b>Figure 13:</b> Event Process Information confirming caller process svchost.exe (TermService).</em>
</p>

#### Forensic Event Fields Matrix

| Telemetry Field | Observed Value | Forensic Interpretation |
|:---|:---|:---|
| **EventID** | `4625` | Security Audit: An account failed to log on |
| **LogonType** | `10` | **RemoteInteractive** (Terminal Services / RDP logon attempt) |
| **Status** | `0xC000006D` | `STATUS_LOGON_FAILURE`: Invalid logon credentials |
| **SubStatus** | `0xC000006A` | `STATUS_PASSWORD_MUST_CHANGE` / Valid username, incorrect password |
| **TargetUserName** | `Administrator` | The targeted account under brute-force |
| **IpAddress** | `192.168.56.30` | Source IP address of the attacking host |
| **CallerProcessName**| `C:\Windows\System32\svchost.exe` | Windows Terminal Services hosting process |

When the attack crosses the lockout threshold, Windows generates **Event ID 4740**:

```
Log Name:      Security
Event ID:      4740
Description:   A user account was locked out.
Target Account Name: Administrator
Caller Computer Name: WIN10-ENDPOINT
```

---

### 5.2 Deep-Dive: NTSTATUS Failure Codes & User Enumeration

In Windows Security Event ID 4625, the combination of **Status** and **SubStatus** codes reveals the exact failure mechanism:

| Status Code | SubStatus Code | Meaning / Mechanism | SOC Analyst Triage Insight |
|:---:|:---:|:---|:---|
| `0xC000006D` | `0xC000006A` | Valid user name, bad password | **Targeted Password Guessing:** Attacker knows a valid account name and is testing passwords. |
| `0xC000006D` | `0xC0000064` | User name does not exist | **User Enumeration / Spraying:** Attacker is cycling through usernames to map active directory accounts. |
| `0xC000006D` | `0xC0000234` | Account is currently locked out | **Denial of Service / Threshold Hit:** Brute-force threshold crossed; account locked. |
| `0xC000006D` | `0xC0000072` | Account is currently disabled | **Dormant Account Target:** Attacker attempting to authenticate against an administrative account left inactive. |
| `0xC000006D` | `0xC000006E` | Account restriction (workstation/time) | **Unauthorized Endpoint:** User tried to authenticate from an unauthorized IP or outside permitted hours. |

---

### 5.3 Deep-Dive: Logon Type 10 (RemoteInteractive) vs Logon Type 3 (Network)

Understanding the logon type is essential for accurately writing detection rules:

- **Logon Type 10 (RemoteInteractive):** Generated when an interactive remote desktop terminal session is established *prior* to credential validation (e.g. RDP connections with **Network Level Authentication disabled**).
- **Logon Type 3 (Network):** Generated when authentication occurs over the network before an interactive desktop is spawned (e.g. RDP connections with **Network Level Authentication enabled** using CredSSP, or SMB / WinRM connections).
- **Logon Type 2 (Interactive):** Physical console logon at the machine keyboard/monitor.
- **Logon Type 7 (Unlock):** Workstation unlock attempt after lock screen.

---

### 5.4 Microsoft Sysmon Network & Process Telemetry (EID 3, EID 1)

Sysmon captures network session initiations and process lineage independently from Windows Security logs:

<p align="center">
  <img src="images/logs/sysmon-process/sysmon-logs-network.png" width="850" alt="Sysmon Operational Log" />
  <br>
  <em><b>Figure 14:</b> Sysmon Operational Log capturing inbound network telemetry on port 3389.</em>
</p>

<p align="center">
  <img src="images/logs/sysmon-process/sysmon-event-id-3---rdp-logon-issue-initiated--field-always-false.png" width="850" alt="Sysmon Event ID 3 Details" />
  <br>
  <em><b>Figure 15:</b> Forensic breakdown of Sysmon Event ID 3: Inbound TCP session to destination port 3389.</em>
</p>

<p align="center">
  <img src="images/logs/sysmon-process/workstation-logs.png" width="850" alt="Workstation Logs Overview" />
  <br>
  <em><b>Figure 16:</b> Consolidated endpoint telemetry streaming in real time to the Wazuh SIEM collector.</em>
</p>

---

## 6. SIEM Detection Engineering (Wazuh Rules)

### 6.1 Custom Detection Rule Architecture

Located in [`detection-rules/brute-force-rule.xml`](detection-rules/brute-force-rule.xml) and [`detection-rules/advanced-rules.xml`](detection-rules/advanced-rules.xml), our rules use **stateful threshold correlation**:

```xml
<!-- Rule 100002: Identify RDP Logon Failures (Logon Type 10) -->
<rule id="100002" level="7">
  <if_sid>100001</if_sid>
  <field name="win.eventdata.logonType">^10$</field>
  <description>Windows: Failed Remote Desktop (RDP) Logon Attempt from Source IP $(win.eventdata.ipAddress)</description>
  <mitre>
    <id>T1110.001</id>
    <id>T1021.001</id>
  </mitre>
  <group>authentication_failed,rdp_failure,</group>
</rule>

<!-- Rule 100003: Stateful Threshold - 5+ Failed Attempts in 60s from same IP -->
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

<!-- Rule 100011: Critical Correlation - Successful Logon Following Brute-Force (Compromise) -->
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
  <group>attack_success,compromise,</group>
</rule>
```

---

### 6.2 Rule Testing & Verification with `wazuh-logtest`

Verify rules on the Wazuh Manager before deploying to production:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Input JSON:
```json
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4625"},"eventdata":{"logonType":"10","targetUserName":"Administrator","ipAddress":"192.168.56.30"}}}
```

Expected Output:
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

### 6.3 Live SIEM Dashboard & Alert Triage

<p align="center">
  <img src="images/architecture/wazuh-dashboard/log-data-analysis.png" width="850" alt="Wazuh SIEM Security Events Dashboard" />
  <br>
  <em><b>Figure 17:</b> Live Wazuh Security Events dashboard displaying triggered Level 10 Brute-Force alerts.</em>
</p>

<p align="center">
  <img src="images/architecture/bruteforce-alert/failed-logon-events-id-4625-when-successfully-scanning-and-deploying-to-computers.png" width="850" alt="Failed Logon Spike Histogram" />
  <br>
  <em><b>Figure 18:</b> Temporal histogram showing the sharp spike in Event ID 4625 during automated attack execution.</em>
</p>

<p align="center">
  <img src="images/architecture/wazuh-dashboard/monitoring-and-securing-cloud-workloads-with-wazuh.png" width="850" alt="Workload Security Monitoring" />
  <br>
  <em><b>Figure 19:</b> Workload security monitoring dashboard highlighting host security posture and metrics.</em>
</p>

<p align="center">
  <img src="images/architecture/wazuh-dashboard/monitoring-microsoft-graph-services-with-wazuh.png" width="850" alt="Microsoft Graph Monitoring" />
  <br>
  <em><b>Figure 20:</b> Microsoft Graph and Identity service security telemetry integrated within Wazuh.</em>
</p>

---

### 6.4 Automated Active Response (Auto-Block Attacker IP)

Wazuh features native Active Response capabilities to execute remediation scripts upon rule matches. To automatically block any host initiating an RDP brute-force attack:

Add to `/var/ossec/etc/ossec.conf` on the Wazuh Manager:

```xml
<!-- Define Active Response Command -->
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- Trigger dynamic firewall block on Rule 100003 for 10 minutes -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100003</rules_id>
  <timeout>600</timeout>
</active-response>
```

---

## 7. Threat Hunting Playbook & Multi-SIEM Queries

### Wazuh / OpenSearch Query DSL

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "data.win.system.eventID": "4625" } },
        { "match": { "data.win.eventdata.logonType": "10" } }
      ],
      "filter": [
        { "range": { "timestamp": { "gte": "now-24h" } } }
      ]
    }
  }
}
```

### Splunk Search Processing Language (SPL)

```spl
# Hunt for RDP Brute-Force & Password Spraying
index=windows sourcetype="WinEventLog:Security" EventCode=4625 Logon_Type=10
| stats count by src_ip, user, status, sub_status
| where count >= 5
| sort -count

# Correlate Failed Logons followed by Successful Logon (Post-Bruteforce Compromise)
index=windows sourcetype="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) Logon_Type=10
| transaction src_ip maxspan=15m startswith=(EventCode=4625) endswith=(EventCode=4624)
| table _time, src_ip, user, eventcount
```

### Microsoft Sentinel KQL

```kusto
// Detect RDP Brute-Force Activity
SecurityEvent
| where EventID == 4625 and LogonType == 10
| summarize FailedCount = count(), 
            TargetedUsers = make_set(TargetUserName), 
            FirstAttempt = min(TimeGenerated), 
            LastAttempt = max(TimeGenerated) 
            by IpAddress, Computer
| where FailedCount >= 5
| extend DurationMinutes = datetime_diff('minute', LastAttempt, FirstAttempt)
| order by FailedCount desc
```

---

## 8. SOC Incident Response & Investigation Playbook

A complete L3 Incident Response Report for Case `INC-2026-0912-001` is maintained in [`reports/incident-report.md`](reports/incident-report.md).

```
   [1. Alert Ingestion]  -->  Rule 100003 fires (Level 10) in Wazuh SIEM
                                       │
                                       ▼
   [2. Triage & Verify]  -->  Extract Attacking IP (192.168.56.30) & Target (Administrator)
                              Verify Logon Type 10 (RDP) & Failure Reason (0xC000006A)
                                       │
                                       ▼
   [3. Compromise Check] -->  Query SIEM for Event ID 4624 from 192.168.56.30
                              Result: 0 Successful Logons Found (No compromise)
                                       │
                                       ▼
   [4. Host Containment] -->  Block Attacker IP on Target Endpoint Firewall:
                              New-NetFirewallRule -DisplayName "Block-192.168.56.30" -Action Block -RemoteAddress 192.168.56.30
                                       │
                                       ▼
   [5. Eradication]      -->  Inspect Sysmon Event ID 1 for unauthorized processes
                              Verify persistence registry keys are clean
                                       │
                                       ▼
   [6. Recovery & Close] -->  Reset account lockout; document findings in Incident Ticket
```

---

## 9. Hardening & Defensive Countermeasures

| Identified Vulnerability | Immediate Remediation | Enterprise Security Control |
|:---|:---|:---|
| **Direct RDP Exposure** | Block TCP 3389 at host/perimeter firewall | Deploy Remote Desktop Gateway / VPN with MFA |
| **No Pre-Authentication** | Enable Network Level Authentication (NLA) | Requires pre-session authentication via CredSSP |
| **Unlimited Password Guessing**| Configure Account Lockout Policy | Lock account for 15 minutes after 5 failed attempts |
| **Privileged Account Targeted**| Rename default `Administrator` account | Disable built-in Administrator; enforce tiered admin accounts |
| **Manual Host Containment** | Configure Wazuh Active Response | Automatically trigger `firewall-drop` script on Rule 100003 |

---

## 10. Operational Troubleshooting & Verification FAQ

### Q1: Wazuh Indexer fails to start on Ubuntu with error `max virtual memory areas vm.max_map_count [65530] is too low`
- **Root Cause:** OpenSearch requires kernel virtual memory allocation limits of at least 262,144 areas.
- **Fix:** Execute `sudo sysctl -w vm.max_map_count=262144` and persist it by adding `vm.max_map_count=262144` to `/etc/sysctl.conf`. Then restart the indexer: `sudo systemctl restart wazuh-indexer`.

### Q2: Hydra throws `file not found` when using `/usr/share/wordlists/rockyou.txt` on Kali
- **Root Cause:** Kali Linux ships `rockyou.txt` compressed as `rockyou.txt.gz`.
- **Fix:** Run `sudo gzip -d -k /usr/share/wordlists/rockyou.txt.gz` (the `-k` flag decompresses while preserving the original gzip file).

### Q3: Windows Agent shows status 'Disconnected' in Wazuh Dashboard
- **Root Cause:** Host firewall on Ubuntu blocking TCP port 1514 or Wazuh Agent service stopped on Windows.
- **Fix:** On Windows, test connectivity: `Test-NetConnection -ComputerName 192.168.56.10 -Port 1514`. On Ubuntu, ensure `sudo ufw allow 1514/tcp` is applied.

### Q4: Why does Event ID 4625 show Logon Type 3 instead of Logon Type 10?
- **Root Cause:** If **Network Level Authentication (NLA)** is enabled on Windows, authentication occurs at the network layer via CredSSP before initiating the terminal session, yielding Logon Type 3. Disabling NLA or connecting via non-NLA RDP prompts generates Logon Type 10.

---

## 11. Senior SOC Analyst Interview & Defense Guide

When discussing this lab during a Senior SOC Analyst / Detection Engineer interview:

### 1. "How do you distinguish between an automated brute-force attack and a password spray attack?"
> *"In a **brute-force attack**, the attacker targets one or a few accounts with thousands of passwords in rapid succession from an IP, quickly triggering account lockouts and high-frequency Event ID 4625 spikes on that specific user. In a **password spray attack**, the attacker tries 1 or 2 common passwords against hundreds of different user accounts across hours to stay beneath account lockout thresholds and evade simple count-based detection."*

### 2. "Why deploy Sysmon if Windows Security Auditing already captures Event ID 4625?"
> *"Windows Event 4625 captures authentication attempts at the OS security boundary, but does not provide granular process lineage or network connection details. **Sysmon Event ID 3** records the raw socket connection, identifying whether the inbound connection was handled by `svchost.exe` (legitimate RDP) or a rogue listening port. If an attacker succeeds, **Sysmon Event ID 1** immediately records any shell (`cmd.exe`, `powershell.exe`) or discovery utility (`whoami.exe`) spawned by `rdpclip.exe` or `svchost.exe`, capturing command-line arguments and process hashes."*

### 3. "How would you eliminate false positives from vulnerability scanners (e.g., Nessus, Qualys) triggering your brute-force rule?"
> *"I implement whitelist exceptions in Wazuh detection rules based on known scanner IP subnets and dedicated scanning service accounts, while maintaining strict rate limits. For example, adding `<check_diff />` or `<condition negative="yes">` on verified security scanner source IPs, ensuring legitimate vulnerability assessments do not trigger critical incident alerts."*

---

## 12. 📸 Complete Visual Evidence Gallery

This project incorporates a curated portfolio of **20 forensic and operational screenshots** detailing every layer of the detection lifecycle:

### Category A: Architecture & Telemetry Pipeline
| ID | Artifact Path | Operational Context |
|:---:|:---|:---|
| **Fig 1** | [`images/architecture/soc-architecture/architecture.png`](images/architecture/soc-architecture/architecture.png) | End-to-end SOC Lab Architecture & Dataflow |
| **Fig 2** | [`images/architecture/soc-architecture/wazuh-central-components.png`](images/architecture/soc-architecture/wazuh-central-components.png) | Wazuh Manager, Filebeat, and OpenSearch Components |
| **Fig 3** | [`images/architecture/soc-architecture/combining-elk-wazuh-hids-and-elastalert-for-optimal-performance.png`](images/architecture/soc-architecture/combining-elk-wazuh-hids-and-elastalert-for-optimal-performance.png) | Telemetry Ingestion, Decoding, and Rule Engine Flow |
| **Fig 4** | [`images/architecture/soc-architecture/elastic-stack-integration.png`](images/architecture/soc-architecture/elastic-stack-integration.png) | Distributed Indexing & Telemetry Aggregation Architecture |

### Category B: Agent Deployment & Monitoring
| ID | Artifact Path | Operational Context |
|:---:|:---|:---|
| **Fig 5** | [`images/architecture/wazuh-dashboard/wazuh-dashboard-and-agent-deployment.png`](images/architecture/wazuh-dashboard/wazuh-dashboard-and-agent-deployment.png) | Active Agent Deployment Verification Console |

### Category C: Attack Simulation & Reconnaissance
| ID | Artifact Path | Operational Context |
|:---:|:---|:---|
| **Fig 6** | [`images/attacks/nmap-scan/nmap-scan-terminal-kali.webp`](images/attacks/nmap-scan/nmap-scan-terminal-kali.webp) | Nmap SYN Reconnaissance (`T1046`) in Kali Terminal |
| **Fig 7** | [`images/attacks/nmap-scan/nmap-external-port-scan-result.webp`](images/attacks/nmap-scan/nmap-external-port-scan-result.webp) | Nmap External Port Scan Output (`3389/tcp open`) |
| **Fig 8** | [`images/attacks/nmap-scan/interpreting-scan-results.png`](images/attacks/nmap-scan/interpreting-scan-results.png) | Service Fingerprinting and Attack Surface Analysis |
| **Fig 9** | [`images/attacks/nmap-scan/brute-force-attack.jpg`](images/attacks/nmap-scan/brute-force-attack.jpg) | Hydra RDP Automated Brute-Force Attack (`T1110.001`) |

### Category D: Windows Security Event Forensics
| ID | Artifact Path | Operational Context |
|:---:|:---|:---|
| **Fig 10** | [`images/logs/sysmon-process/generated-event-is-recorded-in-the-windows-event-log.png`](images/logs/sysmon-process/generated-event-is-recorded-in-the-windows-event-log.png) | Windows Event Viewer capturing Event ID 4625 Stream |
| **Fig 11** | [`images/architecture/bruteforce-alert/event-4625-failed-to-logon.png`](images/architecture/bruteforce-alert/event-4625-failed-to-logon.png) | Event ID 4625 Record confirming Logon Type 10 |
| **Fig 12** | [`images/architecture/bruteforce-alert/windows-event-id-4625-failed-logon.png`](images/architecture/bruteforce-alert/windows-event-id-4625-failed-logon.png) | Failure Codes Analysis (`0xC000006D` / `0xC000006A`) |
| **Fig 13** | [`images/architecture/bruteforce-alert/process-information.png`](images/architecture/bruteforce-alert/process-information.png) | Process Caller Inspection identifying `svchost.exe` |

### Category E: Microsoft Sysmon Endpoint Telemetry
| ID | Artifact Path | Operational Context |
|:---:|:---|:---|
| **Fig 14** | [`images/logs/sysmon-process/sysmon-logs-network.png`](images/logs/sysmon-process/sysmon-logs-network.png) | Sysmon Operational Event Log Network Stream |
| **Fig 15** | [`images/logs/sysmon-process/sysmon-event-id-3---rdp-logon-issue-initiated--field-always-false.png`](images/logs/sysmon-process/sysmon-event-id-3---rdp-logon-issue-initiated--field-always-false.png) | Sysmon Event ID 3 Forensic Inbound Connection Record |
| **Fig 16** | [`images/logs/sysmon-process/workstation-logs.png`](images/logs/sysmon-process/workstation-logs.png) | Workstation Telemetry Log Stream Forwarding |

### Category F: SIEM Analytics & Identity Monitoring
| ID | Artifact Path | Operational Context |
|:---:|:---|:---|
| **Fig 17** | [`images/architecture/wazuh-dashboard/log-data-analysis.png`](images/architecture/wazuh-dashboard/log-data-analysis.png) | Wazuh Security Events Dashboard & Triage |
| **Fig 18** | [`images/architecture/bruteforce-alert/failed-logon-events-id-4625-when-successfully-scanning-and-deploying-to-computers.png`](images/architecture/bruteforce-alert/failed-logon-events-id-4625-when-successfully-scanning-and-deploying-to-computers.png) | Temporal Distribution Spike of Authentication Failures |
| **Fig 19** | [`images/architecture/wazuh-dashboard/monitoring-and-securing-cloud-workloads-with-wazuh.png`](images/architecture/wazuh-dashboard/monitoring-and-securing-cloud-workloads-with-wazuh.png) | Workload Security Monitoring Panel |
| **Fig 20** | [`images/architecture/wazuh-dashboard/monitoring-microsoft-graph-services-with-wazuh.png`](images/architecture/wazuh-dashboard/monitoring-microsoft-graph-services-with-wazuh.png) | Cloud Identity & Microsoft Graph Telemetry Monitor |

---

## 13. Repository Structure

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
│   │   ├── soc-architecture/          # Architecture & dataflow diagrams (Fig 1-4)
│   │   ├── wazuh-dashboard/           # SIEM dashboard & monitoring evidence (Fig 5, 17, 19, 20)
│   │   └── bruteforce-alert/          # Windows Event ID 4625 & alert analysis (Fig 11-13, 18)
│   ├── attacks/
│   │   └── nmap-scan/                 # Nmap scan & Hydra attack execution (Fig 6-9)
│   └── logs/
│       └── sysmon-process/            # Sysmon network connection & process telemetry (Fig 10, 14-16)
├── logs/
│   ├── sample-log.txt                 # Realistic Wazuh JSON alerts export
│   └── windows-events.txt             # Realistic Windows Security & Sysmon log stream
├── reports/
│   └── incident-report.md             # Enterprise-standard L3 SOC Incident Response Report (INC-2026-0912-001)
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

# 14. Author

## Sandeep Mothukuri

**Senior SOC Analyst (L3) · Detection Engineering · Threat Hunting · Incident Response · Security Engineering**

Specializing in:
- Security Operations (SOC L1 / L2 / L3)
- Detection Engineering & Detection-as-Code
- Threat Hunting & Adversary Emulation
- SIEM / XDR Architecture (Wazuh, Splunk, Microsoft Sentinel)
- Endpoint Telemetry (Microsoft Sysmon, Windows Auditing, EDR)
- MITRE ATT&CK Framework Mapping
- Digital Forensics & Incident Response (DFIR)
- Security Automation & SOAR

- **GitHub:** [@sandeepmothukuri](https://github.com/sandeepmothukuri)
- **Website:** [cybertechnology.in](https://cybertechnology.in)
- **LinkedIn:** [linkedin.com/in/sandeepmothukuri](https://www.linkedin.com/in/sandeepmothukuri)
- **Email:** [sandeep.mothukuris@gmail.com](mailto:sandeep.mothukuris@gmail.com)

---

# 🗂️ All Repositories

| Repository | Description | Focus |
|:---|:---|:---|
| [AI-SOC-Decision-Engine](https://github.com/sandeepmothukuri/AI-SOC-Decision-Engine) | AI-assisted SOC decision/control plane for triage, enrichment, safety controls and analyst approval | AI / Automation |
| [AI-Augmented-SOC-Lab](https://github.com/sandeepmothukuri/AI-Augmented-SOC-Lab) | AI-augmented SOC with Wazuh + TheHive + Ollama (LLaMA3) for analyst-assisted triage | GenAI / Incident Response |
| [Enterprise-Detection-Engineering-SOC-Lab](https://github.com/sandeepmothukuri/Enterprise-Detection-Engineering-SOC-Lab) | 12-tool SOC lab with OpenSearch, Suricata, Zeek, MISP, Caldera, Velociraptor | Enterprise SIEM / XDR |
| [Autonomous-SOC-Lab](https://github.com/sandeepmothukuri/Autonomous-SOC-Lab) | Autonomous SOC with AI-driven detection and self-healing playbooks | SOAR / Autonomous Ops |
| [soc-threat-hunting-lab](https://github.com/sandeepmothukuri/soc-threat-hunting-lab) | Threat detection lab — Zeek, RITA, Arkime, Velociraptor, OSQuery, MISP | Network Threat Hunting |
| [soc-lab-free](https://github.com/sandeepmothukuri/soc-lab-free) | Free SOC lab — OpenVAS, Wazuh, pfSense, Proxmox Mail, Lynis | Open-Source Security |
| [SOC-Detection-and-Threat-Hunting-Lab](https://github.com/sandeepmothukuri/SOC-Detection-and-Threat-Hunting-Lab) | SOC analyst home lab — Wazuh, Sysmon, MITRE ATT&CK mapping and incident response | Endpoint Detection |
| [PromptSentinel](https://github.com/sandeepmothukuri/PromptSentinel) | Enterprise-grade prompt injection detection and AI firewall for LLM applications | LLM Security |
| [PromptShield](https://github.com/sandeepmothukuri/PromptShield) | AI Security + SOC Detection Engineering Lab with prompt-security telemetry, detections and response | AI Detection Engineering |
| [sentinel-detection-engine](https://github.com/sandeepmothukuri/sentinel-detection-engine) | Detection-as-code for Microsoft Sentinel and Defender XDR with KQL, SOAR and ATT&CK coverage | Cloud SIEM / KQL |

---

### 📄 License

This project is licensed under the MIT License — see the [`LICENSE`](LICENSE) file for details.

⭐ **Star this repository if you find it helpful for your SOC analyst journey or detection engineering research!**
