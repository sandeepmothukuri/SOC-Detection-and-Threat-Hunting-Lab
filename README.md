# 🔐 SOC Analyst Home Lab

[![Lab Validation](https://github.com/sandeepmothukuri/SOC-Detection-and-Threat-Hunting-Lab/actions/workflows/validate.yml/badge.svg)](https://github.com/sandeepmothukuri/SOC-Detection-and-Threat-Hunting-Lab/actions) [![Wazuh](https://img.shields.io/badge/SIEM-Wazuh-0066CC?logo=wazuh&logoColor=white)](https://wazuh.com/) [![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Hands-on SOC analyst lab** — brute-force attack simulation, endpoint detection with Wazuh SIEM + Sysmon, and MITRE ATT&CK mapping. Built from scratch to demonstrate real L1/L2 SOC detection workflows.

---

## ⚡ Quick Demo

| | |
|---|---|
| **Attack** | Hydra brute-force on RDP |
| **Detection** | Event ID 4625 correlation |
| **SIEM** | Wazuh |
| **Result** | Attack detected, no successful compromise |
| **MITRE** | T1110 — Brute Force |

---

## 📌 Overview

Detected and analyzed a brute-force attack using **Wazuh SIEM**, **Sysmon** telemetry, and **MITRE ATT&CK** mapping in a self-built SOC home lab.

---

## 🏗️ Architecture

```
Kali Linux (Attacker)
        │
        ▼  Hydra / Nmap
Windows 10 Endpoint
   ├─ Sysmon (process/network telemetry)
   └─ Wazuh Agent
        │
        ▼
Wazuh Manager (Ubuntu)
   ├─ Elasticsearch (log storage)
   └─ Kibana Dashboard (visualization)
```

---

## ⚙️ Installation Guide

### Prerequisites

- VirtualBox
- VMware
- Minimum: 8 GB RAM, 100 GB storage

### Deploy Wazuh SIEM

```bash
sudo apt update && sudo apt upgrade -y
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

Access dashboard: `https://<WAZUH-IP>`

### Windows Endpoint — Install Sysmon

```powershell
sysmon.exe -i sysmon-config.xml
```

### Windows Endpoint — Install Wazuh Agent

Download the Wazuh agent and configure the manager address in `ossec.conf`.

---

## ⚔️ Attack Simulation

```bash
nmap -sS <target-ip>
hydra -l admin -P rockyou.txt rdp://<target-ip>
```

---

## 🚨 Detection Workflow

### Key Windows Event IDs

| Event ID | Description |
|---|---|
| 4625 | Failed login attempt |
| 4624 | Successful login |
| 4740 | Account lockout |
| 4672 | Privilege assignment |
| 4663 | File access |
| Sysmon 1 | Process creation |
| Sysmon 3 | Network connection |

### Detection Logic

- **Trigger:** 5+ failed logins from the same source IP within 60 seconds
- **Rule ID:** 100001 (custom)
- **MITRE:** T1110 — Brute Force

---

## 📅 Incident Timeline

| Step | Event |
|---|---|
| 1 | Nmap scan detected (T1046) |
| 2 | Hydra brute-force initiated |
| 3 | Multiple Event ID 4625 alerts fired |
| 4 | Wazuh custom rule triggered |
| 5 | Logs correlated in SIEM |
| 6 | No 4624 found — no successful compromise |
| 7 | Incident closed as contained |

---

## 🎯 MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force | T1110 | Multiple failed login attempts |
| Network Scanning | T1046 | Nmap port scan |
| Command Execution | T1059 | Shell commands on attacker |
| Valid Accounts | T1078 | Target for credential access |

---

## 📸 Lab Evidence

The repository contains architecture, Wazuh dashboard, brute-force detection, attack simulation and Sysmon evidence images under `images/`.

---

## 💼 Skills Demonstrated

- Real SOC detection workflow (attack → alert → investigation → closure)
- SIEM deployment and custom rule authoring (Wazuh)
- Endpoint telemetry with Sysmon
- MITRE ATT&CK framework application
- Incident timeline reconstruction

---

# 👤 Author

## Sandeep Mothukuri

**Senior SOC Analyst (L3) · Detection Engineering · Threat Hunting · Incident Response · Security Engineering**

Focus areas:

- Security Operations
- Detection Engineering
- Threat Hunting
- Incident Response
- SIEM / XDR
- SOAR
- DFIR
- MITRE ATT&CK
- Security Automation
- AI-Augmented SOC Operations

This repository is maintained as a practical security engineering environment for designing, testing and validating modern SOC capabilities.

- GitHub: [@sandeepmothukuri](https://github.com/sandeepmothukuri)
- Website: [cybertechnology.in](https://cybertechnology.in)
- LinkedIn: [linkedin.com/in/sandeepmothukuri](https://www.linkedin.com/in/sandeepmothukuri)
- Email: [sandeep.mothukuris@gmail.com](mailto:sandeep.mothukuris@gmail.com)

---

# 🗂️ All Repositories

| Repository Description | |
| --- | --- |
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

**Author portfolio:** [github.com/sandeepmothukuri](https://github.com/sandeepmothukuri)

⭐ **Star this repo if it helped you — it helps other SOC analysts find it!**
