# 📋 SOC Incident Response Report: RDP Brute-Force & Credential Access

**Incident Case ID:** `INC-2026-0912-001`  
**Classification:** Credential Access / Brute Force (MITRE ATT&CK: T1110.001)  
**Severity:** High (P2)  
**Lead Investigator:** Sandeep Mothukuri (Senior SOC Analyst L3)  
**Date / Time:** 2026-09-12 10:15:00 UTC  
**Incident Status:** Closed / Contained  

---

## 📌 1. Executive Summary

On September 12, 2026, at 10:01:40 UTC, the Security Operations Center (SOC) detected an automated brute-force attack originating from IP `192.168.56.30` targeting Remote Desktop Protocol (RDP) on host `WIN10-ENDPOINT` (`192.168.56.20`). The attacker utilized automated credential-stuffing tooling (Hydra) following an initial network reconnaissance scan.

The attack was identified in real-time by custom **Wazuh Rule 100003** correlating repeated Windows Security Event ID 4625 (Logon Type 10) occurrences. Telemetry verification confirmed **no successful authentication (Event ID 4624)** occurred, and the targeted account was temporarily locked out (Event ID 4740). The attacker's IP was isolated and blocked at the host and perimeter firewall. Zero data exfiltration or host compromise took place.

---

## 🎯 2. Incident Scope & Impact

| Attribute | Details |
|---|---|
| **Affected Endpoint** | `WIN10-ENDPOINT` (IP: `192.168.56.20`) |
| **Attacker Origin** | `192.168.56.30` (Kali Linux / Internal Host) |
| **Target Service** | RDP / Microsoft Terminal Services (TCP Port 3389) |
| **Targeted Accounts** | `Administrator`, `support`, `backup_user` |
| **Impact Assessment** | Low (Denied Access, Zero Exfiltration, Zero Lateral Movement) |
| **Data Compromised** | None |

---

## ⏱️ 3. Chronological Incident Timeline

| Timestamp (UTC) | Source / Component | Event Details | Telemetry Identifier |
|---|---|---|---|
| **10:00:15** | Threat Actor (`192.168.56.30`) | TCP SYN scan directed at port 3389 | Sysmon Event ID 3 |
| **10:01:20** | Threat Actor | High-frequency TCP session initiation to RDP | Sysmon Event ID 3 |
| **10:01:25** | `WIN10-ENDPOINT` | Burst of authentication failures begins | Windows Security Event ID 4625 |
| **10:01:40** | Wazuh SIEM | **Custom Rule 100003 Triggered** (5+ failed attempts in 60s) | Alert Level 10 (High) |
| **10:02:15** | `WIN10-ENDPOINT` | Account lockout policy triggered | Windows Security Event ID 4740 |
| **10:03:10** | SOC Analyst (Sandeep M.) | Alert acknowledged; triage checklist initiated | Ticket INC-2026-0912-001 |
| **10:04:30** | SOC Analyst | Attacker IP `192.168.56.30` blocked via Windows Firewall rule | Containment Complete |
| **10:06:00** | SOC Analyst | Full event correlation query executed: No 4624 events found | Verification Clean |
| **10:08:00** | SOC Analyst | Sysmon process tree inspected: No post-exploitation tools spawned | Eradication Complete |
| **10:15:00** | SOC Analyst | Incident report finalized; security controls tuned | Incident Closed |

---

## 🔍 4. Technical Telemetry & Evidence Analysis

### 4.1 Windows Security Log Evidence: Failed Logon (Event ID 4625)
The Windows Security Event Log captured multiple authentication failures specifically tagged with **Logon Type 10** (RemoteInteractive / RDP).

```
Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4625
Task Category: Logon
Level:         Information
Keywords:      Audit Failure
Computer:      WIN10-ENDPOINT
Description:   An account failed to log on.
Subject:
    Security ID:        S-1-0-0
    Account Name:       -
    Account Domain:     -
    Logon ID:           0x0
Logon Type:             10 (RemoteInteractive)
Account For Which Logon Failed:
    Account Name:       Administrator
    Account Domain:     WIN10-ENDPOINT
Failure Information:
    Failure Reason:     Unknown user name or bad password.
    Status:             0xC000006D
    Sub Status:         0xC000006A
Network Information:
    Workstation Name:   WIN10-ENDPOINT
    Source Network Address: 192.168.56.30
    Source Port:        51244
Process Information:
    Caller Process ID:    0x2c4
    Caller Process Name:  C:\Windows\System32\svchost.exe
```

*Key Forensic Fields:*
- **Status `0xC000006D`:** The logon attempt was made with an invalid logon credential.
- **Sub Status `0xC000006A`:** The user name is valid, but the password provided was incorrect.
- **Logon Type `10`:** Confirms remote desktop protocol entry attempt.

![Event 4625 Forensic Record](../images/architecture/bruteforce-alert/event-4625-failed-to-logon.png)
*Exhibit A: Detailed Windows Event ID 4625 record documenting Logon Type 10 failure from attacker host.*

![Failed Logon Security Properties](../images/architecture/bruteforce-alert/windows-event-id-4625-failed-logon.png)
*Exhibit B: Windows Security log properties highlighting Status 0xC000006D and Sub Status 0xC000006A.*

![Process Information Caller Svchost](../images/architecture/bruteforce-alert/process-information.png)
*Exhibit C: Process caller information identifying svchost.exe hosting TermService.*

![Security Event Log Stream](../images/logs/sysmon-process/generated-event-is-recorded-in-the-windows-event-log.png)
*Exhibit D: Windows Event Viewer showing rapid burst of failed logon entries.*

### 4.2 Sysmon Telemetry Evidence: Inbound Network Connection (Event ID 3)
```
Log Name:      Microsoft-Windows-Sysmon/Operational
Source:        Microsoft-Windows-Sysmon
Event ID:      3
Task Category: Network connection detected
Level:         Information
Computer:      WIN10-ENDPOINT
Description:   Network connection detected:
    RuleName:           -
    UtcTime:            2026-09-12 10:01:22.418
    ProcessGuid:        {5e4a8b7c-0000-0000-0000-000000000000}
    ProcessId:          1240
    Image:              C:\Windows\System32\svchost.exe
    Protocol:           tcp
    Initiated:          false
    SourceIp:           192.168.56.30
    SourceHostname:     kali-attacker
    SourcePort:         51244
    DestinationIp:      192.168.56.20
    DestinationPort:    3389
```

![Sysmon Network Event Viewer](../images/logs/sysmon-process/sysmon-logs-network.png)
*Exhibit E: Sysmon Operational Log capturing inbound TCP connections from 192.168.56.30 to port 3389.*

![Sysmon Event ID 3 Details](../images/logs/sysmon-process/sysmon-event-id-3---rdp-logon-issue-initiated--field-always-false.png)
*Exhibit F: Forensic view of Sysmon Event ID 3 confirming uninitiated inbound network connection.*

### 4.3 Wazuh Alert Record (JSON)
```json
{
  "timestamp": "2026-09-12T10:01:40.125+0000",
  "rule": {
    "level": 10,
    "description": "Wazuh Alert: Potential RDP Brute-Force Attack Detected against WIN10-ENDPOINT from 192.168.56.30 [5+ Failed Attempts in 60s]",
    "id": "100003",
    "mitre": {
      "id": ["T1110", "T1110.001"],
      "tactic": ["Credential Access"],
      "technique": ["Brute Force", "Password Guessing"]
    },
    "groups": ["windows", "authentication_failures", "attack", "bruteforce"]
  },
  "agent": {
    "id": "001",
    "name": "WIN10-ENDPOINT",
    "ip": "192.168.56.20"
  },
  "data": {
    "win": {
      "system": {
        "eventID": "4625",
        "computer": "WIN10-ENDPOINT"
      },
      "eventdata": {
        "logonType": "10",
        "targetUserName": "Administrator",
        "ipAddress": "192.168.56.30",
        "ipPort": "51244"
      }
    }
  }
}
```

![Wazuh Alert Triage Dashboard](../images/architecture/wazuh-dashboard/log-data-analysis.png)
*Exhibit G: Wazuh SIEM Security Events Dashboard displaying correlated Rule 100003 alert trigger and MITRE ATT&CK mapping.*

![Failed Logon Distribution Chart](../images/architecture/bruteforce-alert/failed-logon-events-id-4625-when-successfully-scanning-and-deploying-to-computers.png)
*Exhibit H: Temporal log analysis showing acute spike in Event ID 4625 authentication failures.*

---

## 🛡️ 5. Containment, Eradication & Recovery

1. **Immediate Host Containment:** Blocked inbound traffic from `192.168.56.30` using Windows Advanced Firewall:
   ```powershell
   New-NetFirewallRule -DisplayName "Block Attacker IP - 192.168.56.30" -Direction Inbound -Action Block -RemoteAddress 192.168.56.30
   ```
2. **Account Status Verification:** Confirmed that `Administrator` account was locked by system lockout policy, preventing further exploitation attempts.
3. **Eradication & Artifact Sweep:**
   - Evaluated Sysmon Event ID 1 (Process Creation) around the attack timeframe — no suspicious child processes (e.g., `cmd.exe`, `powershell.exe`, `whoami.exe`) were spawned under `svchost.exe` or `rdpclip.exe`.
   - Verified active sessions via `qwinsta` to confirm no unauthorized interactive RDP sessions existed.
4. **Recovery:** Account was safely unlocked by SOC administrator after confirming no session hijack took place.

---

## 🎯 6. MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Detection Telemetry |
|---|---|---|---|
| **Reconnaissance** | `T1046` | Network Service Discovery | Sysmon Event ID 3 (Port 3389 scan) |
| **Credential Access** | `T1110.001` | Password Guessing / Brute-Force | Event ID 4625 (Logon Type 10) |
| **Initial Access** | `T1078.001` | Default Accounts | Event ID 4625 targeting `Administrator` |
| **Defense Evasion** | `T1110` | Brute Force Lockout Trigger | Event ID 4740 (Account Lockout) |

---

## 💡 7. Lessons Learned & Recommendations

1. **Enforce Network Level Authentication (NLA):** Require NLA for Remote Desktop connections so clients must authenticate against CredSSP before establishing a full RDP session.
2. **Account Lockout Thresholds:** Retain the account lockout policy (5 failed attempts locks the account for 15 minutes) to neutralize high-speed automated brute-forcing.
3. **Network Segmentation & RDP Gateway:** Restrict TCP 3389 exposure behind a VPN or Remote Desktop Gateway, preventing direct access from untrusted subnets.
4. **Multi-Factor Authentication (MFA):** Implement MFA for all remote administrative access.
5. **Automated Active Response:** Configure Wazuh Active Response (`firewall-drop`) to automatically block attacking source IPs upon triggering Rule 100003.