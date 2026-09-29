# 🪟 Windows Target Endpoint Setup & Telemetry Configuration

**Author:** Sandeep Mothukuri (Senior SOC Analyst L3)  
**Target Environment:** Windows 10/11 Pro/Enterprise or Windows Server 2019/2022  
**Role:** Target Host & Telemetry Source (Wazuh Agent + Sysmon)

---

## 📌 1. Endpoint Architecture & Requirements

The Windows endpoint serves as the victim workstation/server in this detection lab. It generates high-fidelity endpoint telemetry through **Windows Security Auditing** and **Microsoft Sysmon**, forwarding events to the Wazuh Manager.

| Parameter | Recommended Configuration |
|---|---|
| **OS** | Windows 10/11 Pro/Enterprise or Server 2019/2022 |
| **RAM / CPU** | 4 GB RAM, 2 vCPUs |
| **IP Address** | Static IP (e.g., `192.168.56.20/24`) |
| **Services** | Remote Desktop (RDP / Port 3389) |
| **Telemetry Agents** | Sysmon 15+, Wazuh Agent 4.7+ |

---

## 🔌 2. Enable Remote Desktop (RDP) & Firewall Rule

Open an elevated PowerShell prompt (Run as Administrator):

```powershell
# Enable Remote Desktop service
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0

# Enable RDP through Windows Defender Firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Optional: Disable Network Level Authentication (NLA) for raw RDP brute-force demonstration
(Get-WmiObject -Class Win32_TSGeneralSetting -Namespace root\cimv2\TerminalServices -Filter "TerminalName='RDP-Tcp'").SetUserAuthenticationRequired(0)

# Verify RDP listening port
Get-NetTCPConnection -LocalPort 3389 -State Listen
```

---

## 🛡️ 3. Configure Advanced Windows Audit Policies (`auditpol`)

To ensure Windows generates detailed Event IDs (4624, 4625, 4672, 4740), configure the local audit policy:

```powershell
# Enable Logon / Logoff Auditing (Captures 4624 and 4625)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Enable Detailed Tracking - Process Creation (Event ID 4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable

# Enable Process Command Line Auditing in Windows Security Log
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -PropertyType DWord -Value 1 -Force

# Verify configured audit subcategories
auditpol /get /category:"Logon/Logoff"
```

![Windows Security Event Log Generated](../images/logs/sysmon-process/generated-event-is-recorded-in-the-windows-event-log.png)
*Figure W1: Windows Event Viewer validating that Security Auditing events are successfully captured.*

---

## 🔍 4. Install & Configure Microsoft Sysmon

Microsoft Sysmon provides process execution graphs, command lines, network connections, and file modifications.

### Step 4.1: Download Sysmon
Download the latest Sysmon zip package from Microsoft Sysinternals:
```powershell
New-Item -ItemType Directory -Path "C:\Tools" -Force
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Tools\Sysmon.zip"
Expand-Archive -Path "C:\Tools\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force
```

### Step 4.2: Apply Modular Sysmon Configuration
Copy `sysmon-config.xml` from this repository to `C:\Tools\Sysmon\sysmon-config.xml`.

```powershell
cd C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmon-config.xml
```

### Step 4.3: Verify Sysmon Operation
```powershell
# Check Sysmon driver service status
Get-Service -Name "Sysmon64"

# Query the latest 5 Sysmon events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 | Format-Table TimeCreated, Id, Message -Wrap
```

![Sysmon Operational Logs](../images/logs/sysmon-process/sysmon-logs-network.png)
*Figure W2: Microsoft-Windows-Sysmon Operational channel capturing detailed telemetry.*

![Sysmon Event ID 3 Network Record](../images/logs/sysmon-process/sysmon-event-id-3---rdp-logon-issue-initiated--field-always-false.png)
*Figure W3: Sysmon Event ID 3 record details highlighting inbound network connection.*

---

## 📦 5. Install & Enroll Wazuh Agent

### Step 5.1: Download & Install Wazuh Agent MSI
```powershell
$wazuhManagerIP = "192.168.56.10" # Replace with your Wazuh Manager IP

Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi" -OutFile "C:\Tools\wazuh-agent.msi"

# Silent installation with auto-enrollment
Start-Process msiexec.exe -Wait -ArgumentList "/i C:\Tools\wazuh-agent.msi /q WAZUH_MANAGER='$wazuhManagerIP' WAZUH_REGISTRATION_SERVER='$wazuhManagerIP'"
```

### Step 5.2: Configure `ossec.conf` for Event Channels
Open `C:\Program Files (x86)\ossec-agent\ossec.conf` in an editor and ensure the Windows Security and Sysmon operational logs are forwarded:

```xml
<ossec_config>
  <client>
    <server>
      <address>192.168.56.10</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <!-- Windows Security Event Log -->
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Microsoft-Windows-Sysmon Log -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- System and Application Logs -->
  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

### Step 5.3: Start & Validate Wazuh Agent Service
```powershell
# Restart the agent service
Restart-Service -Name "WazuhSvc"
Get-Service -Name "WazuhSvc"

# Inspect the agent connection log
Get-Content -Tail 20 "C:\Program Files (x86)\ossec-agent\ossec.log"
```

Look for:
`Connected to the server (192.168.56.10:1514/tcp)`  
`Valid key received`

![Workstation Telemetry Logs](../images/logs/sysmon-process/workstation-logs.png)
*Figure W4: Workstation security and operational logs active and streaming.*

![Wazuh Agent Active in Dashboard](../images/architecture/wazuh-dashboard/wazuh-dashboard-and-agent-deployment.png)
*Figure W5: Wazuh Dashboard confirming active Windows agent connection and continuous log transmission.*

The Windows endpoint is now fully monitored and streaming real-time security events to your Wazuh SIEM.
