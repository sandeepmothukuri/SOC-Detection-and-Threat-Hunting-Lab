# 🛡️ Wazuh SIEM Deployment & Configuration Guide

**Author:** Sandeep Mothukuri (Senior SOC Analyst L3)  
**Target Environment:** Wazuh 4.7+ All-in-One Server on Ubuntu Server 22.04 LTS  

---

## 📌 1. System Requirements & Prerequisites

Wazuh All-in-One central deployment integrates the **Wazuh Manager**, **Wazuh Indexer** (OpenSearch-based engine), and **Wazuh Dashboard** on a single virtual or physical host.

| Component | Minimum Specification | Recommended Production/Lab |
|---|---|---|
| **OS** | Ubuntu 22.04 LTS (64-bit) | Ubuntu 22.04 / Debian 12 |
| **CPU** | 2 vCPUs | 4 vCPUs |
| **RAM** | 4 GB | 8 GB |
| **Disk** | 50 GB SSD | 100 GB SSD |
| **Network** | Static IP (Bridged / Host-Only) | Static IP (e.g., `192.168.56.10`) |

### Architecture & Central Components Overview

![Wazuh Architecture](../images/architecture/soc-architecture/wazuh-central-components.png)
*Figure S1: Wazuh central server components including Wazuh Manager, Filebeat, and OpenSearch Indexer.*

![Elastic Stack & Wazuh Integration](../images/architecture/soc-architecture/elastic-stack-integration.png)
*Figure S2: Elastic Stack / OpenSearch ingestion pipeline, indexing, and visualization architecture.*

---

## 🌐 2. Network & Port Requirements

Ensure the following inbound ports are open on the Wazuh server:

| Port | Protocol | Purpose | Direction |
|---|---|---|---|
| **1514** | TCP/UDP | Agent telemetry & event communication | Inbound from Agents |
| **1515** | TCP | Agent auto-enrollment service (`authd`) | Inbound from Agents |
| **55000** | TCP | Wazuh RESTful Management API | Local / Administrative |
| **443** | TCP | Wazuh Dashboard Web Interface (HTTPS) | Analyst Workstation |
| **9200** | TCP | Wazuh Indexer REST API | Internal / Cluster |

Configure the host firewall:
```bash
sudo ufw allow 1514/tcp
sudo ufw allow 1515/tcp
sudo ufw allow 55000/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

---

## 🚀 3. Step-by-Step Wazuh Installation

### Step 3.1: System Preparation & Kernel Memory Configuration
```bash
# Update base repositories
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl apt-transport-https lsb-release gnupg2 tar ufw

# CRITICAL: Configure Kernel Memory Map Count for OpenSearch/Wazuh Indexer
# Wazuh Indexer requires vm.max_map_count >= 262144, otherwise it will crash on startup
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Optional: Add 4GB swap space if host RAM is under 8GB
if [ $(free -m | awk '/^Mem:/{print $2}') -lt 7500 ]; then
  sudo fallocate -l 4G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
fi
```

### Step 3.2: Download & Execute Wazuh All-in-One Installer
```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Execute the automated deployment
sudo bash wazuh-install.sh -a
```

During installation, the assistant automatically provisions:
1. Wazuh Indexer cluster with self-signed SSL certificates.
2. Wazuh Manager daemon and analysis engine.
3. Filebeat shipper configured for Wazuh alerts.
4. Wazuh Dashboard web UI.

### Step 3.3: Retrieve Administrative Credentials
When the installation completes, the script displays the dashboard access URL and prints the generated admin credentials. To retrieve or store them securely:
```bash
sudo tar -xvf wazuh-install-files.tar
sudo cat wazuh-install-files/wazuh-passwords.txt
```
*Locate the entry for `admin` user and password.*

---

## 🔍 4. Service Verification & Health Check

Verify all three core services are active and running:
```bash
sudo systemctl status wazuh-indexer
sudo systemctl status wazuh-manager
sudo systemctl status wazuh-dashboard
```

Verify the Indexer cluster health:
```bash
curl -k -u admin:<YOUR_ADMIN_PASSWORD> https://127.0.0.1:9200/_cat/health?v
curl -k -u admin:<YOUR_ADMIN_PASSWORD> https://127.0.0.1:9200/_cat/indices?v
```

---

## ⚙️ 5. Deploying Custom Detection Rules

Custom detection rules are placed in `/var/ossec/etc/rules/` on the Wazuh Manager.

### Step 5.1: Copy Rule Files
Copy the detection rules from this repository into the manager's rule directory:
```bash
# Copy Brute Force Rules
sudo cp detection-rules/brute-force-rule.xml /var/ossec/etc/rules/local_bruteforce_rules.xml

# Copy Advanced Multi-Stage Correlation Rules
sudo cp detection-rules/advanced-rules.xml /var/ossec/etc/rules/local_advanced_rules.xml

# Set appropriate permissions
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_*.xml
sudo chmod 660 /var/ossec/etc/rules/local_*.xml
```

### Step 5.2: Test Rules with `wazuh-logtest`
Test that Wazuh parses your rules and correctly fires alerts against Windows Event 4625:
```bash
/var/ossec/bin/wazuh-logtest
```
Paste a sample Windows log into the prompt:
```
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4625","level":"0","task":"12544","keywords":"0x8010000000000000","systemTime":"2026-09-12T10:02:15.000Z","eventRecordID":"18402","computer":"WIN10-ENDPOINT"},"eventdata":{"targetUserName":"Administrator","targetDomainName":"WIN10-ENDPOINT","status":"0xc000006d","subStatus":"0xc000006a","logonType":"10","ipAddress":"192.168.56.20","ipPort":"49812"}}}
```
*Verify that `rule: 100002` or `rule: 100001` matches.*

### Step 5.3: Restart Wazuh Manager
```bash
sudo systemctl restart wazuh-manager
```

---

## 🖥️ 6. Accessing Wazuh Dashboard

1. Open your browser and navigate to: `https://<WAZUH_SERVER_IP>`
2. Accept the self-signed certificate.
3. Log in with user `admin` and the password from `wazuh-passwords.txt`.
4. Navigate to **Modules** -> **Security Events** to monitor real-time detections and agent telemetry.

![Wazuh Dashboard Initial Access](../images/architecture/wazuh-dashboard/wazuh-dashboard-and-agent-deployment.png)
*Figure S3: Wazuh Dashboard interface and agent deployment status.*

![Wazuh Workload Monitoring](../images/architecture/wazuh-dashboard/monitoring-and-securing-cloud-workloads-with-wazuh.png)
*Figure S4: Workload security dashboard displaying telemetry metrics.*

![Microsoft Graph Monitoring with Wazuh](../images/architecture/wazuh-dashboard/monitoring-microsoft-graph-services-with-wazuh.png)
*Figure S5: Microsoft Graph and Identity services monitoring in Wazuh.*

---

## ⚡ 7. Configuring Automated Active Response (Auto-Blocking Attacker IP)

To configure Wazuh to automatically neutralize brute-force attacks at the host/network level, enable the `firewall-drop` active response command on the Wazuh Manager.

Edit `/var/ossec/etc/ossec.conf` on the Wazuh Manager:

```xml
<!-- Active Response Command Definition -->
<command>
  <name>firewall-drop</name>
  <executable>firewall-drop</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- Trigger firewall-drop when Rule 100003 (RDP Brute Force) matches -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100003</rules_id>
  <timeout>600</timeout>
</active-response>
```

Restart the manager to apply changes:
```bash
sudo systemctl restart wazuh-manager
```

---

## 🔧 8. Troubleshooting & Common Operational Pitfalls

| Issue | Root Cause | Remediation Command |
|---|---|---|
| **Wazuh Indexer fails to start** | `vm.max_map_count` lower than 262144 | `sudo sysctl -w vm.max_map_count=262144 && sudo systemctl restart wazuh-indexer` |
| **Agent connection refused** | Port 1514/1515 blocked by host firewall | `sudo ufw allow 1514/tcp && sudo ufw allow 1515/tcp` |
| **Dashboard displays 502 Bad Gateway**| Wazuh Indexer or API initializing | Wait 60s for Java heap allocation; check `journalctl -u wazuh-dashboard -f` |
| **Rules syntax error on startup** | Invalid XML tag or duplicate rule ID | Validate XML with `python3 -c "import xml.etree.ElementTree as ET; ET.parse('rules.xml')"` |
