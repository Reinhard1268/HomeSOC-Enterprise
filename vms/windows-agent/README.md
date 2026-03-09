# Windows Agent Setup — SOC Lab

## Overview

This guide sets up a Windows 10 or Windows 11 host as a fully monitored
Wazuh agent with Sysmon for advanced event logging. Together they give
the SOC visibility into process creation, network connections, LSASS access,
registry changes, and all authentication events.

---

## Quick Deploy (PowerShell — Run as Administrator)
```powershell
# On the target Windows host:
# Download and run the deployment script
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yourhandle/01-enterprise-home-soc/main/scripts/setup/deploy-windows-agent.ps1" -OutFile deploy-windows-agent.ps1

.\deploy-windows-agent.ps1 `
  -ManagerIP "172.20.0.11" `
  -AgentName "windows-endpoint-01" `
  -AgentGroup "windows"
```

---

## Manual Setup

### Step 1 — Install Wazuh Agent
```powershell
# Download Wazuh agent MSI
$WazuhVersion = "4.7.3-1"
$Url = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion.msi"
Invoke-WebRequest -Uri $Url -OutFile "wazuh-agent.msi"

# Silent install with manager enrollment
msiexec.exe /i wazuh-agent.msi /q `
  WAZUH_MANAGER="172.20.0.11" `
  WAZUH_AGENT_NAME="windows-endpoint-01" `
  WAZUH_REGISTRATION_SERVER="172.20.0.11"
```

### Step 2 — Apply Custom ossec.conf
```powershell
# Copy the Windows agent config from this repo
Copy-Item "wazuh\agents\ossec-windows.conf" `
  "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
```

### Step 3 — Install Sysmon

Sysmon provides process creation (EID 1), network connections (EID 3),
LSASS access (EID 10), and registry changes (EID 12/13) required by
Wazuh custom rules 100003-100010.
```powershell
# Download Sysmon from Microsoft Sysinternals
$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip"
Invoke-WebRequest -Uri $SysmonUrl -OutFile "Sysmon.zip"
Expand-Archive "Sysmon.zip" -DestinationPath ".\Sysmon"

# Download SwiftOnSecurity config (comprehensive coverage)
$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
Invoke-WebRequest -Uri $ConfigUrl -OutFile "sysmonconfig.xml"

# Install Sysmon with config
.\Sysmon\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Verify Sysmon is running
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

### Step 4 — Start Wazuh Agent
```powershell
# Start the Wazuh agent service
Start-Service WazuhSvc
Set-Service WazuhSvc -StartupType Automatic

# Verify running
Get-Service WazuhSvc
```

---

## Verify Agent Enrollment
```bash
# On the Wazuh manager (Docker host):
docker exec wazuh-manager /var/ossec/bin/agent-control -l

# Expected:
# ID: 002, Name: windows-endpoint-01, IP: 172.20.0.110, Status: Active
```

---

## Event IDs Monitored (from ossec-windows.conf)

### Security Channel
| EID | Event | Wazuh Rule |
|-----|-------|-----------|
| 4624 | Successful logon | Built-in auth rules |
| 4625 | Failed logon | 100001 (freq counter) |
| 4648 | Logon with explicit credentials | Built-in |
| 4688 | Process creation | 100005 (PowerShell) |
| 4698 | Scheduled task created | 100008 |
| 4720 | User account created | Built-in |

### Sysmon Channel
| EID | Event | Wazuh Rule |
|-----|-------|-----------|
| 1 | Process creation | 100005, 100008, 100010 |
| 3 | Network connection | 100009 |
| 10 | Process access (LSASS) | 100003 |
| 11 | File creation | Syscheck supplement |
| 13 | Registry value set | 100007 |

### PowerShell Channel
| EID | Event | Wazuh Rule |
|-----|-------|-----------|
| 4103 | Module logging | 100005 |
| 4104 | Script block logging | 100005 |

---

## Testing Detections
```powershell
# Test rule 100005 — PowerShell detection
# (harmless — just echoes to screen)
powershell.exe -nop -w hidden -EncodedCommand `
  "V3JpdGUtSG9zdCAnU09DIExhYiBUZXN0IC0gUnVsZSAxMDAwMDUn"

# Decoded: Write-Host 'SOC Lab Test - Rule 100005'
# This should trigger rule 100005 in Wazuh

# Verify on Docker host:
# python3 scripts/testing/verify-detections.py --since 5
```

---

## Troubleshooting
```powershell
# Check agent status
Get-Service WazuhSvc
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 30

# Re-enroll agent
& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" `
  -m 172.20.0.11 -A windows-endpoint-01

# Test ossec.conf syntax
& "C:\Program Files (x86)\ossec-agent\ossec-logtest.exe" -t

# Verify Sysmon events flowing
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3 |
  Select-Object TimeCreated, Id, Message | Format-List

# Check firewall allows outbound to manager
Test-NetConnection -ComputerName 172.20.0.11 -Port 1514
Test-NetConnection -ComputerName 172.20.0.11 -Port 1515
```

---

## Uninstall
```powershell
# Stop and remove Wazuh agent
Stop-Service WazuhSvc
msiexec /x wazuh-agent.msi /q

# Remove Sysmon
.\Sysmon\Sysmon64.exe -u force

# Remove firewall rules added during install
Remove-NetFirewallRule -DisplayName "Wazuh Agent*"
```
