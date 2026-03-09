# Incident Response Playbook — Lateral Movement
**Version:** 1.0  
**Author:** SOC Lab Project  
**MITRE ATT&CK:** T1021.002, T1570, T1550.002, T1078, T1076  
**Wazuh Rules:** 100004, 100002, 100009  
**Estimated Handling Time:** 2–6 hours  

---

## 1. Overview

Lateral movement occurs after an adversary has gained an initial foothold and
attempts to access additional systems within the network using legitimate tools
and stolen credentials. This is one of the most dangerous phases of an attack
because it often precedes data exfiltration, ransomware deployment, or domain
compromise.

**Trigger conditions for this playbook:**
- Wazuh rule 100004 (PsExec lateral movement detected)
- Windows Event 4624 LogonType 3 from unexpected internal source
- Wazuh rule 100002 (successful login after brute force — internal IP)
- SMB/RDP connections between workstations (east-west traffic anomaly)

---

## 2. Severity Matrix

| Condition | Severity | SLA |
|-----------|----------|-----|
| Single lateral hop, contained subnet | Medium | 2h |
| Multiple hops or admin credentials used | High | 1h |
| Domain admin credentials compromised | **Critical** | **15 min** |
| Domain controller accessed | **Critical** | **15 min** |

---

## 3. Step-by-Step Response

### Phase 1 — Detection & Triage (0–15 min)

**Step 1.1** — Identify pivot host and destination hosts
```
From Wazuh alert / Kibana:
  - Source of lateral movement: agent.name / data.srcip
  - Destination host(s): win.eventdata.destinationIp
  - Tool used: win.eventdata.image (psexec.exe, wmic.exe, etc.)
  - Credentials used: win.eventdata.targetUserName
```

**Step 1.2** — Check if domain controller is in scope
```powershell
# On any domain-joined host — is DC showing unusual logon events?
Get-WinEvent -ComputerName <DC_hostname> -LogName Security |
  Where-Object {$_.Id -in 4624,4625,4648} | Select-Object -First 20
```

**Step 1.3** — Determine credentials used
```
Check Windows Event 4648 (explicit credential use):
  - Are these domain admin creds? → Critical
  - Are these local admin creds? → High
  - Are these standard user creds? → Medium
```

**Step 1.4** — Map ALL affected hosts in Kibana
```kql
# KQL query to find all LogonType 3 events from pivot IP
win.system.eventID:"4624" AND win.eventdata.logonType:"3" AND data.srcip:<pivot_ip>
```

**Step 1.5** — Open TheHive case using `Lateral Movement` template

---

### Phase 2 — Containment (15–45 min)

**Step 2.1** — Isolate the pivot (source) host first
```powershell
# Block all outbound SMB/RDP/WMI from pivot host
New-NetFirewallRule -DisplayName 'IR-LM-BLOCK-OUT-SMB' `
  -Direction Outbound -LocalPort 445,3389,5985,135 -Protocol TCP `
  -Action Block -Enabled True
```

**Step 2.2** — Isolate all destination hosts (block inbound from pivot)
```powershell
# Run on each destination host
New-NetFirewallRule -DisplayName 'IR-LM-BLOCK-PIVOT' `
  -Direction Inbound -RemoteAddress <pivot_ip> -Action Block -Enabled True
```

**Step 2.3** — Disable compromised accounts IMMEDIATELY
```powershell
# Active Directory
Disable-ADAccount -Identity <compromised_user>
# Force log off all active sessions for that account
Get-RDUserSession | Where-Object {$_.Username -eq '<compromised_user>'} |
  Invoke-RDUserLogoff -Force

# Local accounts
net user <username> /active:no
```

**Step 2.4** — Stop and remove PsExec service if found
```powershell
# On all affected destination hosts
Stop-Service PSEXESVC -Force -ErrorAction SilentlyContinue
Remove-Item C:\Windows\PSEXESVC.exe -Force -ErrorAction SilentlyContinue
sc.exe delete PSEXESVC
Get-WinEvent -LogName System | Where-Object {$_.Id -eq 7045} |
  Select-Object TimeCreated,Message | Format-List
```

---

### Phase 3 — Investigation (45–180 min)

**Step 3.1** — Trace full attack path hop by hop
```powershell
# On each affected host — logon events in last 48h
Get-WinEvent -LogName Security -MaxEvents 1000 |
  Where-Object {$_.Id -in 4624,4625,4648,4672} |
  Select-Object TimeCreated,Id,
    @{N='User';E={$_.Properties[5].Value}},
    @{N='SrcIP';E={$_.Properties[18].Value}},
    @{N='LogonType';E={$_.Properties[8].Value}} |
  Export-Csv C:\IR\logon_events_$(hostname).csv
```

**Step 3.2** — Check what was executed on each destination host
```powershell
# Process creation events (Security 4688 or Sysmon 1)
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' |
  Where-Object {$_.Id -eq 1 -and
    $_.TimeCreated -gt (Get-Date).AddHours(-48)} |
  Select-Object TimeCreated,
    @{N='Image';E={$_.Properties[4].Value}},
    @{N='CmdLine';E={$_.Properties[10].Value}},
    @{N='ParentImage';E={$_.Properties[20].Value}} |
  Export-Csv C:\IR\process_events_$(hostname).csv
```

**Step 3.3** — Check for credential harvesting on each host
```powershell
# Was LSASS touched on any destination?
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' |
  Where-Object {$_.Id -eq 10 -and $_.Message -like '*lsass*'}

# Were any files with credentials accessed?
Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' |
  Where-Object {$_.Id -eq 11 -and
    $_.Message -match 'SAM|NTDS|credentials|password|\.kdbx'} |
  Select-Object TimeCreated, Message
```

**Step 3.4** — Check for data staging and exfil prep
```powershell
# Large archives or compressed files created recently
Get-ChildItem C:\ -Recurse -Include *.zip,*.rar,*.7z,*.tar,*.gz `
  -ErrorAction SilentlyContinue |
  Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-48) -and
    $_.Length -gt 10MB} |
  Select-Object FullName,LastWriteTime,Length
```

**Step 3.5** — Build attack timeline
```
Document in TheHive case notes:
  [TIMESTAMP] Initial access / pivot host compromised
  [TIMESTAMP] Lateral movement tool (PsExec) executed from pivot
  [TIMESTAMP] Destination host 1 accessed — account X used
  [TIMESTAMP] Destination host 2 accessed — account Y used
  [TIMESTAMP] LSASS accessed on destination host 1
  [TIMESTAMP] Containment — accounts disabled, hosts isolated
```

---

### Phase 4 — Eradication (180–240 min)

**Step 4.1** — Remove all attacker-placed tools and backdoors
```powershell
# Common attacker staging locations
$stagingPaths = @(
    "C:\Windows\Temp\*",
    "C:\Users\Public\*",
    "C:\ProgramData\*",
    "$env:TEMP\*.exe",
    "$env:TEMP\*.ps1"
)
foreach ($path in $stagingPaths) {
    Get-ChildItem $path -ErrorAction SilentlyContinue |
      Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-72)} |
      Select-Object FullName,LastWriteTime
}
```

**Step 4.2** — Reset ALL compromised credentials
```powershell
# Force password reset for all accounts used in the attack
$compromisedAccounts = @('<user1>', '<user2>', '<svc_account>')
foreach ($account in $compromisedAccounts) {
    $newPwd = [System.Web.Security.Membership]::GeneratePassword(20,4)
    Set-ADAccountPassword -Identity $account `
      -NewPassword (ConvertTo-SecureString $newPwd -AsPlainText -Force) -Reset
    Set-ADUser -Identity $account -ChangePasswordAtLogon $true
    Write-Output "Reset: $account — communicate new password via secure channel"
}
```

**Step 4.3** — Krbtgt reset (if domain admin was compromised)
```powershell
# Reset krbtgt password TWICE (24h apart) to invalidate all Kerberos tickets
# WARNING: This will invalidate all active Kerberos tickets — plan downtime
Set-ADAccountPassword -Identity krbtgt `
  -NewPassword (ConvertTo-SecureString "<strong_random_pwd>" -AsPlainText -Force) -Reset
# Repeat 24 hours later
```

---

### Phase 5 — Recovery & Hardening

**Step 5.1** — Apply tiered admin model
```
Implement if not already in place:
  Tier 0: Domain admin accounts — only log on to DCs
  Tier 1: Server admin accounts — only log on to servers
  Tier 2: Workstation admin accounts — only log on to workstations
```

**Step 5.2** — Harden lateral movement vectors
```powershell
# Disable SMBv1 everywhere
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Block workstation-to-workstation SMB (if not required)
# Implement on perimeter and host firewalls

# Restrict WMI access
# Restrict PowerShell Remoting (WinRM) to admin jump hosts only
```

**Step 5.3** — Enable Windows Credential Guard
```powershell
# Requires UEFI + Virtualization-based security
# Enable via Group Policy:
# Computer Configuration > Administrative Templates >
#   System > Device Guard > Turn on Virtualization Based Security
```

---

### Phase 6 — Post-Incident

**Step 6.1** — File formal incident report using `IR-002` template

**Step 6.2** — Map full campaign to MITRE ATT&CK Navigator

**Step 6.3** — Calculate and document:
- Total dwell time (first sign → containment)
- Number of hosts affected
- Credentials compromised
- Data potentially accessed

**Step 6.4** — Brief management if domain admin was involved

---

## 4. Evidence Checklist

- [ ] Logon event exports from all affected hosts
- [ ] Process creation logs from all affected hosts  
- [ ] PsExec/tool artefact file hashes documented
- [ ] Full account list of credentials used
- [ ] Network connection logs showing hop path
- [ ] LSASS access events (if credential dumping occurred)
- [ ] Timeline documented in TheHive case
- [ ] Attack path diagram created

---

## 5. References

- [MITRE T1021.002](https://attack.mitre.org/techniques/T1021/002/)
- [MITRE T1550.002 — Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- [Microsoft: Mitigating Pass-the-Hash](https://www.microsoft.com/en-us/download/details.aspx?id=36036)
- [NSA: Spotting the Adversary with Windows Event Log Monitoring](https://apps.nsa.gov/iaarchive/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm)
