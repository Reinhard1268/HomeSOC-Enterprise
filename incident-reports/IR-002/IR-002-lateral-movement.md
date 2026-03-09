# Incident Report IR-002 — Lateral Movement via PsExec
**Classification:** TLP:AMBER — Internal Use Only  
**Report Version:** 1.0 (Final)  
**Status:** Closed — Resolved  
**Severity:** HIGH  
**Report Date:** 2024-01-18  
**Incident Date:** 2024-01-18  
**Author:** SOC Analyst — SOC Lab Project  
**Case Reference:** TheHive Case #0051  
**Wazuh Rules Triggered:** 100001, 100002, 100004, 100003  

---

## 1. Executive Summary

On January 18, 2024, the SOC detected a multi-stage intrusion that began
with a successful SSH brute force against workstation `WIN-WORKSTATION-01`
(172.20.0.110), followed by credential harvesting via LSASS memory access,
and lateral movement using PsExec to reach the file server `WIN-FILESERVER-01`
(172.20.0.120).

The attacker used stolen domain credentials (`DOMAIN\svc-backup`) to execute
commands on the file server. The incident was detected at each stage by the
custom Wazuh ruleset. The lateral movement was identified within 2 minutes of
the PSEXESVC service appearing on the destination host. The attacker's dwell
time from initial access to containment was 23 minutes.

**Outcome:** Attacker reached the file server and performed reconnaissance
but did not access sensitive files or establish secondary persistence.
All three affected systems were contained, cleaned, and hardened.
Compromised credentials were rotated across all systems.

---

## 2. Incident Timeline
```
2024-01-18 UTC — All times UTC

14:12:03  Initial brute force begins against WIN-WORKSTATION-01
          Source: 198.51.100.77 (external IP)
          Target account: administrator

14:12:41  WAZUH RULE 100001 FIRES on WIN-WORKSTATION-01
          Level 12 — High | TheHive Case #0051 auto-created

14:13:55  WAZUH RULE 100002 FIRES — Successful login after brute force
          Level 15 — Critical | Case escalated | Analyst paged

14:14:02  Analyst begins active triage

14:15:30  WAZUH RULE 100003 FIRES on WIN-WORKSTATION-01
          "Credential dumping: mimikatz.exe accessed LSASS memory"
          Level 14 — Critical | Case updated

          Attacker ran: mimikatz.exe "privilege::debug sekurlsa::logonpasswords"
          Credential harvested: DOMAIN\svc-backup (service account)
          Password hash captured — NTLM hash crackable offline

14:17:48  Attacker uses PsExec from WIN-WORKSTATION-01 to WIN-FILESERVER-01
          Command: PsExec.exe \\172.20.0.120 -u DOMAIN\svc-backup
                   -p [password] cmd.exe

14:17:49  WAZUH RULE 100004 FIRES on WIN-FILESERVER-01
          "Lateral movement via PsExec detected: PSEXESVC on WIN-FILESERVER-01"
          Level 13 — Critical | Case updated with second affected host

14:17:55  Analyst identifies lateral movement — containment begins

14:18:30  WIN-WORKSTATION-01 network-isolated via firewall rules

14:19:00  svc-backup account disabled in Active Directory

14:19:45  WIN-FILESERVER-01 network-isolated via firewall rules

14:20:15  PSEXESVC service stopped and deleted on WIN-FILESERVER-01

14:25:00  Forensic investigation begins on both hosts

14:35:00  Investigation determines attacker performed reconnaissance
          only — no files accessed/modified/exfiltrated

14:37:00  Eradication complete on both hosts

14:40:00  Recovery begins — hosts reconnected with hardened config

14:50:00  All credentials rotated — investigation ongoing

15:00:00  Incident declared contained — post-incident review begins

16:15:00  Full incident report drafted

18:00:00  TheHive Case #0051 closed
```

---

## 3. Attack Description

### 3.1 Attack Chain
```
STAGE 1: Initial Access
  External IP 198.51.100.77
       │
       │ SSH/RDP Brute Force (T1110.001)
       ▼
  WIN-WORKSTATION-01 (172.20.0.110)
  administrator account compromised

STAGE 2: Credential Access
  WIN-WORKSTATION-01
       │
       │ LSASS Memory Access via Mimikatz (T1003.001)
       │ Captured: DOMAIN\svc-backup NTLM hash
       ▼
  Credentials harvested

STAGE 3: Lateral Movement
  WIN-WORKSTATION-01 (pivot)
       │
       │ PsExec using svc-backup credentials (T1021.002)
       │ PSEXESVC service created on target
       ▼
  WIN-FILESERVER-01 (172.20.0.120)
  Reconnaissance performed — no data access

STAGE 4: (Prevented) Impact / Exfiltration
  WIN-FILESERVER-01
       │
       │ BLOCKED — containment at 14:19:45
       ▼
  No further movement or data access
```

### 3.2 Tools Used by Attacker

| Tool | Purpose | Detected By |
|------|---------|-------------|
| Unknown brute force tool | SSH/RDP brute force | Wazuh rule 100001 |
| Mimikatz | LSASS credential dumping | Wazuh rule 100003 (Sysmon EID 10) |
| PsExec | Lateral movement via SMB | Wazuh rule 100004 (EID 7045) |
| cmd.exe (remote) | Reconnaissance on file server | Process audit logging |

### 3.3 Attacker Activity on WIN-FILESERVER-01

Commands executed via PsExec remote shell:
```cmd
whoami                              # DOMAIN\svc-backup — confirmed pivot
ipconfig /all                       # Network enumeration
net user /domain                    # Domain user enumeration
net group "Domain Admins" /domain   # Admin account enumeration
dir C:\Shares\ /s /b                # File share enumeration
dir C:\Users\ /b                    # User profile enumeration
net view \\WIN-DC-01                # Domain controller discovery
# --- SESSION TERMINATED BY CONTAINMENT at 14:19:45 ---
```

The attacker was performing network and user enumeration — standard
post-exploitation reconnaissance. They had not yet attempted to access
specific files or move to the domain controller.

---

## 4. Technical Analysis

### 4.1 Source IP Intelligence

| Field | Value |
|-------|-------|
| IP Address | 198.51.100.77 |
| Geolocation | Amsterdam, Netherlands |
| ASN | AS209 — CenturyLink Communications |
| Usage Type | VPN / Hosting |
| AbuseIPDB Score | 84 / 100 |
| Reported Categories | Brute force, port scan |
| GreyNoise | Known VPN exit node |

### 4.2 Compromised Credential Analysis

| Field | Value |
|-------|-------|
| Account | DOMAIN\svc-backup |
| Account Type | Service account |
| Privileges | Domain user + local admin on file server |
| Password Age | 847 days (never rotated) |
| NTLM Hash | (redacted — rotated) |
| Used For | Backup job scheduled task |

**Key Finding:** The `svc-backup` service account had not had its password
rotated in 847 days, violating the organisation's 90-day rotation policy.
The account also had broader local admin rights than required for its
function (backup operations only).

### 4.3 Wazuh Detection Cascade

Each stage of the attack chain was detected by a separate Wazuh rule,
demonstrating the value of defence-in-depth detection:
```
Stage        Rule    Level   Trigger                        Latency
─────────────────────────────────────────────────────────────────────
Brute Force  100001  12      10+ failures / 60s             0s (real-time)
Compromise   100002  15      Success after brute force      0s (real-time)
Cred Dump    100003  14      Sysmon EID 10: LSASS access    <1s
Lateral Move 100004  13      Sysmon EID 7045: PSEXESVC      <1s
─────────────────────────────────────────────────────────────────────
Total detection cascade: All 4 stages detected in <2 minutes
```

### 4.4 Sysmon Evidence — LSASS Access (Rule 100003)
```json
{
  "@timestamp": "2024-01-18T14:15:30.812Z",
  "rule": { "id": "100003", "level": 14,
    "description": "Credential dumping: mimikatz.exe accessed LSASS memory" },
  "win": {
    "system": { "eventID": "10", "computer": "WIN-WORKSTATION-01" },
    "eventdata": {
      "sourceImage": "C:\\Users\\administrator\\Downloads\\mimikatz.exe",
      "targetImage":  "C:\\Windows\\system32\\lsass.exe",
      "grantedAccess": "0x1410",
      "callTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+..."
    }
  }
}
```

### 4.5 Sysmon Evidence — PsExec Detection (Rule 100004)
```json
{
  "@timestamp": "2024-01-18T14:17:49.223Z",
  "rule": { "id": "100004", "level": 13,
    "description": "Lateral movement via PsExec: PSEXESVC on WIN-FILESERVER-01" },
  "win": {
    "system": { "eventID": "7045", "computer": "WIN-FILESERVER-01" },
    "eventdata": {
      "serviceName": "PSEXESVC",
      "serviceType": "user mode service",
      "startType":   "demand start",
      "imageFile":   "C:\\Windows\\PSEXESVC.exe",
      "accountName": "LocalSystem"
    }
  }
}
```

---

## 5. Impact Assessment

| Category | Assessment | Details |
|----------|------------|---------|
| Confidentiality | **Medium** | LSASS dumped — credentials of all logged-in users compromised. File server reached but no files accessed. |
| Integrity | **Low** | PSEXESVC binary dropped on file server (cleaned). No other modifications. |
| Availability | **None** | No service disruption. Isolation was controlled. |
| Financial | **Low** | Cost of incident response time. No data sold or ransomed. |
| Reputational | **None** | Internal lab — no external impact. |
| Regulatory | **None** | No customer PII accessed. |

**Overall Impact: MEDIUM** — Attacker reached sensitive infrastructure
but was contained before accessing data. Credential compromise requires
full rotation of affected accounts.

---

## 6. Affected Systems and Accounts

### Systems Affected

| Hostname | IP | Role | Compromise Level |
|---------|-----|------|-----------------|
| WIN-WORKSTATION-01 | 172.20.0.110 | Developer workstation | Full compromise (admin access) |
| WIN-FILESERVER-01 | 172.20.0.120 | File server | Partial (PsExec access, no data) |

### Accounts Compromised

| Account | Type | Compromise Type | Action Taken |
|---------|------|----------------|-------------|
| DOMAIN\administrator | Local admin | Password known to attacker | Password reset, MFA added |
| DOMAIN\svc-backup | Service account | NTLM hash captured | Password reset, rights scoped |
| WIN-WORKSTATION-01\administrator | Local | Direct compromise | Password reset |
| All accounts logged into WIN-WORKSTATION-01 at time of dump | Various | LSASS dump exposure | All passwords reset |

---

## 7. Containment, Eradication & Recovery

### Containment
```powershell
# WIN-WORKSTATION-01 — network isolation
New-NetFirewallRule -DisplayName 'IR-002-ISOLATE-IN'  -Direction Inbound  -Action Block
New-NetFirewallRule -DisplayName 'IR-002-ISOLATE-OUT' -Direction Outbound -Action Block
New-NetFirewallRule -DisplayName 'IR-002-SOC-IN'  -Direction Inbound  -RemoteAddress 172.20.0.1 -Action Allow
New-NetFirewallRule -DisplayName 'IR-002-SOC-OUT' -Direction Outbound -RemoteAddress 172.20.0.1 -Action Allow

# Disable compromised service account immediately
Disable-ADAccount -Identity svc-backup
```

### Eradication
```powershell
# Remove PSEXESVC from file server
Stop-Service PSEXESVC -Force
Remove-Item C:\Windows\PSEXESVC.exe -Force
sc.exe delete PSEXESVC

# Remove mimikatz from workstation
Remove-Item "C:\Users\administrator\Downloads\mimikatz.exe" -Force

# Full AV scan on both systems
Start-MpScan -ScanType FullScan
```

### Recovery
```powershell
# Reset all compromised credentials
Set-ADAccountPassword -Identity svc-backup `
  -NewPassword (ConvertTo-SecureString "NewStr0ngP@ssw0rd2024!" -AsPlainText -Force) -Reset
Enable-ADAccount -Identity svc-backup

# Scope svc-backup permissions to minimum required
# Removed local admin rights on WIN-FILESERVER-01
# Retained only: backup operator group membership
```

---

## 8. Root Cause Analysis

### Primary Root Cause
Successful initial access via brute force (same root cause as IR-001) leading
to credential harvesting — attacker was then able to use stolen service account
credentials for lateral movement.

### Contributing Factors
1. **Privileged credential exposure** — svc-backup was logged into
   WIN-WORKSTATION-01 for a maintenance task, placing its credentials
   in LSASS memory at time of compromise
2. **Excessive service account privileges** — svc-backup had local admin
   rights on WIN-FILESERVER-01 beyond what backup operations required
3. **Stale credentials** — svc-backup password not rotated for 847 days
4. **No Credential Guard** — NTLM hashes were accessible in LSASS
5. **Mimikatz not blocked** — No application allowlisting to prevent
   credential dumping tools
6. **Lateral movement tool not blocked** — PsExec executable not restricted
   via AppLocker or software restriction policy

### Why Detection Chain Worked
The detection worked because of the LAYERED approach — even though initial
access was not prevented, each subsequent attacker action triggered a
separate detection rule creating a complete audit trail of the attack.

---

## 9. Lessons Learned

### What Went Well
- **Multi-stage detection** — All 4 attack stages detected via separate rules
- **Rapid escalation** — Rule 100002 (success after brute force) triggered
  immediate page to on-call analyst
- **TheHive automation** — Case automatically updated at each detection stage
  by Shuffle workflow, giving analyst real-time attack progression
- **Detection latency** — All rules fired in < 2 minutes total

### What Needs Improvement
- **Prevention gaps** — Four separate preventive failures allowed this:
  1. Weak/default credentials (same as IR-001)
  2. Unconstrained service account privileges
  3. No Credential Guard deployment
  4. No PsExec blocking via AppLocker
- **Incident linkage** — IR-001 and IR-002 share root cause (weak SSH creds)
  indicating a systemic credential management problem
- **Service account hygiene** — 847-day-old password unacceptable

### Detection Improvements Planned
- Deploy Credential Guard on all Windows endpoints
- Add Wazuh rule for Mimikatz-specific callTrace patterns
- Implement AppLocker to block PsExec on servers
- Add network segmentation rule to block workstation-to-server SMB

---

## 10. Recommendations

### Immediate (Completed)
- [x] Isolate and clean all affected systems
- [x] Rotate all compromised credentials
- [x] Remove PSEXESVC and attacker tools
- [x] Scope svc-backup to minimum required permissions

### Short-Term (1 Week)
- [ ] Enable Credential Guard on all Windows 10/11 systems
- [ ] Implement AppLocker policy blocking PsExec execution
- [ ] Enforce 90-day password rotation for all service accounts
- [ ] Deploy LAPS for local administrator account management

### Long-Term (1 Month)
- [ ] Implement Privileged Access Workstations (PAWs) for admin tasks
- [ ] Deploy tiered admin model (Tier 0/1/2)
- [ ] Network segmentation — block SMB between workstation VLANs
- [ ] Consider deploying a deception solution (honeypot) on SMB

---

## 11. IOCs

| Type | Value | Confidence | Action |
|------|-------|-----------|--------|
| IP | 198.51.100.77 | High | Blocked |
| File | mimikatz.exe (SHA256: 912018ab...) | High | Blocked in AV |
| File | PSEXESVC.exe | Medium | AppLocker block |
| Account | DOMAIN\svc-backup | High | Password reset |
| Technique | LSASS access (grantedAccess: 0x1410) | High | Detection rule active |

---

## 12. Metrics

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Stages Detected / Total Stages | 4 / 4 | 4 / 4 | ✅ |
| Mean Detection Latency per Stage | < 1s | < 60s | ✅ |
| Time to Identify Lateral Movement | 2 min | < 15 min | ✅ |
| Total Dwell Time | 23 min | < 1h | ✅ |
| Files Accessed/Exfiltrated | 0 | 0 | ✅ |
| Hosts Affected | 2 | < 5 | ✅ |
| DC Reached | No | No | ✅ |

---

## 13. Sign-off

| Role | Name | Date |
|------|------|------|
| Incident Analyst | SOC Analyst | 2024-01-18 |
| SOC Lead (Review) | SOC Lead | 2024-01-18 |

**Case Status:** CLOSED — True Positive — Resolved  
**TheHive Case:** #0051  
**Related Incidents:** IR-001 (same root cause — weak SSH credentials)
