# Incident Report IR-001 — SSH Brute Force Attack
**Classification:** TLP:AMBER — Internal Use Only  
**Report Version:** 1.0 (Final)  
**Status:** Closed — Resolved  
**Severity:** HIGH  
**Report Date:** 2024-01-15  
**Incident Date:** 2024-01-15  
**Author:** SOC Analyst — SOC Lab Project  
**Case Reference:** TheHive Case #0042  
**Wazuh Rules Triggered:** 100001, 100002  

---

## 1. Executive Summary

On January 15, 2024, the SOC detected a coordinated SSH brute force attack
originating from IP address `203.0.113.42` (geolocation: Romania, AS: AS60781
LeaseWeb Netherlands) targeting the organisation's Linux endpoint
`linux-endpoint-01` (172.20.0.100). The attack consisted of 847 authentication
failures over a 4-minute period against the `root` account before successfully
authenticating at 10:34:22 UTC.

The Wazuh SIEM detected the attack within 38 seconds of the threshold being
crossed, automatically triggering the Shuffle SOAR workflow which created a
TheHive case and notified the SOC channel via Slack within 12 seconds of
detection. The attacker maintained access for approximately 6 minutes before
the compromised session was terminated and the account locked.

**Outcome:** Attacker successfully authenticated but was contained before
establishing persistence or conducting lateral movement. No data was exfiltrated.
All attacker artefacts removed. System hardened post-incident.

---

## 2. Incident Timeline
```
2024-01-15 UTC — All times UTC

10:28:44  First failed SSH authentication from 203.0.113.42 → root
          Source port: 54201 | Wazuh built-in rule 5760 fires

10:28:44  Rapid authentication failures begin
          Tool signature: Hydra/Medusa (4 attempts/second pacing)
          Targets cycled: root, admin, ubuntu, pi, deploy

10:29:22  WAZUH RULE 100001 FIRES
          "SSH brute force: 10+ failures from 203.0.113.42 in 60s"
          Level 12 — High | Alert forwarded to Elasticsearch

10:29:23  Shuffle SOAR workflow triggered by Wazuh webhook
          IP enrichment: AbuseIPDB score 97/100 | 2,847 reports

10:29:24  TheHive Case #0042 auto-created
          Title: [BF] SSH Brute Force from 203.0.113.42 on linux-endpoint-01
          Severity: High | Assigned to: soc-analyst-01

10:29:25  Slack notification delivered to #soc-alerts channel
          Message included: attacker IP, target, AbuseIPDB score,
          link to TheHive case, link to Kibana query

10:29:31  Analyst acknowledged alert (6s after Slack notification)

10:34:22  WAZUH RULE 100002 FIRES — CRITICAL ESCALATION
          "Successful SSH login from 203.0.113.42 after brute force"
          Level 15 — Maximum | Case severity escalated to Critical

10:34:22  Email alert sent to SOC distribution list (critical threshold)
          Subject: [CRITICAL] SSH Brute Force SUCCESS — linux-endpoint-01

10:34:28  Analyst begins active investigation
          Queried Kibana: all events from 203.0.113.42 last 30 minutes

10:35:10  Attacker IP blocked via UFW on linux-endpoint-01
          Rule: ufw insert 1 deny from 203.0.113.42 to any

10:35:15  Active SSH session from 203.0.113.42 identified and terminated
          Command: sudo ss -K dst 203.0.113.42

10:35:20  Root account locked
          Command: sudo passwd -l root

10:36:00  Investigation of attacker's 6-minute session begins
          Commands executed by attacker reviewed from auth.log and
          bash history

10:38:30  Investigation complete — no persistence or lateral movement found
          No files downloaded or uploaded
          No cron jobs or services created

10:45:00  SSH hardening applied: PasswordAuthentication no
          fail2ban installed and configured

10:50:00  All changes verified and tested — SSH key auth working

11:00:00  Post-incident documentation begun

11:30:00  TheHive Case #0042 closed — True Positive
          Resolution: Contained and Remediated
```

---

## 3. Attack Description

### 3.1 Attack Vector

The attacker targeted SSH (port 22/TCP) which was exposed on the internet-facing
interface of `linux-endpoint-01`. The attack used an automated credential
stuffing tool with the following characteristics identified from log analysis:

- **Tool:** Consistent 4 attempts/second pacing — consistent with Hydra or Medusa
- **Username list:** Cycled through: `root`, `admin`, `ubuntu`, `pi`, `deploy`,
  `ec2-user`, `git`, `oracle`, `postgres`, `vagrant`
- **Password list:** Common password dictionary including `password`, `123456`,
  `admin`, `root`, `toor`, and approximately 830 additional attempts
- **Source:** Single IP — not distributed (no credential stuffing proxy rotation)
- **Persistence:** Attack continued even as rule 100001 fired — attacker was
  unaware of detection

### 3.2 Successful Authentication

At 10:34:22 UTC, the attacker successfully authenticated as `root` using the
password `Password123!` — a weak password that had not been changed from the
initial system setup default. This password was in the attacker's wordlist.

### 3.3 Attacker Activity During Session (10:34:22 – 10:35:15 UTC)

Command history recovered from `/root/.bash_history` and kernel audit logs:
```bash
# Commands executed by attacker (chronological)
whoami                              # 10:34:24 — identity check
id                                  # 10:34:25 — privilege check
uname -a                            # 10:34:27 — OS fingerprinting
cat /etc/passwd | head -20          # 10:34:29 — user enumeration
cat /etc/shadow 2>/dev/null         # 10:34:31 — attempted credential harvest (FAILED - perms)
ps aux                              # 10:34:35 — process enumeration
netstat -tulpn                      # 10:34:38 — network service enumeration
cat /root/.ssh/authorized_keys      # 10:34:41 — check existing SSH keys
ls -la /home/                       # 10:34:44 — home directory enumeration
w                                   # 10:34:46 — check other logged-in users
# --- SESSION TERMINATED AT 10:35:15 ---
```

The attacker had begun reconnaissance but had not yet:
- Added SSH keys for persistence
- Created backdoor accounts
- Initiated data exfiltration
- Attempted lateral movement

The attack was interrupted before the post-reconnaissance exploitation phase.

---

## 4. Technical Analysis

### 4.1 Source IP Intelligence

| Field | Value |
|-------|-------|
| IP Address | 203.0.113.42 |
| Geolocation | Bucharest, Romania |
| ASN | AS60781 — LeaseWeb Netherlands B.V. |
| Usage Type | Data Center / Web Hosting |
| AbuseIPDB Score | 97 / 100 |
| AbuseIPDB Reports | 2,847 (90-day window) |
| Reported Categories | SSH brute force, port scan, credential stuffing |
| VirusTotal | 8/93 security vendors flagged as malicious |
| GreyNoise | Listed as known SSH scanner |
| First Seen on AbuseIPDB | 2023-03-12 |

**Assessment:** This is a well-known automated scanning IP operating from
a cloud/hosting provider. The attack was opportunistic — targeting any
system with port 22 exposed, not a targeted attack against this organisation
specifically.

### 4.2 Vulnerability Exploited

| Field | Value |
|-------|-------|
| Vulnerability Type | Weak credential / default password |
| CVE | N/A (configuration weakness, not a CVE) |
| Affected System | linux-endpoint-01 |
| Affected Account | root |
| Password Used | `Password123!` (in attacker wordlist) |
| Root Cause | SSH exposed to internet with password auth enabled |
| Contributing Factor | Default/weak password not changed at provisioning |

### 4.3 Wazuh Detection Analysis
```
Detection Performance:
  Time of first attack event   : 10:28:44 UTC
  Time of threshold breach     : 10:29:22 UTC (38s after first event)
  Time rule 100001 fired       : 10:29:22 UTC (0s delay — real-time)
  Time alert in Elasticsearch  : 10:29:22 UTC (< 1s propagation)
  Time Kibana dashboard updated: 10:29:23 UTC
  Time Shuffle workflow started : 10:29:23 UTC
  Time TheHive case created    : 10:29:24 UTC (1s after detection)
  Time Slack notification      : 10:29:25 UTC (2s after detection)
  Time analyst acknowledged    : 10:29:31 UTC (6s after Slack)

  Time of successful login     : 10:34:22 UTC
  Time rule 100002 fired       : 10:34:22 UTC (0s delay — real-time)
  Time analyst began containment: 10:34:28 UTC (6s after rule 100002)
  Time session terminated      : 10:35:15 UTC (53s after detection)
  Time account locked          : 10:35:20 UTC (58s after detection)

Total Detection-to-Containment Time: 58 seconds ✅ (SLA: < 15 minutes)
```

### 4.4 Log Evidence

**Auth log extract (Wazuh alert data — key events):**
```
Jan 15 10:28:44 linux-endpoint-01 sshd[12441]: Failed password for root from 203.0.113.42 port 54201 ssh2
Jan 15 10:28:45 linux-endpoint-01 sshd[12442]: Failed password for admin from 203.0.113.42 port 54202 ssh2
Jan 15 10:28:45 linux-endpoint-01 sshd[12443]: Invalid user ubuntu from 203.0.113.42 port 54203
[... 843 similar entries omitted ...]
Jan 15 10:34:22 linux-endpoint-01 sshd[13891]: Accepted password for root from 203.0.113.42 port 56789 ssh2
Jan 15 10:35:15 linux-endpoint-01 sshd[13891]: Received disconnect from 203.0.113.42 port 56789:11: disconnected by server
```

**Wazuh rule 100001 alert (JSON):**
```json
{
  "@timestamp": "2024-01-15T10:29:22.441Z",
  "rule": {
    "id": "100001",
    "level": 12,
    "description": "SSH brute force attack: 10+ failed logins from 203.0.113.42 in 60 seconds",
    "groups": ["authentication_failures", "brute_force"],
    "mitre": { "id": "T1110.001" }
  },
  "agent": { "name": "linux-endpoint-01", "ip": "172.20.0.100" },
  "data": { "srcip": "203.0.113.42", "srcuser": "root" }
}
```

---

## 5. Impact Assessment

| Impact Category | Assessment | Details |
|----------------|------------|---------|
| Confidentiality | **Low** | Attacker read /etc/passwd (world-readable). /etc/shadow access denied. No sensitive data exfiltrated. |
| Integrity | **None** | No files modified. No persistence established. |
| Availability | **None** | System remained fully operational during and after incident. |
| Financial | **Negligible** | No ransom, no data sold, no regulatory breach. |
| Reputational | **None** | No external impact. Internal lab environment. |
| Regulatory | **None** | No PII accessed. No notification required. |

**Overall Impact: LOW** — Attack was detected and contained before significant
damage could occur.

---

## 6. Containment Actions

| Action | Time (UTC) | Performed By | Verification |
|--------|-----------|--------------|-------------|
| Block attacker IP via UFW | 10:35:10 | soc-analyst-01 | `ufw status` confirmed deny rule #1 |
| Terminate active SSH session | 10:35:15 | soc-analyst-01 | `ss -an` showed no connection from 203.0.113.42 |
| Lock root account | 10:35:20 | soc-analyst-01 | `passwd -S root` showed `root L` |
| Disable password authentication | 10:45:00 | soc-analyst-01 | `sshd -t` passed, service restarted |

---

## 7. Eradication Actions

| Action | Details | Status |
|--------|---------|--------|
| Remove attacker files | No files found to remove | Complete |
| Check for new accounts | `awk -F: '$3 >= 1000' /etc/passwd` — no unauthorised accounts | Complete |
| Check crontabs | `crontab -l -u root` — no malicious entries | Complete |
| Check .ssh/authorized_keys | No keys added by attacker | Complete |
| Check running services | No new services found | Complete |
| Password reset | Root password changed to strong passphrase | Complete |

---

## 8. Recovery Actions

| Action | Details | Status |
|--------|---------|--------|
| Re-enable root for admin use | Root locked as precaution — created admin user with sudo | Complete |
| SSH key-based auth configured | Generated ed25519 key pair for all admin accounts | Complete |
| Disable password auth in sshd | `PasswordAuthentication no` in /etc/ssh/sshd_config | Complete |
| fail2ban installed | Config: maxretry=3, bantime=3600, findtime=300 | Complete |
| Verify Wazuh monitoring | Agent healthy, rules active, test alert verified | Complete |

---

## 9. Root Cause Analysis

### Primary Root Cause
SSH port 22 was exposed to the internet with password-based authentication
enabled and a weak default password (`Password123!`) on the root account.

### Contributing Factors
1. **No hardening at provisioning** — SSH password auth not disabled during
   initial system setup
2. **Weak password policy** — No enforcement of minimum complexity for
   the root account
3. **SSH port exposure** — Port 22 open to all source IPs with no IP allowlist
4. **No fail2ban** — No rate limiting on authentication attempts at the
   OS level before Wazuh detection

### Why Detection Worked
1. Wazuh rule 100001 frequency counter correctly triggered at 10 failures/60s
2. Rule 100002 correlation correctly identified the success-after-brute-force
3. Shuffle SOAR automation reduced analyst response time to 6 seconds
4. The 58-second detection-to-containment time prevented attacker from
   establishing persistence

---

## 10. Lessons Learned

### What Went Well
- **Detection speed** — Wazuh fired within 0 seconds of threshold crossing
- **Automation** — TheHive case and Slack notification created in < 2 seconds
- **Analyst response** — Acknowledged within 6 seconds of Slack notification
- **Correlation rule** — Rule 100002 successfully caught the successful login
- **Containment** — Session terminated within 58 seconds of successful login

### What Needs Improvement
- **Preventive controls** — The attack should never have succeeded
  SSH password auth should have been disabled from day one
- **Alert fatigue risk** — 847 rule 5760 events before 100001 fired could
  cause noise in a busier environment
- **Proactive hardening** — fail2ban was not installed pre-incident
- **Password policy** — Weak root password was the ultimate root cause

### Detection Improvements Made
```xml
<!-- Verified rule 100001 thresholds are appropriate — no changes needed -->
<!-- Added IP allowlist for SSH access: only SOC management IPs -->
<!-- fail2ban now provides OS-level rate limiting below Wazuh layer -->
```

---

## 11. Recommendations

### Immediate (Completed During Incident)
- [x] Disable SSH password authentication
- [x] Configure SSH key-based authentication only
- [x] Install and configure fail2ban
- [x] Block attacker IP permanently

### Short-Term (Within 1 Week)
- [ ] Implement SSH allowlist — only permit from known management IPs
- [ ] Deploy SSH on non-standard port (security through obscurity, defence in depth)
- [ ] Review all other exposed services for similar weak credentials
- [ ] Add rule to detect SSH on non-standard ports

### Long-Term (Within 1 Month)
- [ ] Implement centralised credential management (HashiCorp Vault)
- [ ] Add CDB threat intel list for known SSH scanning IPs to auto-block
- [ ] Configure Wazuh active response to auto-block IPs after rule 100001
- [ ] Implement network-level firewall restricting SSH to VPN/management VLAN

---

## 12. IOCs (Indicators of Compromise)

| Type | Value | Confidence | Action |
|------|-------|-----------|--------|
| IP Address | 203.0.113.42 | High | Blocked via UFW |
| ASN | AS60781 LeaseWeb Netherlands | Medium | Monitor |
| Attack Tool | Hydra/Medusa (pacing signature) | Medium | N/A |
| Username | root (primary target) | N/A | Account hardened |
| Password | Password123! (compromised) | High | Changed |

---

## 13. Metrics

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Detection Time (first event → alert) | 38s | < 60s | ✅ |
| Automation Time (alert → TheHive case) | 1s | < 30s | ✅ |
| Notification Time (alert → Slack) | 2s | < 60s | ✅ |
| Analyst Acknowledgement | 6s | < 5 min | ✅ |
| Containment Time (detection → block) | 58s | < 15 min | ✅ |
| Total Incident Duration | 66 min | < 4h | ✅ |
| Data Exfiltrated | 0 bytes | 0 | ✅ |
| Persistence Established | No | No | ✅ |

---

## 14. Sign-off

| Role | Name | Date |
|------|------|------|
| Incident Analyst | SOC Analyst | 2024-01-15 |
| SOC Lead (Review) | SOC Lead | 2024-01-15 |

**Case Status:** CLOSED — True Positive — Resolved  
**TheHive Case:** #0042  
**Next Review:** Lessons learned reviewed at next team meeting
