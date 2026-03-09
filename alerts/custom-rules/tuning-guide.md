# Wazuh Custom Rule Tuning Guide
**Version:** 1.0  
**Author:** SOC Lab Project  
**Purpose:** Explains how to adjust detection thresholds, reduce false
positives, and improve true positive rates for all 10 custom SOC rules.

---

## 1. Core Tuning Concepts

### 1.1 The FP/FN Trade-off

Every detection rule sits on a spectrum:
```
Too Sensitive                              Too Strict
      │                                         │
 Many False Positives                    Many False Negatives
 (Alert fatigue,                         (Real attacks missed,
  analysts stop trusting alerts)          SOC becomes blind)
      │                                         │
      └──────────── OPTIMAL ────────────────────┘
                  (Tuned rule:
               low FP, low FN)
```

Your goal is to tune each rule to sit as close to OPTIMAL as possible
for YOUR environment. There is no universal threshold — what works
in a 10-person startup is wrong for a 10,000-person enterprise.

### 1.2 Tuning Levers Available in Wazuh

| Lever | Effect | Use When |
|-------|--------|----------|
| Raise `level` | Alert less urgently | Signal is real but lower risk in your context |
| Lower `level` | Alert more urgently | Threats are higher risk in your environment |
| Raise `frequency` | Require more events before firing | Too many FPs from noisy sources |
| Lower `frequency` | Fire on fewer events | You need faster detection |
| Raise `timeframe` | Wider detection window | Attackers pacing slowly |
| Lower `timeframe` | Tighter detection window | Reduce FPs from bursty-but-legit activity |
| Add `<field negate="yes">` | Exclude specific values | Known-good process/IP/user causing FPs |
| Add `<same_user>` | Count per-user instead of per-IP | User-focused attack patterns |
| Add `<same_dst_ip>` | Count per destination | Detect scanning behaviour |

### 1.3 Tuning Workflow
```
1. Run rule in production for 1–2 weeks
2. Export all alerts to spreadsheet
3. Triage each: True Positive (TP) or False Positive (FP)?
4. For FPs: identify WHAT triggered the FP (which field, which value)
5. Add exclusion or adjust threshold
6. Document change in tuning-report-v1.md
7. Re-run for another week, measure FP rate improvement
8. Repeat until FP rate < 5% while maintaining TP detection
```

---

## 2. Rule-by-Rule Tuning Reference

### Rule 100001 — SSH Brute Force

**Default:** frequency=10, timeframe=60

**Raise frequency to 20 if you see FPs from:**
```xml
<rule id="100001" level="12" frequency="20" timeframe="60">
```
- CI/CD pipelines doing SSH health checks
- Ansible/Chef/Puppet that retries on connection failure
- Load balancers probing backend SSH availability

**Add exclusions for known scanners:**
```xml
<rule id="100001" level="12" frequency="10" timeframe="60">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip />
  <!-- Exclude known Shodan/Censys scanner IPs via CDB list -->
  <list field="srcip" lookup="not_match_key">etc/lists/known-scanners</list>
  <description>SSH brute force: 10+ failures from $(srcip) in 60s</description>
  ...
</rule>
```

**For environments with many SSH users — use per-user counting:**
```xml
<same_source_ip />
<same_user />   <!-- Count failures per IP+user combination -->
```

---

### Rule 100002 — Successful Login After Brute Force

**Default:** timeframe=120 (2 minutes)

This rule has very low FP rates — almost never needs tuning.
Only adjust if:
- Your auth system retries logins automatically after failure
  → Raise timeframe to 300
- You want faster correlation of slow attacks
  → Raise timeframe to 600 (10 minutes)

**Never lower the level below 13** — this is your highest-confidence
indicator of a successful compromise. Keep it loud.

---

### Rule 100003 — LSASS Access

**Default:** level=14, no frequency (single-event trigger)

**Add exclusions for AV/EDR products that legitimately access LSASS:**
```xml
<rule id="100003" level="14">
  <if_group>windows</if_group>
  <field name="win.system.eventID">^10$</field>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe$</field>
  <!-- Exclude Windows Error Reporting and known AV tools -->
  <field name="win.eventdata.sourceImage" negate="yes" type="pcre2">
    (?i)(WerFault|MsMpEng|SenseIR|CylanceSvc|cbsensor|bdservicehost)\.exe$
  </field>
  <description>Credential dumping: $(win.eventdata.sourceImage) accessed LSASS</description>
  ...
</rule>
```

**Build your exclusion list incrementally:**
1. Run rule for 1 week
2. Identify FP source processes from `win.eventdata.sourceImage`
3. Verify each is a legitimate security product (check vendor + hash)
4. Add to exclusion regex only after verification

---

### Rule 100004 — PsExec Lateral Movement

**Default:** level=13

**If PsExec is used legitimately by admins in your environment:**
```xml
<!-- Option 1: Lower level for known-good admin accounts -->
<rule id="100004" level="8">   <!-- Medium instead of Critical -->
  <if_group>windows</if_group>
  <field name="win.system.eventID">^1$|^7045$</field>
  <field name="win.eventdata.image|win.eventdata.serviceName" type="pcre2">(?i)(psexec|psexesvc|paexec)</field>
  <!-- Only match if NOT from known admin accounts -->
  <field name="win.eventdata.user" negate="yes" type="pcre2">(?i)(soc-admin|it-admin|domain\\admins)</field>
  ...
</rule>

<!-- Option 2: Keep level 13 but only for non-admin accounts -->
<rule id="100004b" level="13">
  ...same conditions...
  <!-- Add: must NOT be a known admin user -->
  <field name="win.eventdata.user" negate="yes" type="pcre2">(?i)(it-helpdesk|sysadmin)</field>
</rule>
```

---

### Rule 100005 — Suspicious PowerShell

**Default:** level=12, matches many PS flags

**Reduce noise from SCCM/Intune management:**
```xml
<field name="win.eventdata.parentImage" negate="yes" type="pcre2">
  (?i)(CCMExec|smsagent|SCClient|IntuneMDM|MsMpEng)\.exe$
</field>
```

**Reduce noise from developer workstations:**
```xml
<!-- Lower level for developer machines (create a "developers" agent group) -->
<rule id="100005" level="8">   <!-- Medium on dev machines -->
  <if_group>windows,developers</if_group>   <!-- developers group only -->
  ...
</rule>
```

**Split into two rules for better prioritisation:**
```xml
<!-- High confidence: encoded command + download combo -->
<rule id="100005a" level="14">
  <field name="win.eventdata.commandLine" type="pcre2">
    (?i)(-enc|-EncodedCommand).*(DownloadString|Net\.WebClient|IEX)
  </field>
  ...
</rule>

<!-- Medium confidence: single suspicious flag -->  
<rule id="100005b" level="10">
  <field name="win.eventdata.commandLine" type="pcre2">
    (?i)(-ep bypass|-ExecutionPolicy\s+Bypass|-WindowStyle\s+[Hh]idden)
  </field>
  ...
</rule>
```

---

### Rule 100006 — Ransomware Behaviour

**Default:** frequency=20, timeframe=30, level=15

**This rule should almost never need lowering.**
If you're getting FPs, investigate what's creating files with those
extensions — it might actually be ransomware or a backup tool
encrypting files (legitimate but needs review).

**For backup software using .enc/.encrypted extensions:**
```xml
<!-- Exclude backup service account -->
<field name="syscheck.uname_after" negate="yes" type="pcre2">
  (?i)(backup-svc|veeam|backupexec|acronis)
</field>
```

**Expand the extension list as new ransomware families emerge:**
- Monitor: https://id-ransomware.malwarehunterteam.com/
- Monitor: https://www.bleepingcomputer.com/ransomware-decryptor/

---

### Rules 100007, 100008 — Persistence Detection

**Common legitimate FP sources:**
- Software installers writing to Run keys: add exclusion for msiexec.exe
- Windows Update writing to services: add exclusion for TrustedInstaller
- Cloud sync apps (OneDrive, Dropbox): add exclusion for specific process names

**Exclusion pattern:**
```xml
<field name="win.eventdata.image" negate="yes" type="pcre2">
  (?i)(msiexec|TrustedInstaller|OneDriveSetup|DropboxUpdate|
       GoogleUpdate|Teams.*Setup|VCRedist)\.exe$
</field>
```

---

### Rules 100009, 100010 — Network / Exfil Detection

**Tune port list for your environment:**
- Remove ports your applications legitimately use
- Add ports specific to tools in your threat model

**For 100010 (exfil) — reduce noise from developers:**
```xml
<!-- Exclude known CI/CD pipeline service accounts -->
<field name="win.eventdata.user" negate="yes" type="pcre2">
  (?i)(jenkins|gitlab-runner|circleci|build-agent)
</field>
```

---

## 3. Using Wazuh's Testing Tool

Before deploying any rule change, test it:
```bash
# On the Wazuh manager
docker exec -it wazuh-manager bash

# Test a specific log line against all rules
echo 'Jan 15 10:00:00 host sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2' \
  | /var/ossec/bin/ossec-logtest -t

# Test and show which decoder fires
echo '<log line>' | /var/ossec/bin/ossec-logtest -v

# Validate rule file XML syntax before deploying
/var/ossec/bin/wazuh-control -t
```

---

## 4. Measuring Improvement

Track these metrics weekly:

| Metric | Target | How to Measure |
|--------|--------|----------------|
| False Positive Rate | < 5% | (FP count / total alerts) × 100 |
| Alert Fatigue Score | < 20 alerts/analyst/day | Total alerts ÷ analyst count |
| Mean Time to Triage | < 10 min | Average time from alert to triage decision |
| True Positive Rate | > 80% | (TP count / total alerts) × 100 |
| Detection Coverage | > 70% MITRE | ATT&CK Navigator heatmap |
```bash
# Quick FP rate query in Elasticsearch
curl -su elastic:${ELASTIC_PASSWORD} \
  "http://localhost:9200/wazuh-alerts-*/_search" \
  -H "Content-Type: application/json" \
  -d '{
    "size": 0,
    "query": {
      "range": { "@timestamp": { "gte": "now-7d" } }
    },
    "aggs": {
      "by_rule": {
        "terms": { "field": "rule.id", "size": 20 },
        "aggs": {
          "alert_count": { "value_count": { "field": "_id" } }
        }
      }
    }
  }' | python3 -m json.tool
```
