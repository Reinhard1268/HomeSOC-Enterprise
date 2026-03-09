# Atomic Red Team — Simulation Results Template
**Template Version:** 1.0  
**Author:** SOC Lab Project  
**Instructions:** Copy this file and rename it for each simulation run.  
**Naming convention:** `results-YYYYMMDD-<simulation-name>.md`  
**Example:** `results-20240115-brute-force.md`

---

## 1. Simulation Metadata

| Field | Value |
|-------|-------|
| **Simulation Name** | *(e.g. simulate-brute-force.py)* |
| **MITRE ATT&CK Technique** | *(e.g. T1110.001 — Brute Force: Password Guessing)* |
| **Date & Time (UTC)** | *(e.g. 2024-01-15 10:30:00 UTC)* |
| **Duration** | *(e.g. 4 minutes 32 seconds)* |
| **Operator** | *(Your name / handle)* |
| **Lab Environment** | *(e.g. Home SOC Lab — Kali Linux / Docker)* |
| **Target Agent** | *(e.g. linux-endpoint-01 / 172.20.0.100)* |
| **Script Version** | *(Git commit hash or version)* |

---

## 2. Command Executed
```bash
# Paste the exact command used to run the simulation
python3 atomic-red-team/scenarios/simulate-brute-force.py \
  --target 172.20.0.100 \
  --user root \
  --attempts 15 \
  --delay 0.5
```

**Script output summary:**
```
# Paste key lines from script output here
# Focus on: attempts made, success/failure counts, any errors
```

---

## 3. Expected vs Actual Detections

### 3.1 Expected Wazuh Rules

| Rule ID | Description | Expected Level | Status |
|---------|-------------|----------------|--------|
| *(e.g. 100001)* | *(e.g. SSH brute force 10+ failures)* | *(e.g. 12 — High)* | ✅ Fired / ❌ Not Fired / ⚠️ Partial |

### 3.2 Actual Wazuh Alerts Observed

*Screenshot or paste of Wazuh dashboard alert(s)*

| Timestamp | Rule ID | Level | Agent | Description |
|-----------|---------|-------|-------|-------------|
| *(e.g. 2024-01-15 10:30:45)* | *(e.g. 100001)* | *(e.g. 12)* | *(e.g. linux-endpoint-01)* | *(e.g. SSH brute force: 10+ failures from 172.20.0.1)* |

### 3.3 Kibana Verification Query
```kql
# KQL query used to find the alert in Kibana Discover
rule.id:"100001" AND @timestamp:[now-1h TO now]
```

**Results:** *(e.g. 1 document found matching rule 100001)*

### 3.4 Verify Script Output
```bash
# Run verify script and paste output
python3 scripts/testing/verify-detections.py --simulation brute-force --since 30

# Expected output:
# [PASS] brute-force
#   [FOUND] Rule 100001  [REQUIRED]       1 alert(s)  L12 | linux-endpoint-01 | 2024-01-15...
```

---

## 4. Pipeline Verification

Confirm the full detection pipeline functioned correctly:

| Stage | Status | Notes |
|-------|--------|-------|
| Attack generated (script ran) | ✅ / ❌ | |
| Wazuh agent collected logs | ✅ / ❌ | Verify: `wazuh-control status` |
| Wazuh manager rule matched | ✅ / ❌ | Verify: `wazuh-logtest` |
| Alert forwarded to Elasticsearch | ✅ / ❌ | Verify: ES query |
| Alert visible in Kibana | ✅ / ❌ | Verify: dashboard |
| TheHive case auto-created | ✅ / ❌ | Verify: TheHive UI |
| Shuffle workflow triggered | ✅ / ❌ | Verify: Shuffle execution log |
| Slack/email notification sent | ✅ / ❌ | Verify: check channel |

---

## 5. Detection Timeline
```
HH:MM:SS  Simulation started
HH:MM:SS  First malicious event generated
HH:MM:SS  Wazuh agent collected first log
HH:MM:SS  Wazuh rule fired (rule XXXXX)
HH:MM:SS  Alert appeared in Elasticsearch
HH:MM:SS  Kibana dashboard updated
HH:MM:SS  TheHive case created (Case #XX)
HH:MM:SS  Shuffle workflow completed
HH:MM:SS  Slack notification received
────────────────────────────────────
Total detection time: XX seconds
Total response time:  XX seconds
```

---

## 6. Detection Gaps / False Negatives

*Did any expected rules NOT fire? Document here.*

| Expected Rule | Reason Not Fired | Remediation |
|--------------|-----------------|-------------|
| *(e.g. 100002)* | *(e.g. No successful login in test scope)* | *(e.g. Add --succeed flag in next run)* |

---

## 7. False Positives Generated

*Did the simulation trigger any unintended alerts?*

| Rule ID | Description | FP Type | Action |
|---------|-------------|---------|--------|
| *(e.g. 5710)* | *(e.g. Reverse lookup failed)* | *(e.g. Benign side effect)* | *(e.g. Add to FP exclusion list)* |

---

## 8. Evidence Collected

| Evidence Type | Location | Hash (SHA256) |
|--------------|----------|--------------|
| Wazuh alert JSON export | *(path or attachment)* | *(sha256)* |
| Kibana screenshot | *(path or attachment)* | *(sha256)* |
| Script output log | *(path or attachment)* | *(sha256)* |
| TheHive case export | *(case number + path)* | *(sha256)* |
| Network pcap (if captured) | *(path or attachment)* | *(sha256)* |

---

## 9. MITRE ATT&CK Coverage Assessment
```
Tactic: Initial Access / Credential Access / Lateral Movement / Impact
         (circle the applicable tactic)

Technique: TXXXX.XXX — (technique name)

Sub-techniques tested:
  ✅ Tested and detected
  ❌ Tested but NOT detected (gap)
  ⚠️  Partially detected
  ⬜ Not tested in this run
```

**ATT&CK Navigator layer:** *(Link or attach .json layer file)*

---

## 10. Observations & Recommendations

### What Worked Well
- *(Detection fired within expected timeframe)*
- *(TheHive case created automatically)*
- *(Slack notification included all relevant context)*

### What Needs Improvement
- *(Rule X threshold too high — missed first 5 attempts)*
- *(Detection latency was 45s — target is < 30s)*
- *(Missing detection for variant technique Y)*

### Recommended Rule Changes
```xml
<!-- Example: Lower frequency threshold to catch faster attacks -->
<rule id="100001" level="12" frequency="8" timeframe="60">
  <!-- Changed from frequency="10" based on simulation results -->
  ...
</rule>
```

### Next Simulation Recommended
- *(e.g. Re-run with --succeed flag to test rule 100002 correlation)*
- *(e.g. Test renamed psexec binary to verify rule 100004 misses it)*
- *(e.g. Combine lateral movement with credential dumping chain)*

---

## 11. Sign-off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Simulation Operator | | | |
| SOC Analyst (Reviewer) | | | |

---

*Template version 1.0 — SOC Lab Project*  
*Store completed reports in: `atomic-red-team/results/`*
