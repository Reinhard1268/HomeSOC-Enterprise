<div align="center">

```
███████╗ ██████╗  ██████╗    ██╗      █████╗ ██████╗
██╔════╝██╔═══██╗██╔════╝    ██║     ██╔══██╗██╔══██╗
███████╗██║   ██║██║         ██║     ███████║██████╔╝
╚════██║██║   ██║██║         ██║     ██╔══██║██╔══██╗
███████║╚██████╔╝╚██████╗    ███████╗██║  ██║██████╔╝
╚══════╝ ╚═════╝  ╚═════╝    ╚══════╝╚═╝  ╚═╝╚═════╝
```

# 🛡️ Enterprise Home SOC Lab

**A full-stack Security Operations Centre built on a single Kali Linux host using Docker.**  
Designed to mirror real-world enterprise SOC environments — from detection engineering to incident response.

[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-557C94?style=flat-square&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.7.3-00A1E0?style=flat-square)](https://wazuh.com/)
[![Elastic](https://img.shields.io/badge/Elastic-8.13.4-005571?style=flat-square&logo=elastic&logoColor=white)](https://www.elastic.co/)
[![TheHive](https://img.shields.io/badge/TheHive-5.x-FFCD00?style=flat-square)](https://thehive-project.org/)
[![Shuffle](https://img.shields.io/badge/Shuffle-SOAR-FF6B35?style=flat-square)](https://shuffler.io/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docs.docker.com/compose/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Stack Components](#-stack-components)
- [Detection Coverage](#-detection-coverage)
- [Project Structure](#-project-structure)
- [Quick Start](#-quick-start)
- [Custom Wazuh Rules](#-custom-wazuh-rules)
- [SOAR Automation](#-soar-automation)
- [Attack Simulations](#-attack-simulations)
- [Incident Reports](#-incident-reports)
- [Skills Demonstrated](#-skills-demonstrated)
- [Requirements](#-requirements)

---

## 🔍 Overview

This project implements a production-grade Security Operations Centre on a home lab using Docker. Every component maps directly to enterprise tools used in real-world SOC deployments.

The lab covers the **full detection and response lifecycle**:

```
ATTACK  →  DETECT  →  ALERT  →  ENRICH  →  RESPOND  →  DOCUMENT
  │            │          │          │           │            │
Atomic     Wazuh       Kibana    Shuffle     TheHive      IR Reports
Red Team   Rules       Dashboards  SOAR       Cases        (IR-001/002/003)
Scripts    + MITRE     + KQL      Workflows   Playbooks
```

**Built for:** Junior Security Analyst / Junior Penetration Tester roles in the Canadian market.  
**Certification context:** EC-Council CCT certified.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                  KALI LINUX HOST  (32GB RAM)                    │
│                                                                 │
│   DOCKER NETWORK: soc-net (172.20.0.0/24)                      │
│                                                                 │
│   WAZUH STACK              ELASTIC STACK                        │
│   ├── wazuh-indexer        ├── elasticsearch  :9200             │
│   ├── wazuh-manager  ──────► kibana           :5601             │
│   └── wazuh-dashboard:443                                       │
│                                                                 │
│   INCIDENT MGMT            SOAR                                 │
│   ├── cassandra            ├── shuffle-backend  :5001           │
│   └── thehive   :9000      ├── shuffle-frontend :3001           │
│                            └── shuffle-database                 │
│                                                                 │
│   MONITORED ENDPOINTS                                           │
│   ├── Linux agent  (Ubuntu/Debian/Kali)                         │
│   └── Windows agent (Win 10/11 + Sysmon)                        │
└─────────────────────────────────────────────────────────────────┘
```

> Full architecture diagram: [`architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md)  
> Network diagram: [`architecture/network-diagram.md`](architecture/network-diagram.md)

---

## 🧰 Stack Components

| Component | Version | Role | Enterprise Equivalent |
|-----------|---------|------|-----------------------|
| **Wazuh Manager** | 4.7.3 | SIEM — log collection, rule matching, alerting | Splunk / IBM QRadar / Microsoft Sentinel |
| **Wazuh Indexer** | 4.7.3 | Alert storage (OpenSearch-based) | Splunk Indexer |
| **Wazuh Dashboard** | 4.7.3 | Built-in ops view | Splunk Web |
| **Elasticsearch** | 8.13.4 | Long-term alert storage + KQL queries | Elastic SIEM |
| **Kibana** | 8.13.4 | Custom dashboards + saved searches | Elastic SIEM UI |
| **TheHive 5** | 5.x | Case management — triage, investigation, closure | ServiceNow SecOps / Jira |
| **Shuffle SOAR** | Latest | Workflow automation — enrich, respond, notify | Splunk SOAR / Palo Alto XSOAR |
| **Wazuh Agents** | 4.7.3 | Log collection on Linux + Windows endpoints | CrowdStrike Falcon / Defender for Endpoint |


## 🎯 Detection Coverage

12 custom Wazuh rules mapped to **MITRE ATT&CK**:

| Rule ID | Detection | MITRE Technique | Level |
|---------|-----------|-----------------|-------|
| 100001 | SSH Brute Force (10+ failures/60s) | T1110.001 | 10 |
| 100002 | Successful Login After Brute Force | T1078 | 15 |
| 100003 | LSASS Memory Access (Credential Dumping) | T1003.001 | 14 |
| 100004 | PsExec Lateral Movement | T1021.002 | 13 |
| 100005 | Suspicious PowerShell Execution | T1059.001 | 12 |
| 100006 | Ransomware Mass File Rename | T1486 | 15 |
| 100007 | Registry Run Key Persistence | T1547.001 | 11 |
| 100008 | Scheduled Task Created | T1053.005 | 10 |
| 100009 | Suspicious C2 Port Connection | T1071.001 | 13 |
| 100010 | Data Exfiltration Tool Detected | T1048 | 12 |
| 100011 | Shadow Copy Deletion *(post IR-003)* | T1490 | 14 |
| 100012 | Execution from AppData *(post IR-003)* | T1059.001 | 11 |

**False positive reduction documented:** from 90%+ baseline → under 10% after tuning.  
See [`alerts/tuning-reports/tuning-report-v1.md`](alerts/tuning-reports/tuning-report-v1.md)


## 📁 Project Structure

```
01-enterprise-home-soc/
├── alerts/
│   ├── custom-rules/
│   │   ├── soc-rules-annotated.xml      # All 12 rules with full inline annotations
│   │   └── tuning-guide.md              # FP reduction methodology + examples
│   └── tuning-reports/
│       └── tuning-report-v1.md          # 14-day tuning report (847 alerts analysed)
│
├── architecture/
│   ├── ARCHITECTURE.md                  # Full architecture + data flow diagrams
│   └── network-diagram.md               # Network layout + port reference
│
├── atomic-red-team/
│   ├── scenarios/
│   │   ├── simulate-brute-force.py      # T1110.001 — SSH brute force
│   │   ├── simulate-persistence.py      # T1547.001 — Registry/crontab persistence
│   │   ├── simulate-lateral-movement.py # T1021.002 — PsExec-style lateral movement
│   │   ├── simulate-data-exfil.py       # T1048 — Data exfiltration (local listener)
│   │   └── simulate-ransomware.py       # T1486 — Mass file rename/encryption
│   └── results/
│       └── results-template.md          # Standardised results documentation template
│
├── docs/
│   ├── setup-guide.md                   # 10-step deployment walkthrough
│   └── tool-versions.md                 # Version matrix + compatibility table
│
├── elastic/
│   ├── dashboards/
│   │   └── soc-overview-dashboard.ndjson  # Kibana dashboard (5 panels)
│   ├── index-templates/
│   │   └── wazuh-alerts-template.json   # 60+ field mappings for wazuh-alerts-*
│   └── saved-searches/
│       ├── soc-saved-searches.ndjson    # 5 KQL saved searches
│       └── README.md                    # Import instructions (UI + curl)
│
├── incident-reports/
│   ├── IR-001/IR-001-brute-force.md     # SSH brute force — root compromise
│   ├── IR-002/IR-002-lateral-movement.md # PsExec lateral movement campaign
│   └── IR-003/IR-003-ransomware.md      # STOP/Djvu ransomware via phishing macro
│
├── scripts/
│   ├── automation/
│   │   ├── alert-to-thehive.py          # Wazuh → TheHive polling daemon
│   │   ├── backup-configs.sh            # GPG-encrypted config backup + rotation
│   │   └── health-check.py              # 9-service health checker with watch mode
│   ├── setup/
│   │   ├── deploy.sh                    # Master deployment script
│   │   ├── docker-compose.yml           # 8-service Docker stack
│   │   ├── deploy-linux-agent.sh        # Multi-distro Linux agent installer
│   │   └── deploy-windows-agent.ps1     # Silent Windows MSI deployment
│   └── testing/
│       ├── test-rules.py                # Unit tests for all 10 custom rules
│       └── verify-detections.py         # Post-simulation Elasticsearch verifier
│
├── shuffle/
│   ├── integrations/
│   │   ├── thehive-api-config.md        # TheHive API setup guide
│   │   └── wazuh-webhook-config.md      # Wazuh → Shuffle webhook config
│   └── workflows/
│       └── brute-force-auto-response.json  # 7-step automated response workflow
│
├── thehive/
│   ├── case-reports/                    # IR exports (populated during live use)
│   ├── playbooks/
│   │   ├── brute-force-playbook.md      # 6-phase playbook with all commands
│   │   ├── malware-playbook.md          # Ransomware isolation + forensics
│   │   └── lateral-movement-playbook.md # PsExec removal + krbtgt reset
│   └── templates/
│       ├── brute-force-case-template.json
│       ├── malware-case-template.json
│       └── lateral-movement-case-template.json
│
├── vms/
│   ├── linux-agent/README.md            # Linux agent setup guide
│   └── windows-agent/README.md          # Windows agent + Sysmon setup guide
│
└── wazuh/
    ├── agents/
    │   ├── ossec-linux.conf             # Full Linux agent config (10+ log sources)
    │   └── ossec-windows.conf           # Windows agent (Security/Sysmon/PS/Defender)
    ├── decoders/
    │   └── custom-decoders.xml          # Sysmon, Windows Security, Linux auth, Docker
    └── rules/
        └── custom-soc-rules.xml         # 12 custom detection rules (IDs 100001–100012)
```

---

## 🚀 Quick Start

### Prerequisites
- Kali Linux (or Ubuntu 22.04+)
- 32GB RAM recommended (16GB minimum)
- 100GB+ free disk space
- Docker Engine 24.x

### Deploy the full stack

```bash
git clone https://github.com/YOUR_HANDLE/01-enterprise-home-soc.git
cd 01-enterprise-home-soc

chmod +x scripts/setup/deploy.sh
sudo bash scripts/setup/deploy.sh
```

### Verify everything is up

```bash
python3 scripts/automation/health-check.py
```

### Access the dashboards

| Service | URL | Credentials |
|---------|-----|-------------|
| Wazuh Dashboard | https://localhost:443 | admin / *(see .env)* |
| Kibana | http://localhost:5601 | elastic / *(see .env)* |
| TheHive | http://localhost:9000 | admin@thehive.local / secret |
| Shuffle | http://localhost:3001 | admin / *(see .env)* |

> ⚠️ Change all default credentials immediately after first login.

Full setup walkthrough: [`docs/setup-guide.md`](docs/setup-guide.md)


## 🔧 Custom Wazuh Rules

Rules are located in [`wazuh/rules/custom-soc-rules.xml`](wazuh/rules/custom-soc-rules.xml).  
Fully annotated versions with tuning guidance: [`alerts/custom-rules/soc-rules-annotated.xml`](alerts/custom-rules/soc-rules-annotated.xml)

Deploy to a running stack:

```bash
docker cp wazuh/rules/custom-soc-rules.xml \
  wazuh-manager:/var/ossec/etc/rules/custom-soc-rules.xml

docker cp wazuh/decoders/custom-decoders.xml \
  wazuh-manager:/var/ossec/etc/decoders/custom-decoders.xml

docker exec wazuh-manager /var/ossec/bin/wazuh-control restart
```

Test all rules fire correctly:

```bash
python3 scripts/testing/test-rules.py
# Expected: 10/10 PASS
```

## ⚡ SOAR Automation

The Shuffle workflow [`shuffle/workflows/brute-force-auto-response.json`](shuffle/workflows/brute-force-auto-response.json) automates the full brute force response pipeline:

```
Wazuh Webhook
     │
     ▼
Parse Alert Fields
     │
     ▼
AbuseIPDB Enrichment  ──►  Threat score + country + ISP
     │
     ▼
Create TheHive Case  ──►  Auto-populated with severity + MITRE tags
     │
     ▼
Tag Observables  ──►  IP, hostname, rule ID as IOCs
     │
     ▼
Block IP  ──►  UFW / iptables (RFC1918 guard prevents self-blocking)
     │
     ▼
Slack Notification  ──►  Block-kit formatted alert card
     │
     ▼
Email (Critical only)  ──►  Level 13+ alerts only
```

Integration setup guides:
- [`shuffle/integrations/wazuh-webhook-config.md`](shuffle/integrations/wazuh-webhook-config.md)
- [`shuffle/integrations/thehive-api-config.md`](shuffle/integrations/thehive-api-config.md)


## 💥 Attack Simulations

Five Python-based simulation scripts in [`atomic-red-team/scenarios/`](atomic-red-team/scenarios/) — all **safe for home lab use** (no real malware, no external C2 traffic).

| Script | Technique | What it does |
|--------|-----------|-------------|
| `simulate-brute-force.py` | T1110.001 | Rapid SSH login attempts via Paramiko |
| `simulate-persistence.py` | T1547.001 / T1053.005 | Crontab, .bashrc, SUID, registry keys (auto-reverts) |
| `simulate-lateral-movement.py` | T1021.002 | SSH pivot + PSEXESVC drop + syslog injection |
| `simulate-data-exfil.py` | T1048 / T1041 | curl/nc/wget to local TCP listener (no external traffic) |
| `simulate-ransomware.py` | T1486 | Mass file rename in sandbox dir (auto-cleanup) |

Run a simulation then verify detection:

```bash
python3 atomic-red-team/scenarios/simulate-brute-force.py \
  --target 172.20.0.100 --attempts 12

python3 scripts/testing/verify-detections.py \
  --simulation brute-force --since 10
```

## 📄 Incident Reports

Three full incident reports written in professional format:

| Report | Incident | Key Stats |
|--------|----------|-----------|
| [IR-001](incident-reports/IR-001/IR-001-brute-force.md) | SSH Brute Force → Root Compromise | 847 attempts, 58s detection-to-containment |
| [IR-002](incident-reports/IR-002/IR-002-lateral-movement.md) | PsExec Lateral Movement Campaign | 4-stage attack chain, <2min full detection |
| [IR-003](incident-reports/IR-003/IR-003-ransomware.md) | STOP/Djvu Ransomware via Phishing | 2,847 files encrypted, full backup restore |

All reports follow NIST SP 800-61 format with: timeline, evidence, root cause analysis, MITRE ATT&CK mapping, and lessons learned.


## 🎓 Skills Demonstrated

| Skill Area | Evidence |
|------------|---------|
| **SIEM Administration** | Custom Wazuh rules, decoders, agent configs, Elasticsearch index templates |
| **Threat Detection Engineering** | 12 custom rules mapped to MITRE ATT&CK, FP tuning from 90% → <10% |
| **Incident Response** | 3 full IR reports (IR-001/002/003) following NIST SP 800-61 |
| **SOAR Automation** | 7-step Shuffle workflow: enrich → case create → block → notify |
| **Case Management** | TheHive 5 templates, playbooks, custom fields |
| **Alert Tuning** | 14-day tuning report, documented FP/FN trade-offs, CDB lists |
| **Log Analysis** | Kibana dashboards, 5 KQL saved searches, MITRE heatmap |
| **Attack Simulation** | 5 Atomic Red Team scenarios in Python (T1110/T1486/T1021/T1048/T1547) |
| **Scripting & Automation** | Python daemons, Bash deployment, PowerShell agent installer |
| **Documentation** | Architecture diagrams, setup guides, IR reports, playbooks |


## 💻 Requirements

```
OS:      Kali Linux 2023+ (Ubuntu 22.04+ compatible)
RAM:     32GB recommended | 16GB minimum
Disk:    100GB+ free
Docker:  Engine 24.x + Compose v2
Python:  3.10+

Python packages:
  pip3 install paramiko requests urllib3 --break-system-packages
```


## ⚠️ Disclaimer

This lab is built for **educational and portfolio purposes only**. All attack simulations are self-contained and run against local infrastructure. No real malware is used. No external systems are targeted. Always obtain proper authorization before running security tools against any system.

<div align="center">

**Built by Reinhard Amoah | EC-Council Trained CCT**

*"Detection is only as good as the rules behind it."*

</div>
