# Enterprise Home SOC Lab — Architecture Documentation
**Version:** 1.0  
**Last Updated:** 2025-12-22  
**Author:** SOC Lab Project  

---

## 1. Architecture Overview

This SOC lab implements a full-stack Security Operations Centre on a single
physical host using Docker. The architecture mirrors an enterprise SOC at
reduced scale — every component maps directly to a production equivalent
used in real-world SOC deployments.
```
┌─────────────────────────────────────────────────────────────────────────┐
│                     PHYSICAL HOST — KALI LINUX                          │
│                     RAM: 32GB  |  Docker Engine 24.x                    │
│                                                                         │
│  ┌─────────────── DOCKER NETWORK: soc-net (172.20.0.0/24) ──────────┐  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐ │  │
│  │  │                   WAZUH STACK                               │ │  │
│  │  │                                                             │ │  │
│  │  │  ┌──────────────────┐   ┌──────────────────────────────┐   │ │  │
│  │  │  │  Wazuh Indexer   │   │      Wazuh Manager           │   │ │  │
│  │  │  │  172.20.0.10     │◄──│      172.20.0.11             │   │ │  │
│  │  │  │  Port: 9201      │   │      Ports: 1514 1515        │   │ │  │
│  │  │  │  (OpenSearch)    │   │             514  55000       │   │ │  │
│  │  │  └──────────────────┘   └──────────────┬───────────────┘   │ │  │
│  │  │                                        │                    │ │  │
│  │  │  ┌──────────────────────────────────── ▼ ───────────────┐  │ │  │
│  │  │  │               Wazuh Dashboard                        │  │ │  │
│  │  │  │               172.20.0.12  |  Port: 443              │  │ │  │
│  │  │  └──────────────────────────────────────────────────────┘  │ │  │
│  │  └─────────────────────────────────────────────────────────────┘ │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐ │  │
│  │  │                  ELASTIC STACK                              │ │  │
│  │  │                                                             │ │  │
│  │  │  ┌─────────────────────┐     ┌─────────────────────────┐   │ │  │
│  │  │  │   Elasticsearch     │     │         Kibana           │   │ │  │
│  │  │  │   172.20.0.20       │◄────│         172.20.0.21      │   │ │  │
│  │  │  │   Port: 9200        │     │         Port: 5601       │   │ │  │
│  │  │  └─────────────────────┘     └─────────────────────────┘   │ │  │
│  │  └─────────────────────────────────────────────────────────────┘ │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐ │  │
│  │  │              INCIDENT MANAGEMENT                            │ │  │
│  │  │                                                             │ │  │
│  │  │  ┌──────────────────────┐   ┌──────────────────────────┐   │ │  │
│  │  │  │      Cassandra       │   │        TheHive 5         │   │ │  │
│  │  │  │      172.20.0.30     │◄──│        172.20.0.31       │   │ │  │
│  │  │  │      Port: 9042      │   │        Port: 9000        │   │ │  │
│  │  │  └──────────────────────┘   └──────────────────────────┘   │ │  │
│  │  └─────────────────────────────────────────────────────────────┘ │  │
│  │                                                                   │  │
│  │  ┌─────────────────────────────────────────────────────────────┐ │  │
│  │  │                   SOAR PLATFORM                             │ │  │
│  │  │                                                             │ │  │
│  │  │  ┌───────────────────┐  ┌───────────────┐  ┌────────────┐  │ │  │
│  │  │  │ Shuffle Backend   │  │Shuffle Frontend│  │  Shuffle   │  │ │  │
│  │  │  │ 172.20.0.40       │  │172.20.0.41     │  │  Database  │  │ │  │
│  │  │  │ Port: 5001        │  │Port: 3001      │  │172.20.0.42 │  │ │  │
│  │  │  └───────────────────┘  └───────────────┘  └────────────┘  │ │  │
│  │  └─────────────────────────────────────────────────────────────┘ │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │                   WAZUH MONITORED ENDPOINTS                        │ │
│  │                                                                    │ │
│  │  ┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐ │ │
│  │  │  Linux Endpoint │   │Windows Endpoint │   │   Kali Linux    │ │ │
│  │  │  (Ubuntu/Debian)│   │  (Windows 10/11)│   │  (Attack Host)  │ │ │
│  │  │  Wazuh Agent    │   │  Wazuh Agent    │   │  Wazuh Agent    │ │ │
│  │  │  + Sysmon(opt.) │   │  + Sysmon EID   │   │  (optional)     │ │ │
│  │  └────────┬────────┘   └────────┬────────┘   └────────┬────────┘ │ │
│  └───────────┼─────────────────────┼─────────────────────┼──────────┘ │
│              │    Agent → Manager  │  Port 1514 (UDP/TCP) │            │
│              └────────────────────►│◄────────────────────┘            │
│                           Wazuh Manager 172.20.0.11                    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Flow Diagram
```
  ATTACK/LOG EVENT
       │
       ▼
  ┌─────────────┐     ┌──────────────────────────────────────────────────┐
  │  Endpoint   │     │               WAZUH MANAGER                      │
  │  Wazuh      │────►│                                                  │
  │  Agent      │     │  1. Log collection (ossec-remoted)               │
  │             │     │  2. Decode (custom-decoders.xml)                 │
  │  Collects:  │     │  3. Rule match (custom-soc-rules.xml)            │
  │  - syslog   │     │  4. Alert generation (level >= threshold)        │
  │  - auth.log │     │  5. Dual output:                                 │
  │  - Sysmon   │     │     a) Wazuh Indexer (internal dashboard)        │
  │  - FIM      │     │     b) Filebeat → Elasticsearch (external SIEM)  │
  │  - Audit    │     │     c) Webhook → Shuffle (SOAR trigger)          │
  └─────────────┘     └──────────────────┬───────────────────────────────┘
                                         │
              ┌──────────────────────────┼────────────────────┐
              │                          │                     │
              ▼                          ▼                     ▼
  ┌───────────────────┐     ┌────────────────────┐  ┌─────────────────────┐
  │  Wazuh Indexer    │     │   Elasticsearch    │  │   Shuffle SOAR      │
  │  (OpenSearch)     │     │   (wazuh-alerts-*) │  │                     │
  │  172.20.0.10      │     │   172.20.0.20      │  │   Workflow Steps:   │
  │                   │     │                    │  │   1. Parse alert    │
  │  Powers:          │     │   Powers:          │  │   2. AbuseIPDB enr. │
  │  Wazuh Dashboard  │     │   Kibana           │  │   3. Create case    │
  │  (built-in view)  │     │   Custom Dashboards│  │   4. Add observ.    │
  └───────────────────┘     │   KQL Searches     │  │   5. Auto-block IP  │
                            │   Saved Searches   │  │   6. Slack notify   │
                            └────────────────────┘  │   7. Email (crit.)  │
                                                     └──────────┬──────────┘
                                                                │
                                                                ▼
                                                     ┌──────────────────────┐
                                                     │      TheHive 5       │
                                                     │                      │
                                                     │  Auto-created:       │
                                                     │  - Case              │
                                                     │  - Observables       │
                                                     │  - MITRE tags        │
                                                     │  - Severity mapping  │
                                                     │                      │
                                                     │  Analyst works:      │
                                                     │  - Tasks/playbooks   │
                                                     │  - Evidence          │
                                                     │  - Timeline          │
                                                     │  - Case closure      │
                                                     └──────────────────────┘
```

---

## 3. Network Architecture

### 3.1 Docker Network
```
Network Name : soc-net
Driver       : bridge
Subnet       : 172.20.0.0/24
Gateway      : 172.20.0.1

IP Allocations:
  172.20.0.1    Docker bridge gateway (host)
  172.20.0.10   wazuh-indexer
  172.20.0.11   wazuh-manager
  172.20.0.12   wazuh-dashboard
  172.20.0.20   elasticsearch
  172.20.0.21   kibana
  172.20.0.30   cassandra
  172.20.0.31   thehive
  172.20.0.40   shuffle-backend
  172.20.0.41   shuffle-frontend
  172.20.0.42   shuffle-database
  172.20.0.50-  Reserved for monitored endpoints (VMs/containers)
```

### 3.2 Port Exposure (Host → Container)

| Port | Protocol | Service | Purpose |
|------|----------|---------|---------|
| 443 | HTTPS | Wazuh Dashboard | Web UI for Wazuh |
| 1514 | UDP/TCP | Wazuh Manager | Agent event ingestion |
| 1515 | TCP | Wazuh Manager | Agent auto-enrollment |
| 514 | UDP | Wazuh Manager | Syslog collection |
| 55000 | HTTPS | Wazuh Manager API | REST API |
| 9200 | HTTP | Elasticsearch | REST API / Kibana backend |
| 5601 | HTTP | Kibana | Web UI for Elastic Stack |
| 9000 | HTTP | TheHive | Web UI + REST API |
| 5001 | HTTP | Shuffle Backend | SOAR REST API |
| 3001 | HTTP | Shuffle Frontend | SOAR Web UI |

### 3.3 Inter-Service Communication
```
wazuh-manager   → wazuh-indexer   :9200  (alert storage)
wazuh-manager   → elasticsearch   :9200  (Filebeat output)
wazuh-dashboard → wazuh-indexer   :9200  (dashboard data)
kibana          → elasticsearch   :9200  (dashboard data)
thehive         → cassandra       :9042  (case database)
shuffle-backend → thehive         :9000  (case creation API)
shuffle-backend → elasticsearch   :9200  (alert enrichment)
shuffle-backend → wazuh-manager   :55000 (Wazuh API queries)
alert-to-thehive→ wazuh-manager   :55000 (alert polling)
alert-to-thehive→ thehive         :9000  (case creation)
```

---

## 4. Component Reference

### 4.1 Wazuh Manager
**Role:** Core SIEM engine — log collection, decoding, rule matching, alerting  
**Version:** 4.7.3  
**IP:** 172.20.0.11  
**Key configs:**
- `/var/ossec/etc/ossec.conf` — master config
- `/var/ossec/etc/rules/` — active rules (includes custom-soc-rules.xml)
- `/var/ossec/etc/decoders/` — active decoders (includes custom-decoders.xml)
- Custom rule IDs: 100001–100010 (SOC Lab) + 100011–100012 (post-IR-003)

**Agent Communication:**
- Port 1514: Encrypted agent event stream (AES-256)
- Port 1515: Agent enrollment (certificate-based)
- Port 55000: REST API (JWT authentication)

### 4.2 Elasticsearch
**Role:** Long-term alert storage, KQL querying, Kibana data source  
**Version:** 8.13.4  
**IP:** 172.20.0.20  
**Index pattern:** `wazuh-alerts-*`  
**Retention:** 90 days (ILM policy)  
**Key features used:**
- Custom index template (60+ field mappings)
- ILM hot-warm-delete lifecycle
- Aggregations for dashboard visualisations

### 4.3 Kibana
**Role:** SIEM visualisation — dashboards, KQL searches, investigations  
**Version:** 8.13.4  
**IP:** 172.20.0.21  
**Deployed assets:**
- SOC Overview Dashboard (5 panels)
- 5 saved searches (brute force, PS events, FIM, network, critical alerts)
- Index pattern: `wazuh-alerts-*`

### 4.4 TheHive 5
**Role:** Case management — triage, investigation, playbooks, closure  
**Version:** 5.x  
**IP:** 172.20.0.31  
**Deployed assets:**
- 3 case templates (brute force, malware, lateral movement)
- 3 response playbooks
- Custom fields for Wazuh rule context

### 4.5 Shuffle SOAR
**Role:** Workflow automation — alert enrichment, case creation, notification  
**Version:** Latest  
**IP:** 172.20.0.40-42  
**Deployed workflows:**
- Brute force auto-response (7 steps)
- Integrations: Wazuh webhook, TheHive API, AbuseIPDB, Slack, email

### 4.6 Wazuh Agents
**Role:** Log collection on monitored endpoints  
**Supported:** Linux (Debian/Ubuntu/Kali/RHEL), Windows 10/11  
**Key monitoring:**
- Linux: auth.log, syslog, FIM on /etc /usr /sbin, docker logs, audit
- Windows: Security (4624/4625/4688 etc.), Sysmon, PowerShell, Defender, FIM

---

## 5. Security Architecture

### 5.1 Authentication & Access Control

| Service | Auth Method | Default Credentials (CHANGE IMMEDIATELY) |
|---------|------------|------------------------------------------|
| Wazuh Dashboard | Local users | admin / SecretPassword (see .env) |
| Elasticsearch | Basic auth | elastic / (see .env ELASTIC_PASSWORD) |
| Kibana | Via Elasticsearch | elastic / (see .env) |
| TheHive | Local users | admin@thehive.local / secret |
| Shuffle | Local users | admin / (see .env SHUFFLE_SECRET) |
| Wazuh API | JWT / Basic | wazuh-wui / (see .env) |

### 5.2 Encryption

| Channel | Encryption | Notes |
|---------|-----------|-------|
| Agent → Manager | AES-256 | Built into Wazuh agent protocol |
| Wazuh Dashboard | TLS (self-signed) | Certificate in wazuh-indexer volume |
| Wazuh API | TLS (self-signed) | HTTPS on port 55000 |
| Elasticsearch | HTTP (lab only) | Enable TLS for production |
| All secrets | Environment vars | Never hardcoded — see .env |

### 5.3 Network Isolation

All SOC platform services communicate only within `soc-net` (172.20.0.0/24).
Monitored endpoints connect to Wazuh Manager port 1514/1515 only — they have
no direct access to Elasticsearch, TheHive, or Shuffle.

---

## 6. Resource Requirements

### 6.1 Minimum Specifications

| Resource | Minimum | Recommended | This Lab |
|----------|---------|-------------|----------|
| RAM | 16GB | 32GB | 32GB ✅ |
| CPU | 4 cores | 8 cores | (host-dependent) |
| Disk | 100GB | 250GB | (host-dependent) |
| OS | Ubuntu 22.04 | Kali Linux 2024 | Kali ✅ |
| Docker | 24.x | 24.x | 24.x ✅ |

### 6.2 Per-Service RAM Allocation

| Service | Minimum | Recommended |
|---------|---------|-------------|
| wazuh-indexer | 2GB | 4GB |
| wazuh-manager | 1GB | 2GB |
| wazuh-dashboard | 512MB | 1GB |
| elasticsearch | 4GB | 8GB |
| kibana | 1GB | 2GB |
| cassandra | 2GB | 4GB |
| thehive | 1GB | 2GB |
| shuffle (all) | 512MB | 1GB |
| **Total** | **~12GB** | **~24GB** |

---

## 7. Production Equivalents

This lab maps to these enterprise tools in the real world:

| Lab Component | Enterprise Equivalent |
|--------------|----------------------|
| Wazuh SIEM | Splunk Enterprise / IBM QRadar / Microsoft Sentinel |
| Elasticsearch + Kibana | Elastic SIEM / Splunk / Exabeam |
| TheHive | ServiceNow Security Operations / Jira Service Management |
| Shuffle SOAR | Splunk SOAR (Phantom) / Palo Alto XSOAR / Swimlane |
| Wazuh Agents | CrowdStrike Falcon / Carbon Black / Microsoft Defender for Endpoint |
| Custom Wazuh Rules | Splunk correlation searches / SIEM use cases |
| Atomic Red Team scripts | Cobalt Strike / Metasploit (red team engagements) |

---

## 8. Portfolio Relevance

This architecture demonstrates the following job-relevant skills:

| Skill | Demonstrated By |
|-------|----------------|
| SIEM administration | Custom Wazuh rules, decoders, agent configs, index templates |
| Threat detection | 12 custom detection rules mapped to MITRE ATT&CK |
| Incident response | 3 full IR reports (IR-001 through IR-003) |
| SOAR automation | Shuffle workflow: 7-step enrichment and response |
| Case management | TheHive templates, playbooks, custom fields |
| Alert tuning | FP reduction from 90%+ to < 10% documented |
| Log analysis | Kibana dashboards, KQL saved searches |
| Attack simulation | 5 Atomic Red Team scenarios (Python) |
| Scripting | Python automation, Bash deployment, PowerShell agents |
| Documentation | Architecture docs, setup guides, IR reports, playbooks |

