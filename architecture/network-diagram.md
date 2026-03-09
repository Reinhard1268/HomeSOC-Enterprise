# Network Diagram — Enterprise Home SOC Lab

## Physical and Logical Network Layout
```
INTERNET
    │
    │ (simulated threats / external IPs in scenarios)
    │
    ▼
┌───────────────────────────────────────────┐
│          KALI LINUX HOST MACHINE          │
│          192.168.1.x (home network)       │
│          RAM: 32GB | Docker 24.x          │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │     DOCKER BRIDGE: soc-net          │  │
│  │     172.20.0.0/24                   │  │
│  │                                     │  │
│  │  WAZUH                              │  │
│  │  ├── wazuh-indexer   172.20.0.10    │  │
│  │  ├── wazuh-manager   172.20.0.11    │  │
│  │  └── wazuh-dashboard 172.20.0.12    │  │
│  │                                     │  │
│  │  ELASTIC STACK                      │  │
│  │  ├── elasticsearch   172.20.0.20    │  │
│  │  └── kibana          172.20.0.21    │  │
│  │                                     │  │
│  │  INCIDENT MANAGEMENT                │  │
│  │  ├── cassandra        172.20.0.30   │  │
│  │  └── thehive          172.20.0.31   │  │
│  │                                     │  │
│  │  SOAR                               │  │
│  │  ├── shuffle-backend  172.20.0.40   │  │
│  │  ├── shuffle-frontend 172.20.0.41   │  │
│  │  └── shuffle-database 172.20.0.42   │  │
│  └─────────────────────────────────────┘  │
│                                           │
│  MONITORED ENDPOINTS (VMs or containers)  │
│  ├── linux-endpoint-01   172.20.0.100     │
│  ├── windows-endpoint-01 172.20.0.110     │
│  └── (additional agents  172.20.0.50+)   │
└───────────────────────────────────────────┘

PORT EXPOSURE TO HOST:
  443   → wazuh-dashboard  (HTTPS)
  1514  → wazuh-manager    (agent events)
  1515  → wazuh-manager    (agent enrollment)
  5601  → kibana           (HTTP)
  9000  → thehive          (HTTP)
  9200  → elasticsearch    (HTTP)
  55000 → wazuh-manager    (REST API HTTPS)
  5001  → shuffle-backend  (HTTP)
  3001  → shuffle-frontend (HTTP)
```

## Data Flow Summary
```
ENDPOINT LOG/EVENT
       │ Port 1514 (encrypted)
       ▼
WAZUH MANAGER ──► Decode ──► Rule Match ──► Alert
       │                                      │
       │                          ┌───────────┼────────────┐
       ▼                          ▼           ▼            ▼
WAZUH INDEXER             ELASTICSEARCH  SHUFFLE     WAZUH DASHBOARD
(built-in view)           (wazuh-alerts) (SOAR)      (ops view)
                               │              │
                               ▼              ▼
                            KIBANA        THEHIVE
                          (dashboards)  (cases/IR)
```
