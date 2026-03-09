# Setup Guide — Enterprise Home SOC Lab
**Version:** 1.0  
**Platform:** Kali Linux (Ubuntu/Debian compatible)  
**Time to Deploy:** 30–45 minutes  

---

## Prerequisites

### Hardware
- RAM: 32GB minimum (16GB possible with reduced Elasticsearch heap)
- Disk: 100GB+ free space for Docker volumes
- CPU: 4+ cores recommended

### Software
```bash
# Verify Docker is installed (deploy.sh installs it if missing)
docker --version    # Need: 24.x+
docker compose version  # Need: 2.x+

# Verify kernel parameter support
sysctl vm.max_map_count   # Must be settable to 262144 (for Elasticsearch)
```

### Network
- Ports 443, 1514, 1515, 514, 55000, 9200, 5601, 9000, 5001, 3001
  must be free on the host
- Check: `ss -tulpn | grep -E '443|5601|9000|9200'`

---

## Step 1 — Clone and Configure
```bash
# Clone the repository
git clone https://github.com/yourhandle/01-enterprise-home-soc.git
cd 01-enterprise-home-soc

# Review and customise the environment file BEFORE deploying
# The deploy script will generate a .env but you can pre-create it:
cat scripts/setup/.env.example   # if provided
# Key variables to set:
#   ELASTIC_PASSWORD      — Elasticsearch admin password
#   WAZUH_MANAGER_PASSWORD — Wazuh admin password
#   THEHIVE_SECRET        — TheHive application secret
#   SHUFFLE_SECRET        — Shuffle admin password
```

---

## Step 2 — Deploy the Stack
```bash
# Make deploy script executable
chmod +x scripts/setup/deploy.sh

# Run the deployment (requires sudo for Docker install and sysctl)
sudo bash scripts/setup/deploy.sh

# Expected output:
#  [OK] Docker installed / already present
#  [OK] vm.max_map_count set to 262144
#  [OK] .env file generated
#  [OK] Pulling Docker images (this takes 5-10 minutes first run)
#  [OK] Starting 8 services...
#  [OK] wazuh-indexer   healthy
#  [OK] wazuh-manager   healthy
#  [OK] elasticsearch   healthy
#  [OK] kibana          healthy
#  [OK] thehive         healthy
#  [OK] shuffle-backend healthy
#
#  ACCESS URLS:
#  Wazuh Dashboard : https://localhost:443
#  Kibana          : http://localhost:5601
#  TheHive         : http://localhost:9000
#  Shuffle         : http://localhost:3001
```

---

## Step 3 — Verify Health
```bash
# Run the health check script
python3 scripts/automation/health-check.py

# All services should show UP
# Expected: 8/8 services UP

# Watch mode (live monitoring)
python3 scripts/automation/health-check.py --watch --interval 10
```

---

## Step 4 — Import Elasticsearch Assets
```bash
# Import the custom index template
curl -X PUT "http://localhost:9200/_index_template/wazuh-alerts-soc" \
  -u elastic:YOUR_ELASTIC_PASSWORD \
  -H 'Content-Type: application/json' \
  -d @elastic/index-templates/wazuh-alerts-template.json

# Expected: {"acknowledged":true}

# Verify template was applied
curl -s "http://localhost:9200/_index_template/wazuh-alerts-soc" \
  -u elastic:YOUR_ELASTIC_PASSWORD | python3 -m json.tool | head -20
```

---

## Step 5 — Import Kibana Dashboards
```bash
# Import the SOC overview dashboard
curl -X POST "http://localhost:5601/api/saved_objects/_import" \
  -u elastic:YOUR_ELASTIC_PASSWORD \
  -H "kbn-xsrf: true" \
  --form file=@elastic/dashboards/soc-overview-dashboard.ndjson

# Import saved searches
curl -X POST "http://localhost:5601/api/saved_objects/_import" \
  -u elastic:YOUR_ELASTIC_PASSWORD \
  -H "kbn-xsrf: true" \
  --form file=@elastic/saved-searches/soc-saved-searches.ndjson

# Verify: Open http://localhost:5601 → Stack Management → Saved Objects
# Should see: SOC Overview Dashboard + 5 saved searches
```

---

## Step 6 — Deploy Wazuh Custom Rules
```bash
# Copy custom rules into the Wazuh manager container
docker cp wazuh/rules/custom-soc-rules.xml \
  wazuh-manager:/var/ossec/etc/rules/custom-soc-rules.xml

# Copy custom decoders
docker cp wazuh/decoders/custom-decoders.xml \
  wazuh-manager:/var/ossec/etc/decoders/custom-decoders.xml

# Validate the rule syntax
docker exec wazuh-manager /var/ossec/bin/ossec-logtest -t

# Restart Wazuh manager to apply changes
docker exec wazuh-manager /var/ossec/bin/wazuh-control restart

# Verify rules loaded
docker exec wazuh-manager \
  grep -r "100001\|100002\|100003" /var/ossec/etc/rules/ \
  && echo "Custom rules loaded successfully"
```

---

## Step 7 — Deploy Wazuh Agents

### Linux Agent (Ubuntu/Debian/Kali)
```bash
# Copy agent config to target host, then run:
chmod +x scripts/setup/deploy-linux-agent.sh

sudo WAZUH_MANAGER=172.20.0.11 \
     WAZUH_AGENT_NAME=linux-endpoint-01 \
     bash scripts/setup/deploy-linux-agent.sh

# Verify agent enrolled:
docker exec wazuh-manager /var/ossec/bin/agent-control -l
# Should show: linux-endpoint-01  Active
```

### Windows Agent
```powershell
# Run in PowerShell as Administrator on the Windows target:
.\scripts\setup\deploy-windows-agent.ps1 `
  -ManagerIP 172.20.0.11 `
  -AgentName "windows-endpoint-01" `
  -AgentGroup "windows"

# Verify: Check Wazuh Dashboard → Agents
```

### Copy Custom Agent Configs
```bash
# Linux agent config
docker cp wazuh/agents/ossec-linux.conf \
  wazuh-manager:/var/ossec/etc/shared/default/agent.conf

# Windows agent config (deploy via Wazuh centralized config)
# Upload wazuh/agents/ossec-windows.conf via Wazuh Dashboard:
# Management → Configuration → Agent groups → default → Edit config
```

---

## Step 8 — Configure TheHive
```bash
# Open TheHive: http://localhost:9000
# Default login: admin@thehive.local / secret
# CHANGE PASSWORD IMMEDIATELY after first login

# Import case templates via TheHive UI:
# Admin → Case templates → Import
# Files to import:
#   thehive/templates/brute-force-case-template.json
#   thehive/templates/malware-case-template.json
#   thehive/templates/lateral-movement-case-template.json

# Generate API key for Shuffle integration:
# Admin → Users → admin → Generate API Key
# Copy key to Shuffle environment: THEHIVE_API_KEY=<key>
```

---

## Step 9 — Configure Shuffle SOAR
```bash
# Open Shuffle: http://localhost:3001
# Default: admin / (set via SHUFFLE_SECRET in .env)

# Import brute force workflow:
# Workflows → Import → Upload shuffle/workflows/brute-force-auto-response.json

# Set environment variables in Shuffle:
# Settings → Environments → Add variables:
#   THEHIVE_URL        = http://172.20.0.31:9000
#   THEHIVE_API_KEY    = <key from Step 8>
#   ABUSEIPDB_API_KEY  = <your AbuseIPDB API key>
#   SLACK_WEBHOOK_URL  = <your Slack webhook URL>

# Configure Wazuh webhook to trigger Shuffle:
# Copy webhook URL from Shuffle workflow trigger
# See: shuffle/integrations/wazuh-webhook-config.md for full guide
```

---

## Step 10 — Run Validation Tests
```bash
# Test all 10 custom rules fire correctly
python3 scripts/testing/test-rules.py --mode logtest

# Expected: 10/10 PASS

# Run a sample simulation to verify the full pipeline
python3 atomic-red-team/scenarios/simulate-brute-force.py \
  --target 172.20.0.100 --attempts 12

# Verify detection appeared in Elasticsearch
python3 scripts/testing/verify-detections.py \
  --simulation brute-force --since 5

# Check Kibana dashboard was updated
# Open: http://localhost:5601 → SOC Overview Dashboard
# Should see: new alerts in the alert volume panel

# Check TheHive for auto-created case
# Open: http://localhost:9000 → Cases
# Should see: [BF] SSH Brute Force case
```

---

## Common Issues & Fixes

### Elasticsearch won't start
```bash
# Most common cause: vm.max_map_count too low
sudo sysctl -w vm.max_map_count=262144
# Make permanent:
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# Check logs:
docker logs elasticsearch --tail 50
```

### Wazuh agents not connecting
```bash
# Verify manager is listening on 1514
ss -tulpn | grep 1514

# Check agent registration
docker exec wazuh-manager /var/ossec/bin/agent-control -l

# Re-enroll agent if needed
docker exec wazuh-manager \
  /var/ossec/bin/manage_agents -r <agent-id>
```

### TheHive won't start
```bash
# Most common cause: Cassandra not ready yet
docker logs cassandra --tail 30
# Wait for: "Starting listening for CQL clients"
# Then restart TheHive:
docker restart thehive
```

### Shuffle workflows not triggering
```bash
# Verify webhook URL is correct in ossec.conf
# Check Shuffle execution history: Workflows → Executions
# Check Wazuh integration logs:
docker exec wazuh-manager \
  tail -f /var/ossec/logs/integrations.log
```

---

## Quick Reference — Access URLs

| Service | URL | Default Credentials |
|---------|-----|-------------------|
| Wazuh Dashboard | https://localhost:443 | admin / (see .env) |
| Kibana | http://localhost:5601 | elastic / (see .env) |
| TheHive | http://localhost:9000 | admin@thehive.local / secret |
| Shuffle | http://localhost:3001 | admin / (see .env) |
| Elasticsearch API | http://localhost:9200 | elastic / (see .env) |
| Wazuh API | https://localhost:55000 | wazuh-wui / (see .env) |
