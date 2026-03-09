# Tool Versions — Enterprise Home SOC Lab

## Core Platform

| Component | Version | Docker Image | Notes |
|-----------|---------|-------------|-------|
| Wazuh Manager | 4.7.3 | wazuh/wazuh-manager:4.7.3 | Custom rules 100001-100012 |
| Wazuh Indexer | 4.7.3 | wazuh/wazuh-indexer:4.7.3 | OpenSearch-based |
| Wazuh Dashboard | 4.7.3 | wazuh/wazuh-dashboard:4.7.3 | |
| Elasticsearch | 8.13.4 | docker.elastic.co/elasticsearch/elasticsearch:8.13.4 | 8GB heap |
| Kibana | 8.13.4 | docker.elastic.co/kibana/kibana:8.13.4 | |
| TheHive | 5.x | strangebee/thehive:latest | |
| Cassandra | 4.0 | cassandra:4.0 | TheHive backend |
| Shuffle | Latest | ghcr.io/shuffle/shuffle:latest | |

## Agent Software

| Software | Version | Platform | Purpose |
|----------|---------|----------|---------|
| Wazuh Agent | 4.7.3 | Linux / Windows | Log collection |
| Sysmon | 15.x | Windows | Advanced event logging |
| Sysmon for Linux | 1.3.x | Linux | Optional |
| Filebeat | 8.13.4 | Wazuh Manager | Log forwarding to Elasticsearch |
| fail2ban | 1.0.x | Linux endpoints | SSH brute force rate limiting |

## Python Dependencies (automation scripts)

| Package | Version | Used By |
|---------|---------|---------|
| paramiko | 3.4.x | simulate-brute-force.py, simulate-lateral-movement.py |
| requests | 2.31.x | alert-to-thehive.py, health-check.py, verify-detections.py |
| urllib3 | 2.x | All scripts (SSL suppression) |
```bash
# Install all Python dependencies
pip3 install paramiko requests urllib3 --break-system-packages
```

## Sysmon Configuration

Wazuh rule coverage requires Sysmon to be configured to log:

| EID | Event | Required For |
|-----|-------|-------------|
| 1 | Process creation | Rules 100005, 100008, 100010 |
| 3 | Network connection | Rule 100009 |
| 10 | Process access | Rule 100003 |
| 11 | File creation | Rule 100006 (Windows) |
| 12 | Registry create/delete | Rule 100007 |
| 13 | Registry set value | Rule 100007 |
```xml
<!-- Minimal Sysmon config for SOC lab (SwiftOnSecurity config recommended) -->
<!-- Download: https://github.com/SwiftOnSecurity/sysmon-config -->
<!-- Install: Sysmon64.exe -accepteula -i sysmonconfig.xml -->
```

## Kernel Requirements (Linux Host)
```bash
# Required for Elasticsearch
vm.max_map_count=262144

# Verify and set:
sysctl vm.max_map_count
sudo sysctl -w vm.max_map_count=262144

# Persist across reboots:
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

## Version Compatibility Matrix

| Wazuh | Elasticsearch | Kibana | TheHive | Status |
|-------|--------------|--------|---------|--------|
| 4.7.3 | 8.13.4 | 8.13.4 | 5.x | ✅ Tested |
| 4.7.x | 8.13.x | 8.13.x | 5.x | ✅ Compatible |
| 4.6.x | 8.11.x | 8.11.x | 5.x | ⚠️ Not tested |

## Checking Current Versions
```bash
# Check all running container image versions
docker ps --format "table {{.Names}}\t{{.Image}}" | sort

# Check Wazuh version
docker exec wazuh-manager /var/ossec/bin/wazuh-control info

# Check Elasticsearch version
curl -s http://localhost:9200 -u elastic:$ELASTIC_PASSWORD \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['version']['number'])"

# Check Kibana version
curl -s http://localhost:5601/api/status \
  -u elastic:$ELASTIC_PASSWORD \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['version']['number'])"
```
