# Wazuh → Shuffle Webhook Integration Guide
**Version:** 1.0  
**Author:** SOC Lab Project  
**Purpose:** Configure Wazuh manager to forward alerts to Shuffle SOAR
via HTTP POST webhooks so automated response workflows trigger on detection.

---

## 1. Architecture Overview
```
Wazuh Manager
  │
  ├── Alert fires (rule 100001 / 100002)
  │
  └── ossec-integrations → POST JSON → Shuffle Webhook URL
                                              │
                                        Shuffle Workflow
                                              │
                                    ┌─────────┴──────────┐
                                    │                    │
                               TheHive Case          Slack Alert
                               (auto-created)        (SOC channel)
```

---

## 2. Step 1 — Get the Shuffle Webhook URL

1. Open Shuffle: `http://<your-host>:3001`
2. Navigate to **Workflows → Brute Force Auto Response**
3. Click on the **Wazuh Alert Webhook** trigger node
4. Copy the full webhook URL shown — it looks like:
```
   http://shuffle-backend:3001/api/v1/hooks/webhook_<UUID>
```
5. Save this URL — you will paste it into Wazuh's integration config

---

## 3. Step 2 — Configure Wazuh Integration

Edit the Wazuh manager configuration to add the Shuffle integration.

### On the Wazuh Manager container:
```bash
docker exec -it wazuh-manager bash
nano /var/ossec/etc/ossec.conf
```

### Add this block inside `<ossec_config>`:
```xml
<!-- Shuffle SOAR Integration -->
<integration>
  <name>shuffle</name>
  <hook_url>http://shuffle-backend:3001/api/v1/hooks/webhook_YOUR_UUID_HERE</hook_url>
  <level>10</level>
  <!-- Only send alerts level 10+ to avoid flooding Shuffle -->
  <rule_id>100001,100002,100003,100004,100005,100006,100007,100008,100009,100010</rule_id>
  <alert_format>json</alert_format>
</integration>
```

> **Important:** Replace `webhook_YOUR_UUID_HERE` with the actual UUID from Step 1.

### Restart Wazuh manager to apply:
```bash
/var/ossec/bin/wazuh-control restart
```

### Verify integration is running:
```bash
tail -f /var/ossec/logs/integrations.log
# Should show: shuffle: sending alert...
```

---

## 4. Step 3 — Create a Custom Integration Script

Wazuh's built-in `shuffle` integration may not exist in all versions.
Use this Python script as a custom integration if needed:

Create the file:
```bash
nano /var/ossec/integrations/shuffle
chmod +x /var/ossec/integrations/shuffle
chown root:wazuh /var/ossec/integrations/shuffle
```

File contents:
```python
#!/usr/bin/env python3
# =============================================================================
# /var/ossec/integrations/shuffle
# Custom Wazuh → Shuffle webhook forwarder
# =============================================================================

import sys
import json
import os
import requests
from datetime import datetime

# Read args passed by Wazuh: alert_file hook_url api_key
alert_file_path = sys.argv[1]
hook_url        = sys.argv[3]

# Read alert JSON
with open(alert_file_path, 'r') as f:
    alert_data = json.load(f)

# Add metadata
alert_data['_shuffle_forwarded_at'] = datetime.utcnow().isoformat()
alert_data['_source'] = 'wazuh-integration'

# Forward to Shuffle
try:
    response = requests.post(
        hook_url,
        json=alert_data,
        headers={'Content-Type': 'application/json'},
        timeout=10,
        verify=False
    )
    if response.status_code == 200:
        print(f"[OK] Alert forwarded to Shuffle: rule {alert_data.get('rule',{}).get('id','?')}")
    else:
        print(f"[ERROR] Shuffle returned {response.status_code}: {response.text}", file=sys.stderr)
except Exception as e:
    print(f"[ERROR] Failed to forward to Shuffle: {e}", file=sys.stderr)
    sys.exit(1)
```

---

## 5. Step 4 — Configure Alert Level Filtering

To avoid sending every low-level alert to Shuffle (which would overwhelm
the workflow engine), filter by level in `ossec.conf`:
```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://shuffle-backend:3001/api/v1/hooks/webhook_YOUR_UUID</hook_url>
  <level>10</level>            <!-- Minimum level: High (10+) -->
  <alert_format>json</alert_format>
</integration>
```

Alternatively, filter by specific rule groups:
```xml
<integration>
  <name>shuffle</name>
  <hook_url>http://shuffle-backend:3001/api/v1/hooks/webhook_YOUR_UUID</hook_url>
  <group>brute_force,credential_dumping,ransomware,lateral_movement,attack</group>
  <alert_format>json</alert_format>
</integration>
```

---

## 6. Step 5 — Test the Integration

### Send a test alert manually:
```bash
# On the Wazuh manager container
docker exec -it wazuh-manager bash

# Generate a test auth failure (triggers rule 5760 → 100001)
/var/ossec/bin/ossec-logtest << 'EOF'
Jan 15 10:00:00 test-host sshd[9999]: Failed password for root from 1.2.3.4 port 22 ssh2
EOF
```

### Monitor forwarding in real-time:
```bash
tail -f /var/ossec/logs/integrations.log
```

### Verify in Shuffle:
1. Open Shuffle → **Workflows → Brute Force Auto Response**
2. Click **Execution History** (clock icon)
3. You should see a new execution with green status nodes
4. Click any execution to inspect the JSON payload at each step

---

## 7. Troubleshooting

| Problem | Solution |
|---------|----------|
| No entries in integrations.log | Check integration block syntax in ossec.conf |
| `Connection refused` to Shuffle | Verify shuffle-backend container is running: `docker ps` |
| `SSL certificate` errors | Add `<ssl_verify>no</ssl_verify>` to integration block |
| Workflow not triggering | Check webhook URL is correct; verify in Shuffle trigger settings |
| Alerts too noisy | Raise `<level>` threshold or restrict `<rule_id>` list |
| Python import errors | Install requests: `pip3 install requests` in wazuh-manager container |

---

## 8. Security Considerations

- The webhook URL contains a secret UUID — treat it as a credential
- Use HTTPS in production (configure Shuffle with TLS certificate)
- The integration script runs as the `wazuh` user — minimal privilege
- Rotate webhook URLs periodically via Shuffle trigger settings
- Never log the full alert payload to disk — it may contain credentials
