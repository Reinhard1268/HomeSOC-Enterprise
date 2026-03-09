# TheHive 5 → Shuffle API Integration Guide
**Version:** 1.0  
**Author:** SOC Lab Project  
**Purpose:** Connect Shuffle SOAR to TheHive 5 for automated case creation,
observable management, task logging, and alert escalation.

---

## 1. Architecture Overview
```
Shuffle Workflow
      │
      ├── action_create_thehive_case  ──→  POST /api/v1/case
      ├── action_create_observable    ──→  POST /api/v1/case/{id}/observable
      ├── action_update_case_block    ──→  POST /api/v1/case/{id}/log
      └── (future) action_close_case  ──→  PATCH /api/v1/case/{id}
                │
          TheHive 5 API (port 9000)
                │
          Cassandra + Elasticsearch backend
```

---

## 2. Step 1 — Generate a TheHive API Key

1. Open TheHive: `http://<your-host>:9000`
2. Login as `admin@thehive.local` (default password: `secret`)
   > **Change the default password immediately after first login**
3. Navigate to: **Settings → API Keys** (top-right user menu)
4. Click **Create API Key**
5. Set description: `shuffle-soar-integration`
6. Copy the generated key — it will only be shown once
7. Store it in Shuffle as environment variable `ENV_THEHIVE_API_KEY`

---

## 3. Step 2 — Create a Dedicated Integration Account

For production use, create a dedicated analyst account for Shuffle:
```bash
# Via TheHive API
curl -X POST "http://localhost:9000/api/v1/user" \
  -H "Authorization: Bearer <admin_api_key>" \
  -H "Content-Type: application/json" \
  -d '{
    "login": "shuffle-soar@thehive.local",
    "name": "Shuffle SOAR Integration",
    "password": "'"${SHUFFLE_THEHIVE_PASSWORD}"'",
    "profile": "analyst",
    "organisation": "admin"
  }'
```

Then generate an API key for this account and use it instead of the admin key.

---

## 4. Step 3 — Configure Environment Variables in Shuffle

In Shuffle, navigate to **Settings → Environment Variables** and add:

| Variable Name | Value | Secret |
|--------------|-------|--------|
| `ENV_THEHIVE_URL` | `http://172.20.0.31:9000` | No |
| `ENV_THEHIVE_API_KEY` | `<your_api_key>` | **Yes** |

To add a secret variable in Shuffle:
1. Navigate to **Settings → Environments**
2. Click **Edit** on the `default` environment
3. Click **Add variable**
4. Check the **Secret** checkbox for sensitive values

---

## 5. Step 4 — Verify Connectivity

Test that Shuffle can reach TheHive before running the workflow:
```bash
# From the Shuffle backend container
docker exec -it shuffle-backend sh

# Test TheHive API connectivity
curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${ENV_THEHIVE_API_KEY}" \
  http://thehive:9000/api/v1/status

# Expected output: 200
```
```bash
# Test case creation manually
curl -X POST "http://localhost:9000/api/v1/case" \
  -H "Authorization: Bearer ${ENV_THEHIVE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "TEST — Shuffle Integration Check",
    "description": "Automated test case from Shuffle connectivity check. Safe to delete.",
    "severity": 1,
    "tlp": 2,
    "pap": 2,
    "tags": ["test", "shuffle-integration"],
    "status": "New"
  }'

# Expected: {"_id":"...", "number":1, "title":"TEST..."}
```

---

## 6. Step 5 — Import Case Templates into TheHive

Import the JSON case templates from `thehive/templates/` via the API:
```bash
# Brute force template
curl -X POST "http://localhost:9000/api/v1/caseTemplate" \
  -H "Authorization: Bearer ${ENV_THEHIVE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @thehive/templates/brute-force-case-template.json

# Malware template
curl -X POST "http://localhost:9000/api/v1/caseTemplate" \
  -H "Authorization: Bearer ${ENV_THEHIVE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @thehive/templates/malware-case-template.json

# Lateral movement template
curl -X POST "http://localhost:9000/api/v1/caseTemplate" \
  -H "Authorization: Bearer ${ENV_THEHIVE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d @thehive/templates/lateral-movement-case-template.json
```

---

## 7. TheHive API Reference (Key Endpoints Used by Shuffle)

### Create Case
```
POST /api/v1/case
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "title":       "string (required)",
  "description": "string (markdown supported)",
  "severity":    1-4 (Low/Med/High/Critical),
  "tlp":         0-4 (White/Green/Amber/Red/Black),
  "pap":         0-3 (White/Green/Amber/Red),
  "tags":        ["string"],
  "status":      "New|InProgress|Closed",
  "assignee":    "user@domain",
  "customFields": { "fieldName": "value" }
}

Response: { "_id": "~1234", "number": 1, "title": "...", ... }
```

### Add Observable to Case
```
POST /api/v1/case/{case_id}/observable
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "data":     "1.2.3.4",
  "dataType": "ip|domain|url|hash|filename|email",
  "message":  "description of this observable",
  "tags":     ["ioc", "attacker-ip"],
  "tlp":      2,
  "ioc":      true,
  "sighted":  true
}
```

### Add Task Log Entry
```
POST /api/v1/case/{case_id}/log
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "message":  "markdown formatted log entry",
  "startDate": 1705315800000
}
```

### Update Case
```
PATCH /api/v1/case/{case_id}
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "status":   "InProgress",
  "severity": 3,
  "assignee": "analyst@soc.local"
}
```

### Close Case
```
PATCH /api/v1/case/{case_id}
Authorization: Bearer <api_key>
Content-Type: application/json

{
  "status":         "Closed",
  "resolutionStatus": "TruePositive|FalsePositive|Indeterminate",
  "summary":        "Brief resolution summary"
}
```

---

## 8. Configuring TheHive Notifications → Shuffle (Bidirectional)

TheHive can also push events back to Shuffle (e.g. when an analyst updates a case):

1. In TheHive: **Organisation Settings → Notifications**
2. Click **Add Notification**
3. Configure:
   - **Trigger:** `CaseCreated`, `CaseUpdated`, `AlertCreated`
   - **Notifier:** `Http`
   - **URL:** `http://shuffle-backend:3001/api/v1/hooks/webhook_<ANOTHER_UUID>`
   - **Method:** POST
   - **Headers:** `Content-Type: application/json`
4. Save and test with a manual case update

This enables bidirectional SOAR: Wazuh → Shuffle → TheHive → Shuffle → Analyst notification.

---

## 9. Troubleshooting

| Problem | Solution |
|---------|----------|
| `401 Unauthorized` | API key is wrong or expired — regenerate in TheHive |
| `403 Forbidden` | Account lacks `analyst` or `org-admin` role |
| `Connection refused` | TheHive container not running: `docker logs thehive` |
| `500 Internal Server Error` | Check Cassandra is healthy: `docker logs cassandra` |
| Case created but no tasks | Case template import failed — re-import templates |
| Observable not appearing | Check `dataType` is valid (ip/domain/url/hash/filename/email) |
| Custom fields empty | Field names must exactly match template definition |

---

## 10. Security Hardening
```bash
# Change default admin password immediately
curl -X POST "http://localhost:9000/api/v1/user/admin@thehive.local/password/change" \
  -H "Authorization: Bearer ${ENV_THEHIVE_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"currentPassword":"secret","password":"'"${NEW_THEHIVE_PASSWORD}"'"}'

# Rotate API key every 90 days
# Add to crontab:
# 0 0 1 */3 * /opt/soc-lab/scripts/automation/rotate-thehive-apikey.sh
```
