#!/usr/bin/env python3
# =============================================================================
# alert-to-thehive.py — Wazuh Alert Poller → TheHive Case Creator
# Author: SOC Lab Project
# Description: Polls the Wazuh Manager REST API for new alerts with severity
#              >= HIGH (level 10), deduplicates against previously processed
#              alert IDs, and auto-creates TheHive 5 cases with observables,
#              MITRE tags, and correct severity mapping.
# Usage: python3 alert-to-thehive.py [--once] [--dry-run] [--level 10]
# Schedule: Run as a systemd service or cron every 60 seconds
# Environment variables (required — never hardcode):
#   WAZUH_API_URL        e.g. https://localhost:55000
#   WAZUH_API_USER       e.g. wazuh-wui
#   WAZUH_API_PASSWORD   Wazuh API password
#   THEHIVE_URL          e.g. http://localhost:9000
#   THEHIVE_API_KEY      TheHive API key
# =============================================================================

import os
import sys
import json
import time
import logging
import argparse
import hashlib
import requests
import urllib3
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Suppress SSL warnings for self-signed Wazuh certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/var/log/soc-lab/alert-to-thehive.log",
                            mode="a", encoding="utf-8")
    ]
)
log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
WAZUH_API_URL      = os.environ.get("WAZUH_API_URL",      "https://localhost:55000")
WAZUH_API_USER     = os.environ.get("WAZUH_API_USER",     "wazuh-wui")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "")
THEHIVE_URL        = os.environ.get("THEHIVE_URL",        "http://localhost:9000")
THEHIVE_API_KEY    = os.environ.get("THEHIVE_API_KEY",    "")

# Poll interval in seconds
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL", "60"))

# Minimum Wazuh rule level to create a case for (10 = High)
DEFAULT_MIN_LEVEL = 10

# State file to track already-processed alert IDs (survives restarts)
STATE_FILE = Path("/var/lib/soc-lab/processed-alerts.json")

# How many alerts to fetch per Wazuh API call
WAZUH_PAGE_SIZE = 100

# Wazuh rule level → TheHive severity mapping
# TheHive: 1=Low, 2=Medium, 3=High, 4=Critical
LEVEL_TO_SEVERITY = {
    range(10, 12): 2,   # Wazuh 10–11 → TheHive Medium
    range(12, 14): 3,   # Wazuh 12–13 → TheHive High
    range(14, 16): 4,   # Wazuh 14–15 → TheHive Critical
}

# Wazuh rule groups → TheHive tags mapping
GROUP_TAG_MAP = {
    "brute_force":        ["brute-force", "authentication"],
    "authentication_failures": ["auth-failure"],
    "authentication_success":  ["auth-success"],
    "credential_dumping": ["credential-dumping", "T1003"],
    "lateral_movement":   ["lateral-movement"],
    "ransomware":         ["ransomware", "critical"],
    "persistence":        ["persistence"],
    "powershell":         ["powershell", "T1059"],
    "exfiltration":       ["exfiltration"],
    "c2":                 ["command-and-control"],
    "attack":             ["attack"],
    "syscheck":           ["fim", "file-integrity"],
}


# ── Wazuh API client ──────────────────────────────────────────────────────────
class WazuhAPIClient:
    """Thin wrapper around the Wazuh Manager REST API."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.token    = None
        self.session  = requests.Session()
        self.session.verify = False   # Self-signed cert in lab

    def authenticate(self) -> bool:
        """Obtain a JWT token from the Wazuh API."""
        try:
            resp = self.session.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                timeout=15
            )
            resp.raise_for_status()
            self.token = resp.json()["data"]["token"]
            self.session.headers.update(
                {"Authorization": f"Bearer {self.token}"}
            )
            log.info("Authenticated with Wazuh API successfully")
            return True
        except Exception as exc:
            log.error(f"Wazuh authentication failed: {exc}")
            return False

    def get_alerts(self, min_level: int, since: datetime,
                   offset: int = 0) -> list:
        """
        Fetch alerts from the Wazuh indexer API.
        Returns list of alert dicts or empty list on failure.
        """
        try:
            since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
            params = {
                "limit":   WAZUH_PAGE_SIZE,
                "offset":  offset,
                "sort":    "-timestamp",
                "select":  "id,rule,agent,data,timestamp,full_log,location,decoder",
                "q":       f"rule.level>={min_level};timestamp>{since_str}"
            }
            resp = self.session.get(
                f"{self.base_url}/alerts",
                params=params,
                timeout=30
            )

            if resp.status_code == 401:
                log.warning("Token expired — re-authenticating...")
                self.authenticate()
                resp = self.session.get(
                    f"{self.base_url}/alerts",
                    params=params,
                    timeout=30
                )

            resp.raise_for_status()
            result = resp.json()
            alerts = result.get("data", {}).get("affected_items", [])
            total  = result.get("data", {}).get("total_affected_items", 0)
            log.info(f"Fetched {len(alerts)}/{total} alerts "
                     f"(level>={min_level}, since {since_str})")
            return alerts

        except Exception as exc:
            log.error(f"Failed to fetch Wazuh alerts: {exc}")
            return []


# ── TheHive API client ────────────────────────────────────────────────────────
class TheHiveClient:
    """Thin wrapper around the TheHive 5 REST API."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.session  = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Content-Type":  "application/json"
        })

    def create_case(self, payload: dict) -> dict | None:
        """Create a new case in TheHive. Returns case dict or None."""
        try:
            resp = self.session.post(
                f"{self.base_url}/api/v1/case",
                json=payload,
                timeout=30
            )
            resp.raise_for_status()
            case = resp.json()
            log.info(f"Created TheHive case #{case.get('number')} "
                     f"— {payload['title'][:60]}")
            return case
        except requests.HTTPError as exc:
            log.error(f"TheHive case creation failed "
                      f"({exc.response.status_code}): "
                      f"{exc.response.text[:200]}")
            return None
        except Exception as exc:
            log.error(f"TheHive case creation error: {exc}")
            return None

    def add_observable(self, case_id: str, data: str,
                       data_type: str, message: str) -> bool:
        """Add an observable/IOC to an existing case."""
        try:
            payload = {
                "data":     data,
                "dataType": data_type,
                "message":  message,
                "tags":     ["wazuh-alert", "automated"],
                "ioc":      True,
                "sighted":  True,
                "tlp":      2
            }
            resp = self.session.post(
                f"{self.base_url}/api/v1/case/{case_id}/observable",
                json=payload,
                timeout=15
            )
            resp.raise_for_status()
            return True
        except Exception as exc:
            log.warning(f"Failed to add observable '{data}': {exc}")
            return False

    def check_connectivity(self) -> bool:
        """Verify TheHive is reachable and API key is valid."""
        try:
            resp = self.session.get(
                f"{self.base_url}/api/v1/status",
                timeout=10
            )
            resp.raise_for_status()
            log.info("TheHive API connectivity confirmed")
            return True
        except Exception as exc:
            log.error(f"TheHive connectivity check failed: {exc}")
            return False


# ── Helper functions ──────────────────────────────────────────────────────────
def get_thehive_severity(level: int) -> int:
    """Map Wazuh rule level (0–15) to TheHive severity (1–4)."""
    for level_range, severity in LEVEL_TO_SEVERITY.items():
        if level in level_range:
            return severity
    return 2   # Default: Medium


def extract_tags(alert: dict) -> list:
    """Build TheHive tag list from alert rule groups and MITRE IDs."""
    tags = ["wazuh-alert", "automated"]

    # Add rule groups as tags
    groups = alert.get("rule", {}).get("groups", [])
    for group in groups:
        mapped = GROUP_TAG_MAP.get(group, [])
        tags.extend(mapped)
        if group not in tags:
            tags.append(group)

    # Add MITRE ATT&CK IDs
    mitre_ids = alert.get("rule", {}).get("mitre", {})
    if isinstance(mitre_ids, dict):
        for mid in mitre_ids.get("id", []):
            if mid not in tags:
                tags.append(mid)
    elif isinstance(mitre_ids, list):
        tags.extend(mitre_ids)

    # Add agent name
    agent_name = alert.get("agent", {}).get("name", "")
    if agent_name:
        tags.append(f"agent:{agent_name}")

    return list(set(tags))   # Deduplicate


def build_case_description(alert: dict) -> str:
    """Build a rich Markdown description for the TheHive case."""
    rule    = alert.get("rule", {})
    agent   = alert.get("agent", {})
    data    = alert.get("data", {})
    mitre   = rule.get("mitre", {})
    ts      = alert.get("timestamp", "unknown")

    src_ip   = data.get("srcip",   "N/A")
    src_user = data.get("srcuser", "N/A")
    dst_ip   = data.get("dstip",   "N/A")

    mitre_ids = mitre.get("id", []) if isinstance(mitre, dict) else mitre
    mitre_str = ", ".join(mitre_ids) if mitre_ids else "N/A"

    description = f"""## Automated Alert — Wazuh SOC Lab

**Detection Time:** {ts}  
**Wazuh Rule:** `{rule.get('id', 'N/A')}` — {rule.get('description', 'No description')}  
**Rule Level:** {rule.get('level', 'N/A')} / 15  
**Rule Groups:** `{', '.join(rule.get('groups', []))}`  

---

### Endpoint Details
| Field | Value |
|-------|-------|
| Agent Name | `{agent.get('name', 'N/A')}` |
| Agent ID | `{agent.get('id', 'N/A')}` |
| Agent IP | `{agent.get('ip', 'N/A')}` |
| Log Location | `{alert.get('location', 'N/A')}` |
| Decoder | `{alert.get('decoder', {}).get('name', 'N/A')}` |

---

### Network Indicators
| Field | Value |
|-------|-------|
| Source IP | `{src_ip}` |
| Source User | `{src_user}` |
| Destination IP | `{dst_ip}` |

---

### MITRE ATT&CK
**Techniques:** `{mitre_str}`  
[View on ATT&CK Navigator](https://attack.mitre.org/techniques/{mitre_ids[0] if mitre_ids else ''})

---

### Raw Log
```
{alert.get('full_log', 'No raw log available')}
```

---
*Case auto-created by alert-to-thehive.py at {datetime.now(timezone.utc).isoformat()}*  
*Wazuh Alert ID: {alert.get('id', 'N/A')}*
"""
    return description


def build_case_payload(alert: dict) -> dict:
    """Construct the full TheHive case creation payload from a Wazuh alert."""
    rule     = alert.get("rule", {})
    agent    = alert.get("agent", {})
    level    = int(rule.get("level", 0))
    severity = get_thehive_severity(level)
    tags     = extract_tags(alert)

    # Build title: [RULE_GROUP] Description (Agent)
    groups    = rule.get("groups", [])
    group_tag = groups[0].upper() if groups else "ALERT"
    title     = (f"[{group_tag}] "
                 f"{rule.get('description', 'Wazuh Alert')[:80]} "
                 f"— {agent.get('name', 'unknown')}")

    return {
        "title":       title,
        "description": build_case_description(alert),
        "severity":    severity,
        "tlp":         2,    # Amber
        "pap":         2,    # Amber
        "tags":        tags,
        "status":      "New",
        "customFields": {
            "wazuhRuleId":    rule.get("id", ""),
            "wazuhRuleLevel": str(level),
            "agentName":      agent.get("name", ""),
            "agentIp":        agent.get("ip", ""),
        }
    }


def extract_observables(alert: dict) -> list:
    """
    Extract IP addresses and usernames from the alert to add as
    TheHive observables. Returns list of (data, datatype, message) tuples.
    """
    observables = []
    data = alert.get("data", {})

    # Source IP
    src_ip = data.get("srcip", "")
    if src_ip and src_ip not in ("unknown", "N/A", ""):
        observables.append((
            src_ip, "ip",
            f"Source IP from Wazuh rule {alert.get('rule', {}).get('id')}"
        ))

    # Destination IP
    dst_ip = data.get("dstip", "")
    if dst_ip and dst_ip not in ("unknown", "N/A", ""):
        observables.append((
            dst_ip, "ip",
            "Destination IP from Wazuh alert"
        ))

    # Windows eventdata destination IP
    win_dst = (alert.get("win", {})
                    .get("eventdata", {})
                    .get("destinationIp", ""))
    if win_dst and win_dst not in ("unknown", "::1", "127.0.0.1", ""):
        observables.append((
            win_dst, "ip",
            "Network connection destination from Sysmon EID 3"
        ))

    return observables


# ── State management ──────────────────────────────────────────────────────────
def load_processed_ids() -> set:
    """Load set of already-processed alert IDs from state file."""
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        if STATE_FILE.exists():
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
                ids = set(data.get("processed_ids", []))
                log.debug(f"Loaded {len(ids)} processed alert IDs from state")
                return ids
    except Exception as exc:
        log.warning(f"Could not load state file: {exc}")
    return set()


def save_processed_ids(ids: set) -> None:
    """Persist processed alert IDs to state file. Keeps last 10,000."""
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Trim to last 10,000 to prevent unbounded growth
        trimmed = list(ids)[-10_000:]
        with open(STATE_FILE, "w") as f:
            json.dump({
                "processed_ids": trimmed,
                "last_updated": datetime.now(timezone.utc).isoformat(),
                "count": len(trimmed)
            }, f, indent=2)
    except Exception as exc:
        log.warning(f"Could not save state file: {exc}")


# ── Core processing loop ──────────────────────────────────────────────────────
def process_alerts(wazuh: WazuhAPIClient,
                   thehive: TheHiveClient,
                   min_level: int,
                   processed_ids: set,
                   dry_run: bool = False) -> int:
    """
    Fetch new high-severity alerts from Wazuh and create TheHive cases.
    Returns count of new cases created.
    """
    # Look back 2x the poll interval to avoid missing alerts on restart
    since = datetime.now(timezone.utc) - timedelta(
        seconds=POLL_INTERVAL_SECONDS * 2
    )
    alerts = wazuh.get_alerts(min_level=min_level, since=since)

    if not alerts:
        log.info("No new alerts found in this poll cycle")
        return 0

    new_cases = 0
    for alert in alerts:
        alert_id = alert.get("id", "")

        # Skip if we already processed this alert
        if alert_id in processed_ids:
            log.debug(f"Skipping already-processed alert {alert_id}")
            continue

        rule_id    = alert.get("rule", {}).get("id", "unknown")
        rule_level = alert.get("rule", {}).get("level", 0)
        rule_desc  = alert.get("rule", {}).get("description", "")[:80]
        agent_name = alert.get("agent", {}).get("name", "unknown")

        log.info(f"Processing alert {alert_id} | "
                 f"Rule {rule_id} (L{rule_level}) | "
                 f"Agent: {agent_name} | {rule_desc}")

        if dry_run:
            log.info(f"  [DRY RUN] Would create case: "
                     f"{rule_desc[:60]} on {agent_name}")
            processed_ids.add(alert_id)
            new_cases += 1
            continue

        # Build and submit case
        payload = build_case_payload(alert)
        case    = thehive.create_case(payload)

        if case:
            case_id = case.get("_id", "")
            processed_ids.add(alert_id)
            new_cases += 1

            # Add observables (IOCs) to the case
            observables = extract_observables(alert)
            for obs_data, obs_type, obs_msg in observables:
                success = thehive.add_observable(
                    case_id, obs_data, obs_type, obs_msg
                )
                if success:
                    log.info(f"  Added observable: {obs_data} ({obs_type})")
        else:
            log.warning(f"  Failed to create case for alert {alert_id} "
                        f"— will retry next cycle")

    return new_cases


# ── Main entry point ──────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Poll Wazuh API and create TheHive cases for high-severity alerts"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run a single poll cycle then exit (default: run forever)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Fetch alerts but do NOT create TheHive cases"
    )
    parser.add_argument(
        "--level", type=int, default=DEFAULT_MIN_LEVEL,
        help=f"Minimum Wazuh rule level to process (default: {DEFAULT_MIN_LEVEL})"
    )
    return parser.parse_args()


def validate_environment() -> bool:
    """Check all required environment variables are set."""
    required = {
        "WAZUH_API_PASSWORD": WAZUH_API_PASSWORD,
        "THEHIVE_API_KEY":    THEHIVE_API_KEY,
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        log.error(f"Missing required environment variables: {', '.join(missing)}")
        log.error("Set them with: export VARNAME=value")
        return False
    return True


def main() -> None:
    args = parse_args()

    log.info("=" * 60)
    log.info("  alert-to-thehive.py — SOC Lab Alert Forwarder")
    log.info("=" * 60)
    log.info(f"  Wazuh API   : {WAZUH_API_URL}")
    log.info(f"  TheHive URL : {THEHIVE_URL}")
    log.info(f"  Min Level   : {args.level}")
    log.info(f"  Poll Interval: {POLL_INTERVAL_SECONDS}s")
    log.info(f"  Dry Run     : {args.dry_run}")
    log.info(f"  Run Once    : {args.once}")
    log.info("=" * 60)

    if not validate_environment():
        sys.exit(1)

    # Initialise API clients
    wazuh   = WazuhAPIClient(WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD)
    thehive = TheHiveClient(THEHIVE_URL, THEHIVE_API_KEY)

    # Pre-flight connectivity checks
    if not wazuh.authenticate():
        log.error("Cannot authenticate with Wazuh API — check credentials")
        sys.exit(1)

    if not args.dry_run and not thehive.check_connectivity():
        log.error("Cannot reach TheHive API — check URL and API key")
        sys.exit(1)

    # Load persisted state
    processed_ids = load_processed_ids()
    log.info(f"Loaded {len(processed_ids)} previously processed alert IDs")

    # Main poll loop
    cycle = 0
    while True:
        cycle += 1
        log.info(f"--- Poll cycle #{cycle} "
                 f"({datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---")

        try:
            new_cases = process_alerts(
                wazuh, thehive, args.level, processed_ids, args.dry_run
            )
            save_processed_ids(processed_ids)

            if new_cases > 0:
                log.info(f"Cycle #{cycle} complete — {new_cases} new case(s) created")
            else:
                log.info(f"Cycle #{cycle} complete — no new cases")

        except KeyboardInterrupt:
            log.info("Interrupted by user — saving state and exiting")
            save_processed_ids(processed_ids)
            sys.exit(0)
        except Exception as exc:
            log.error(f"Unexpected error in cycle #{cycle}: {exc}", exc_info=True)

        if args.once:
            log.info("--once flag set — exiting after single cycle")
            break

        log.info(f"Sleeping {POLL_INTERVAL_SECONDS}s until next poll...")
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
