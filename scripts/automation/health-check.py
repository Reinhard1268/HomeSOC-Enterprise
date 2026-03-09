#!/usr/bin/env python3
# =============================================================================
# health-check.py — SOC Lab Service Health Monitor
# Author: SOC Lab Project
# Description: Checks all SOC lab services (Wazuh, Elasticsearch, Kibana,
#              TheHive, Shuffle), reports status in a formatted table,
#              exits with code 0 if all healthy, 1 if any service is down.
# Usage: python3 health-check.py [--json] [--watch] [--interval 30]
# =============================================================================

import os
import sys
import json
import time
import argparse
import requests
import urllib3
from datetime import datetime, timezone
from typing import Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Configuration ─────────────────────────────────────────────────────────────
ELASTIC_PASSWORD    = os.environ.get("ELASTIC_PASSWORD",         "ElasticAdmin_S3cur3!")
WAZUH_API_PASSWORD  = os.environ.get("WAZUH_MANAGER_PASSWORD",   "WazuhAdmin_S3cur3!")
THEHIVE_API_KEY     = os.environ.get("THEHIVE_API_KEY",          "")

SERVICES = [
    {
        "name":        "Wazuh Indexer",
        "url":         "https://localhost:9201",
        "auth":        ("admin", WAZUH_API_PASSWORD),
        "verify_ssl":  False,
        "timeout":     10,
        "check_key":   None,
        "expect_code": 200,
        "category":    "Wazuh",
        "port":        9201,
    },
    {
        "name":        "Wazuh Manager API",
        "url":         "https://localhost:55000",
        "auth":        ("wazuh-wui", WAZUH_API_PASSWORD),
        "verify_ssl":  False,
        "timeout":     10,
        "check_key":   None,
        "expect_code": 200,
        "category":    "Wazuh",
        "port":        55000,
    },
    {
        "name":        "Wazuh Dashboard",
        "url":         "https://localhost:443",
        "auth":        None,
        "verify_ssl":  False,
        "timeout":     15,
        "check_key":   None,
        "expect_code": [200, 302, 401],
        "category":    "Wazuh",
        "port":        443,
    },
    {
        "name":        "Elasticsearch",
        "url":         "http://localhost:9200/_cluster/health",
        "auth":        ("elastic", ELASTIC_PASSWORD),
        "verify_ssl":  True,
        "timeout":     10,
        "check_key":   "status",
        "check_not":   "red",
        "expect_code": 200,
        "category":    "Elastic Stack",
        "port":        9200,
    },
    {
        "name":        "Kibana",
        "url":         "http://localhost:5601/api/status",
        "auth":        ("elastic", ELASTIC_PASSWORD),
        "verify_ssl":  True,
        "timeout":     15,
        "check_key":   None,
        "expect_code": 200,
        "category":    "Elastic Stack",
        "port":        5601,
    },
    {
        "name":        "TheHive",
        "url":         "http://localhost:9000/api/v1/status",
        "auth":        None,
        "headers":     {"Authorization": f"Bearer {THEHIVE_API_KEY}"},
        "verify_ssl":  True,
        "timeout":     15,
        "check_key":   None,
        "expect_code": [200, 401],
        "category":    "Incident Management",
        "port":        9000,
    },
    {
        "name":        "Shuffle Backend",
        "url":         "http://localhost:5001/api/v1/health",
        "auth":        None,
        "verify_ssl":  True,
        "timeout":     10,
        "check_key":   None,
        "expect_code": [200, 404],
        "category":    "SOAR",
        "port":        5001,
    },
    {
        "name":        "Shuffle Frontend",
        "url":         "http://localhost:3001",
        "auth":        None,
        "verify_ssl":  True,
        "timeout":     10,
        "check_key":   None,
        "expect_code": [200, 302],
        "category":    "SOAR",
        "port":        3001,
    },
    {
        "name":        "Cassandra (TheHive DB)",
        "url":         None,
        "check_type":  "docker",
        "container":   "cassandra",
        "category":    "Databases",
        "port":        9042,
    },
]

# ── Colour helpers ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"


def colour(text: str, code: str) -> str:
    """Wrap text in ANSI colour codes (stripped if not a TTY)."""
    if not sys.stdout.isatty():
        return text
    return f"{code}{text}{RESET}"


# ── Individual service checks ─────────────────────────────────────────────────
def check_http_service(service: dict) -> dict:
    """
    Perform an HTTP/HTTPS health check against a service endpoint.
    Returns result dict with status, latency, and detail fields.
    """
    result = {
        "name":     service["name"],
        "category": service["category"],
        "port":     service.get("port"),
        "status":   "UNKNOWN",
        "latency":  None,
        "detail":   "",
        "url":      service["url"],
    }

    try:
        kwargs = {
            "timeout": service.get("timeout", 10),
            "verify":  service.get("verify_ssl", True),
            "allow_redirects": True,
        }

        if service.get("auth"):
            kwargs["auth"] = service["auth"]
        if service.get("headers"):
            kwargs["headers"] = service["headers"]

        start = time.monotonic()
        resp  = requests.get(service["url"], **kwargs)
        latency_ms = int((time.monotonic() - start) * 1000)

        result["latency"] = latency_ms

        # Check status code
        expected = service.get("expect_code", 200)
        if isinstance(expected, list):
            code_ok = resp.status_code in expected
        else:
            code_ok = resp.status_code == expected

        # Optional JSON key check (e.g. Elasticsearch cluster health != red)
        key_ok = True
        if service.get("check_key") and code_ok:
            try:
                body = resp.json()
                value = body.get(service["check_key"], "")
                if service.get("check_not"):
                    key_ok = value != service["check_not"]
                    if not key_ok:
                        result["detail"] = (
                            f"Degraded: {service['check_key']}={value}"
                        )
                else:
                    key_ok = bool(value)
            except Exception:
                pass

        if code_ok and key_ok:
            result["status"] = "UP"
            result["detail"] = result["detail"] or f"HTTP {resp.status_code} | {latency_ms}ms"
        elif code_ok and not key_ok:
            result["status"] = "DEGRADED"
        else:
            result["status"] = "DOWN"
            result["detail"] = f"HTTP {resp.status_code} (expected {expected})"

    except requests.ConnectionError:
        result["status"] = "DOWN"
        result["detail"] = "Connection refused — service may not be running"
    except requests.Timeout:
        result["status"] = "DOWN"
        result["detail"] = f"Timeout after {service.get('timeout', 10)}s"
    except Exception as exc:
        result["status"] = "DOWN"
        result["detail"] = f"Error: {str(exc)[:80]}"

    return result


def check_docker_container(service: dict) -> dict:
    """Check Docker container health via the Docker socket."""
    result = {
        "name":     service["name"],
        "category": service["category"],
        "port":     service.get("port"),
        "status":   "UNKNOWN",
        "latency":  None,
        "detail":   "",
        "url":      "unix:///var/run/docker.sock",
    }

    try:
        import subprocess
        container = service["container"]
        proc = subprocess.run(
            ["docker", "inspect", "--format",
             "{{.State.Status}}|{{.State.Health.Status}}",
             container],
            capture_output=True, text=True, timeout=5
        )

        if proc.returncode != 0:
            result["status"] = "DOWN"
            result["detail"] = f"Container '{container}' not found"
            return result

        output = proc.stdout.strip()
        parts  = output.split("|")
        state  = parts[0] if len(parts) > 0 else "unknown"
        health = parts[1] if len(parts) > 1 else "N/A"

        if state == "running" and health in ("healthy", "N/A", ""):
            result["status"] = "UP"
            result["detail"] = f"State: {state} | Health: {health}"
        elif state == "running" and health == "starting":
            result["status"] = "STARTING"
            result["detail"] = f"Container starting — health check pending"
        elif state == "running" and health == "unhealthy":
            result["status"] = "DEGRADED"
            result["detail"] = f"Container running but health check failing"
        else:
            result["status"] = "DOWN"
            result["detail"] = f"State: {state} | Health: {health}"

    except FileNotFoundError:
        result["status"] = "UNKNOWN"
        result["detail"] = "Docker CLI not found"
    except Exception as exc:
        result["status"] = "DOWN"
        result["detail"] = f"Docker check error: {str(exc)[:80]}"

    return result


def check_wazuh_agents(wazuh_url: str,
                       username: str,
                       password: str) -> Optional[dict]:
    """Fetch Wazuh agent summary (active/disconnected/never connected)."""
    try:
        auth_resp = requests.post(
            f"{wazuh_url}/security/user/authenticate",
            auth=(username, password),
            verify=False, timeout=10
        )
        if auth_resp.status_code != 200:
            return None

        token = auth_resp.json()["data"]["token"]
        agents_resp = requests.get(
            f"{wazuh_url}/agents/summary/status",
            headers={"Authorization": f"Bearer {token}"},
            verify=False, timeout=10
        )
        if agents_resp.status_code == 200:
            return agents_resp.json().get("data", {})
    except Exception:
        pass
    return None


# ── Display functions ─────────────────────────────────────────────────────────
def print_results_table(results: list, agent_summary: dict,
                        check_time: str) -> None:
    """Print a formatted health status table to stdout."""

    # Status formatting
    status_fmt = {
        "UP":       colour("  UP  ", GREEN),
        "DOWN":     colour(" DOWN ", RED),
        "DEGRADED": colour("DEGRADED", YELLOW),
        "STARTING": colour("STARTING", YELLOW),
        "UNKNOWN":  colour("UNKNOWN ", YELLOW),
    }

    # Header
    print()
    print(colour("═" * 72, CYAN))
    print(colour(f"  SOC LAB HEALTH CHECK — {check_time}", BOLD))
    print(colour("═" * 72, CYAN))
    print()

    # Group by category
    categories: dict = {}
    for r in results:
        cat = r["category"]
        categories.setdefault(cat, []).append(r)

    all_up = True
    for category, svcs in categories.items():
        print(colour(f"  ▶ {category}", BOLD + CYAN))
        print(colour("  " + "─" * 68, DIM))

        for svc in svcs:
            status = svc["status"]
            if status != "UP":
                all_up = False

            status_str = status_fmt.get(status, status)
            latency    = f"{svc['latency']}ms" if svc["latency"] else "  N/A"
            name       = svc["name"].ljust(28)
            port_str   = f":{svc['port']}".ljust(7) if svc["port"] else "       "
            detail     = svc.get("detail", "")[:35]

            print(f"  [{status_str}] {name} {port_str}  "
                  f"{colour(latency.rjust(6), DIM)}   {colour(detail, DIM)}")

        print()

    # Wazuh agent summary
    if agent_summary:
        total       = agent_summary.get("Total", 0)
        active      = agent_summary.get("Active", 0)
        disconnected = agent_summary.get("Disconnected", 0)
        never       = agent_summary.get("Never connected", 0)

        print(colour("  ▶ Wazuh Agents", BOLD + CYAN))
        print(colour("  " + "─" * 68, DIM))
        print(f"  Total Registered : {colour(str(total), BOLD)}")
        print(f"  Active           : {colour(str(active), GREEN)}")
        print(f"  Disconnected     : "
              f"{colour(str(disconnected), RED if disconnected > 0 else GREEN)}")
        print(f"  Never Connected  : {colour(str(never), YELLOW)}")
        print()

    # Summary line
    down_count = sum(1 for r in results
                     if r["status"] not in ("UP", "STARTING"))
    if all_up:
        summary = colour("  ✔  ALL SERVICES HEALTHY", BOLD + GREEN)
    else:
        summary = colour(
            f"  ✖  {down_count} SERVICE(S) DOWN OR DEGRADED", BOLD + RED
        )

    print(colour("═" * 72, CYAN))
    print(summary)
    print(colour("═" * 72, CYAN))
    print()


def print_json_results(results: list, agent_summary: dict,
                       check_time: str) -> None:
    """Print results as JSON (for integration with monitoring systems)."""
    output = {
        "timestamp": check_time,
        "overall_status": "healthy" if all(
            r["status"] in ("UP", "STARTING") for r in results
        ) else "degraded",
        "services": results,
        "wazuh_agents": agent_summary,
    }
    print(json.dumps(output, indent=2))


# ── Main ──────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SOC Lab service health check"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON instead of table"
    )
    parser.add_argument(
        "--watch", action="store_true",
        help="Continuously monitor, refreshing every --interval seconds"
    )
    parser.add_argument(
        "--interval", type=int, default=30,
        help="Refresh interval in seconds for --watch mode (default: 30)"
    )
    return parser.parse_args()


def run_checks() -> tuple:
    """Run all service checks. Returns (results list, agent_summary dict)."""
    results = []
    for service in SERVICES:
        if service.get("check_type") == "docker":
            results.append(check_docker_container(service))
        elif service.get("url"):
            results.append(check_http_service(service))

    # Wazuh agent summary (best-effort)
    agent_summary = check_wazuh_agents(
        "https://localhost:55000", "wazuh-wui", WAZUH_API_PASSWORD
    ) or {}

    return results, agent_summary


def main() -> None:
    args = parse_args()

    if args.watch:
        try:
            while True:
                if sys.stdout.isatty():
                    print("\033[2J\033[H", end="")   # Clear screen
                check_time = datetime.now(timezone.utc).strftime(
                    "%Y-%m-%d %H:%M:%S UTC"
                )
                results, agent_summary = run_checks()
                if args.json:
                    print_json_results(results, agent_summary, check_time)
                else:
                    print_results_table(results, agent_summary, check_time)
                print(f"  Next refresh in {args.interval}s  "
                      f"(Ctrl+C to exit)\n")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nHealth check stopped.")
            sys.exit(0)
    else:
        check_time = datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
        results, agent_summary = run_checks()
        if args.json:
            print_json_results(results, agent_summary, check_time)
        else:
            print_results_table(results, agent_summary, check_time)

        # Exit code 1 if any service is down
        any_down = any(
            r["status"] not in ("UP", "STARTING") for r in results
        )
        sys.exit(1 if any_down else 0)


if __name__ == "__main__":
    main()
