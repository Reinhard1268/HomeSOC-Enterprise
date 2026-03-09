#!/usr/bin/env python3
# =============================================================================
# verify-detections.py — Post-Simulation Detection Verifier
# Author: SOC Lab Project
# Description: Queries the Elasticsearch API to confirm that Wazuh alert
#              documents appeared after each atomic-red-team simulation
#              script was run. Validates that the full detection pipeline
#              (attack → Wazuh agent → Wazuh manager → Elasticsearch) worked.
# Usage: python3 verify-detections.py [--since 30m] [--rule 100001]
#                                     [--simulation brute-force]
# =============================================================================

import os
import sys
import json
import argparse
import logging
import requests
from datetime import datetime, timedelta, timezone
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
ES_URL      = os.environ.get("ELASTICSEARCH_URL",  "http://localhost:9200")
ES_USER     = os.environ.get("ELASTICSEARCH_USER", "elastic")
ES_PASSWORD = os.environ.get("ELASTIC_PASSWORD",   "ElasticAdmin_S3cur3!")
ES_INDEX    = "wazuh-alerts-*"

# ── Colour output ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"; RED   = "\033[91m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; BOLD  = "\033[1m";  DIM    = "\033[2m"; RESET = "\033[0m"

def c(text, code):
    return f"{code}{text}{RESET}" if sys.stdout.isatty() else text


# ── Expected detections per simulation scenario ───────────────────────────────
# Maps simulation name → list of expected Wazuh rule IDs
SIMULATION_EXPECTATIONS = {
    "brute-force": {
        "description": "simulate-brute-force.py — Rapid SSH login attempts",
        "expected_rules": ["100001"],
        "optional_rules": ["100002"],
        "search_fields":  {"rule.groups": "brute_force"},
        "min_alerts":     1,
    },
    "persistence": {
        "description": "simulate-persistence.py — Registry/crontab modification",
        "expected_rules": ["100007"],
        "optional_rules": ["100008"],
        "search_fields":  {"rule.groups": "persistence"},
        "min_alerts":     1,
    },
    "lateral-movement": {
        "description": "simulate-lateral-movement.py — PsExec-like execution",
        "expected_rules": ["100004"],
        "optional_rules": ["100009"],
        "search_fields":  {"rule.groups": "lateral_movement"},
        "min_alerts":     1,
    },
    "data-exfil": {
        "description": "simulate-data-exfil.py — Large outbound transfer",
        "expected_rules": ["100010"],
        "optional_rules": ["100009"],
        "search_fields":  {"rule.groups": "exfiltration"},
        "min_alerts":     1,
    },
    "ransomware": {
        "description": "simulate-ransomware.py — Mass file rename",
        "expected_rules": ["100006"],
        "optional_rules": [],
        "search_fields":  {"rule.groups": "ransomware"},
        "min_alerts":     1,
    },
    "all": {
        "description": "All simulation scenarios",
        "expected_rules": [
            "100001", "100004", "100006", "100007", "100010"
        ],
        "optional_rules": ["100002", "100008", "100009"],
        "search_fields":  {},
        "min_alerts":     5,
    }
}


# ── Elasticsearch query helpers ───────────────────────────────────────────────
class ElasticsearchClient:
    """Minimal Elasticsearch client for querying Wazuh alerts."""

    def __init__(self, url: str, user: str, password: str):
        self.url      = url.rstrip("/")
        self.auth     = (user, password)
        self.session  = requests.Session()
        self.session.auth = self.auth
        self.session.headers.update({"Content-Type": "application/json"})

    def check_connectivity(self) -> bool:
        try:
            resp = self.session.get(f"{self.url}/_cluster/health", timeout=10)
            data = resp.json()
            status = data.get("status", "red")
            if status in ("green", "yellow"):
                log.info(f"Elasticsearch cluster health: {status}")
                return True
            log.error(f"Elasticsearch cluster status: {status}")
            return False
        except Exception as exc:
            log.error(f"Cannot reach Elasticsearch: {exc}")
            return False

    def search_alerts(self, rule_ids: list = None,
                      rule_groups: str = None,
                      since_minutes: int = 60,
                      agent_name: str = None) -> list:
        """
        Search Wazuh alerts index for recent alerts matching criteria.
        Returns list of alert _source dicts.
        """
        since = (datetime.now(timezone.utc)
                 - timedelta(minutes=since_minutes)).isoformat()

        must_clauses = [
            {"range": {"@timestamp": {"gte": since}}}
        ]

        if rule_ids:
            must_clauses.append({"terms": {"rule.id": rule_ids}})

        if rule_groups:
            must_clauses.append({"term": {"rule.groups": rule_groups}})

        if agent_name:
            must_clauses.append({"term": {"agent.name": agent_name}})

        query = {
            "size": 100,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {"bool": {"must": must_clauses}},
            "_source": [
                "@timestamp", "rule.id", "rule.level",
                "rule.description", "rule.groups", "rule.mitre",
                "agent.name", "agent.ip", "data.srcip"
            ]
        }

        try:
            resp = self.session.post(
                f"{self.url}/{ES_INDEX}/_search",
                json=query, timeout=30
            )
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
            return [h["_source"] for h in hits]
        except Exception as exc:
            log.error(f"Elasticsearch search failed: {exc}")
            return []

    def get_rule_counts(self, since_minutes: int = 60) -> dict:
        """
        Aggregate alert counts by rule ID for the past N minutes.
        Returns dict of rule_id → count.
        """
        since = (datetime.now(timezone.utc)
                 - timedelta(minutes=since_minutes)).isoformat()

        query = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": since}}},
            "aggs": {
                "by_rule": {
                    "terms": {"field": "rule.id", "size": 50}
                }
            }
        }

        try:
            resp = self.session.post(
                f"{self.url}/{ES_INDEX}/_search",
                json=query, timeout=15
            )
            resp.raise_for_status()
            buckets = (resp.json()
                       .get("aggregations", {})
                       .get("by_rule", {})
                       .get("buckets", []))
            return {b["key"]: b["doc_count"] for b in buckets}
        except Exception as exc:
            log.error(f"Aggregation query failed: {exc}")
            return {}


# ── Verification logic ────────────────────────────────────────────────────────
def verify_simulation(es: ElasticsearchClient,
                      simulation: str,
                      since_minutes: int,
                      agent_name: Optional[str]) -> dict:
    """
    Verify that expected alerts appeared after a simulation run.
    Returns result dict with pass/fail status per expected rule.
    """
    if simulation not in SIMULATION_EXPECTATIONS:
        log.error(f"Unknown simulation: {simulation}")
        return {}

    config = SIMULATION_EXPECTATIONS[simulation]
    log.info(f"Verifying: {config['description']}")

    alerts = es.search_alerts(
        rule_ids      = config["expected_rules"] + config.get("optional_rules", []),
        since_minutes = since_minutes,
        agent_name    = agent_name,
    )

    # Build rule → alerts mapping
    fired_rules: dict = {}
    for alert in alerts:
        rule_id = alert.get("rule", {}).get("rule_id") or alert.get("rule.id", "")
        if rule_id:
            fired_rules.setdefault(rule_id, []).append(alert)

    results = {
        "simulation":    simulation,
        "description":   config["description"],
        "since_minutes": since_minutes,
        "total_alerts":  len(alerts),
        "checks":        [],
        "passed":        True,
    }

    for rule_id in config["expected_rules"]:
        found  = rule_id in fired_rules
        count  = len(fired_rules.get(rule_id, []))
        passed = found and count >= config.get("min_alerts", 1)

        if not passed:
            results["passed"] = False

        check = {
            "rule_id":  rule_id,
            "required": True,
            "found":    found,
            "count":    count,
            "passed":   passed,
        }

        if found:
            latest = fired_rules[rule_id][0]
            check["latest_timestamp"] = latest.get("@timestamp", "")
            check["latest_agent"]     = (
                latest.get("agent", {}).get("name", "")
                or latest.get("agent.name", "")
            )
            check["latest_level"]     = (
                latest.get("rule", {}).get("level", "")
                or latest.get("rule.level", "")
            )
            check["description"]      = (
                latest.get("rule", {}).get("description", "")
                or latest.get("rule.description", "")
            )

        results["checks"].append(check)

    for rule_id in config.get("optional_rules", []):
        found = rule_id in fired_rules
        count = len(fired_rules.get(rule_id, []))
        results["checks"].append({
            "rule_id":  rule_id,
            "required": False,
            "found":    found,
            "count":    count,
            "passed":   True,   # Optional — never fails
        })

    return results


# ── Display ───────────────────────────────────────────────────────────────────
def print_verification_results(all_results: list) -> None:
    print()
    print(c("═" * 72, CYAN))
    print(c("  POST-SIMULATION DETECTION VERIFICATION", BOLD))
    print(c("═" * 72, CYAN))

    overall_pass = True

    for result in all_results:
        if not result:
            continue

        sim_passed = result.get("passed", False)
        if not sim_passed:
            overall_pass = False

        sim_status = c(" PASS ", GREEN + BOLD) if sim_passed else c(" FAIL ", RED + BOLD)
        print()
        print(f"  [{sim_status}] {c(result['simulation'].upper(), BOLD)}")
        print(c(f"           {result['description']}", DIM))
        print(c(f"           Searched last {result['since_minutes']}m "
                f"| Found {result['total_alerts']} related alert(s)", DIM))
        print()

        for check in result.get("checks", []):
            rule_id  = check["rule_id"]
            required = "REQUIRED" if check["required"] else "optional"
            found    = check["found"]
            count    = check["count"]

            if check["passed"] and found:
                status  = c("  FOUND  ", GREEN)
                ts      = check.get("latest_timestamp", "")[:19]
                agent   = check.get("latest_agent", "unknown")
                level   = check.get("latest_level", "?")
                desc    = check.get("description", "")[:40]
                detail  = f"L{level} | {agent} | {ts} | {desc}"
            elif check["passed"] and not found:
                status = c("  N/A   ", DIM)
                detail = "Optional rule — not required to fire"
            else:
                status  = c(" MISSING ", RED)
                detail  = (f"Expected rule {rule_id} to fire — "
                            f"check simulation ran successfully")

            req_str = c(f"[{required}]", DIM).ljust(20)
            print(f"    [{status}] Rule {rule_id}  {req_str}  "
                  f"{c(str(count) + ' alert(s)', DIM)}  "
                  f"{c(detail, DIM)}")

    print()
    print(c("─" * 72, DIM))

    if overall_pass:
        print(c("  ✔  ALL REQUIRED DETECTIONS CONFIRMED IN ELASTICSEARCH", GREEN + BOLD))
    else:
        print(c("  ✖  SOME EXPECTED DETECTIONS NOT FOUND — CHECK PIPELINE", RED + BOLD))
        print(c("     Troubleshooting:", YELLOW))
        print(c("       1. Verify simulation script ran successfully", DIM))
        print(c("       2. Check Wazuh agent is active: /var/ossec/bin/wazuh-control status", DIM))
        print(c("       3. Check Wazuh manager logs: docker logs wazuh-manager", DIM))
        print(c("       4. Verify Filebeat is forwarding to Elasticsearch", DIM))
        print(c("       5. Check index pattern in Kibana matches wazuh-alerts-*", DIM))

    print(c("═" * 72, CYAN))
    print()


def print_rule_summary(es: ElasticsearchClient, since_minutes: int) -> None:
    print()
    print(c(f"  Recent Custom Rule Alert Counts (last {since_minutes} min)", BOLD + CYAN))
    print(c("  " + "─" * 50, DIM))

    counts      = es.get_rule_counts(since_minutes=since_minutes)
    custom_rules = {k: v for k, v in counts.items() if k.startswith("1000")}

    if not custom_rules:
        print(c("  No custom rule alerts found in this time window", YELLOW))
    else:
        for rule_id in sorted(custom_rules.keys()):
            count  = custom_rules[rule_id]
            bar    = "█" * min(count, 40)
            colour_code = RED if count > 10 else (YELLOW if count > 3 else GREEN)
            print(f"  Rule {rule_id}  "
                  f"{c(str(count).rjust(4), colour_code + BOLD)} alerts  "
                  f"{c(bar, colour_code)}")
    print()


# ── Main ──────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify Wazuh detections appeared in Elasticsearch after simulations"
    )
    parser.add_argument(
        "--since", type=int, default=60,
        help="Look back N minutes for alerts (default: 60)"
    )
    parser.add_argument(
        "--simulation",
        choices=list(SIMULATION_EXPECTATIONS.keys()),
        default="all",
        help="Which simulation to verify (default: all)"
    )
    parser.add_argument(
        "--agent", type=str, default=None,
        help="Filter results to a specific Wazuh agent name"
    )
    parser.add_argument(
        "--summary", action="store_true",
        help="Also print recent custom rule alert count summary"
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Save results to JSON file"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print()
    print(c("  verify-detections.py — SOC Lab Detection Verifier", BOLD + CYAN))
    print(c(f"  Elasticsearch: {ES_URL}", DIM))
    print(c(f"  Looking back:  {args.since} minutes", DIM))
    print()

    es = ElasticsearchClient(ES_URL, ES_USER, ES_PASSWORD)

    if not es.check_connectivity():
        log.error("Cannot reach Elasticsearch — check service status")
        sys.exit(1)

    sims_to_check = (
        [s for s in SIMULATION_EXPECTATIONS if s != "all"]
        if args.simulation == "all"
        else [args.simulation]
    )

    all_results = []
    for sim in sims_to_check:
        result = verify_simulation(es, sim, args.since, args.agent)
        all_results.append(result)

    print_verification_results(all_results)

    if args.summary:
        print_rule_summary(es, args.since)

    if args.output:
        with open(args.output, "w") as f:
            json.dump({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "results":   all_results
            }, f, indent=2)
        log.info(f"Results saved to {args.output}")

    overall_pass = all(r.get("passed", False) for r in all_results if r)
    sys.exit(0 if overall_pass else 1)


if __name__ == "__main__":
    main()
