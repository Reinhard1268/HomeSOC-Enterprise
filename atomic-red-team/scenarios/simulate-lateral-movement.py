#!/usr/bin/env python3
# =============================================================================
# simulate-lateral-movement.py — PsExec-Style Lateral Movement Simulation
# Author: SOC Lab Project
# Description: Simulates lateral movement by:
#              1. Creating a remote service on a target host via SSH
#                 (mimicking PsExec's PSEXESVC service creation behaviour)
#              2. Executing commands on the target as if via PsExec
#              3. Generating Windows Event 7045 / Sysmon EID 1 equivalents
#              Designed to trigger Wazuh rule 100004.
#              Also simulates pass-the-hash-style credential reuse (T1550.002)
#              by attempting to use harvested credentials against other hosts.
# MITRE ATT&CK: T1021.002 — Remote Services: SMB/Windows Admin Shares
#               T1570     — Lateral Tool Transfer
#               T1550.002 — Pass the Hash (simulated)
# Usage: python3 simulate-lateral-movement.py --pivot 192.168.1.100
#                                             --target 192.168.1.101
#                                             --user admin
#                                             --password 'Password123'
# =============================================================================

import os
import sys
import time
import socket
import argparse
import logging
import subprocess
import tempfile
from datetime import datetime

try:
    import paramiko
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip",
                           "install", "paramiko", "--quiet"])
    import paramiko

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

RED    = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; BOLD  = "\033[1m";  RESET  = "\033[0m"
def c(text, code): return f"{code}{text}{RESET}"


# ── SSH execution helper ───────────────────────────────────────────────────────
def ssh_exec(host: str, port: int, username: str,
             password: str, command: str,
             timeout: float = 30.0) -> tuple:
    """
    Execute a command on a remote host via SSH.
    Returns (stdout, stderr, exit_code).
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host, port=port,
            username=username, password=password,
            timeout=timeout, look_for_keys=False,
            allow_agent=False
        )
        stdin, stdout, stderr = client.exec_command(
            command, timeout=timeout
        )
        out     = stdout.read().decode("utf-8", errors="replace").strip()
        err     = stderr.read().decode("utf-8", errors="replace").strip()
        retcode = stdout.channel.recv_exit_status()
        return out, err, retcode

    except paramiko.AuthenticationException:
        return "", "Authentication failed", 1
    except Exception as exc:
        return "", str(exc), 1
    finally:
        try:
            client.close()
        except Exception:
            pass


def check_host_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    """Check if a host:port is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


# ── Simulation phases ─────────────────────────────────────────────────────────

def phase1_reconnaissance(target: str, port: int,
                           username: str, password: str) -> dict:
    """
    Simulate post-compromise reconnaissance from target host:
    - Hostname and OS info
    - Network interfaces  
    - Running processes
    - Active sessions
    Mirrors what an attacker does immediately after pivoting.
    """
    log.info("Phase 1: Post-pivot reconnaissance on target...")

    recon_commands = {
        "hostname":   "hostname && whoami",
        "os_info":    "uname -a 2>/dev/null || ver",
        "network":    "ip addr show 2>/dev/null || ipconfig",
        "processes":  "ps aux --no-headers 2>/dev/null | head -20 || "
                      "tasklist /fo csv 2>/dev/null | head -20",
        "users":      "who 2>/dev/null || query user 2>/dev/null",
        "netstat":    "ss -tulpn 2>/dev/null | head -15 || "
                      "netstat -an 2>/dev/null | head -15",
    }

    results = {}
    for name, cmd in recon_commands.items():
        stdout, stderr, code = ssh_exec(
            target, port, username, password, cmd, timeout=15.0
        )
        results[name] = stdout or stderr
        status = c("OK", GREEN) if code == 0 else c("FAIL", YELLOW)
        log.info(f"  [{status}] {name}: "
                 f"{(stdout or stderr)[:80].replace(chr(10), ' ')}")
        time.sleep(0.3)

    return results


def phase2_tool_transfer(target: str, port: int,
                          username: str, password: str) -> bool:
    """
    Simulate lateral tool transfer — drop a fake 'attacker tool' on the
    target host in a temp location. Wazuh FIM should detect new files.
    File content is harmless (just an echo script).
    Triggers: syscheck alert on /tmp directory.
    """
    log.info("Phase 2: Simulating tool transfer to target...")

    # Create a fake 'psexec-dropped' binary (harmless shell script)
    fake_tool_content = (
        "#!/bin/bash\n"
        "# PSEXESVC simulation — harmless test file\n"
        "echo 'PSEXESVC running' > /dev/null\n"
    )
    drop_path = "/tmp/PSEXESVC"

    cmd = (
        f"echo '{fake_tool_content}' > {drop_path} && "
        f"chmod +x {drop_path} && "
        f"echo 'DROP_SUCCESS:{drop_path}'"
    )

    stdout, stderr, code = ssh_exec(
        target, port, username, password, cmd, timeout=15.0
    )

    if "DROP_SUCCESS" in stdout:
        log.info(c(f"  [+] Fake tool dropped at {drop_path} on {target}", GREEN))
        return True
    else:
        log.warning(f"  Tool transfer failed: {stderr}")
        return False


def phase3_remote_execution(target: str, port: int,
                             username: str, password: str) -> bool:
    """
    Simulate remote command execution as PSEXESVC would do — runs commands
    under a service context. Creates audit trail entries that match what
    Wazuh rule 100004 looks for.
    Also writes to syslog with PSEXESVC identifier to trigger decoder.
    """
    log.info("Phase 3: Simulating PSEXESVC-style remote execution...")

    # Commands that mimic what an attacker runs after lateral movement
    lateral_commands = [
        # Create a service entry in syslog matching PSEXESVC decoder
        ("Create PSEXESVC audit entry",
         "logger -t PSEXESVC 'Service started: PSEXESVC "
         "running as SYSTEM via lateral movement simulation'"),

        # Dump local user accounts
        ("Enumerate local users",
         "cut -d: -f1 /etc/passwd | tail -20"),

        # Check sudo permissions
        ("Check sudo access",
         "sudo -l 2>/dev/null | head -10 || echo 'sudo check failed'"),

        # Look for credential files
        ("Search for credential files",
         "find /home /root -name '*.key' -o -name '*.pem' "
         "-o -name 'id_rsa' 2>/dev/null | head -10"),

        # Simulate creating a backdoor service
        ("Simulate service creation",
         "logger -p auth.notice 'New service installed: "
         "Name=PSEXESVC, Type=User-Mode-Service, "
         "Start=Demand-Start, Path=/tmp/PSEXESVC'"),
    ]

    success_count = 0
    for name, cmd in lateral_commands:
        stdout, stderr, code = ssh_exec(
            target, port, username, password, cmd, timeout=15.0
        )
        status = c("OK", GREEN) if code == 0 else c("SKIP", YELLOW)
        log.info(f"  [{status}] {name}")
        if stdout:
            for line in stdout.splitlines()[:3]:
                log.info(c(f"           {line}", YELLOW))
        if code == 0:
            success_count += 1
        time.sleep(0.5)

    return success_count > 0


def phase4_cleanup_target(target: str, port: int,
                           username: str, password: str) -> None:
    """Remove artefacts dropped during the simulation."""
    log.info("Phase 4: Cleaning up simulation artefacts on target...")

    cleanup_cmds = [
        "rm -f /tmp/PSEXESVC",
        "rm -f /tmp/.lateral-test",
    ]

    for cmd in cleanup_cmds:
        stdout, stderr, code = ssh_exec(
            target, port, username, password, cmd, timeout=10.0
        )
        status = c("OK", GREEN) if code == 0 else c("SKIP", DIM)
        log.info(f"  [{status}] {cmd}")


# ── Credential reuse simulation ────────────────────────────────────────────────
def simulate_credential_reuse(targets: list, port: int,
                               username: str, password: str) -> dict:
    """
    Simulate pass-the-hash / credential reuse by attempting the SAME
    credential set against multiple hosts. Reflects how attackers pivot
    after dumping credentials from one host.
    """
    log.info("Credential reuse simulation — testing same creds on multiple hosts...")
    results = {}

    for target in targets:
        reachable = check_host_reachable(target, port)
        if not reachable:
            log.info(f"  {target}:{port} — unreachable, skipping")
            results[target] = "unreachable"
            continue

        out, err, code = ssh_exec(
            target, port, username, password,
            "hostname && id", timeout=5.0
        )
        if code == 0:
            log.info(c(f"  [+] CREDENTIAL REUSE SUCCESS on {target}: {out}", GREEN))
            results[target] = "success"
        else:
            log.info(f"  [-] Credential reuse failed on {target}")
            results[target] = "failed"
        time.sleep(0.3)

    return results


# ── Main ──────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulate lateral movement to test Wazuh detection"
    )
    parser.add_argument("--pivot",    required=True,
                        help="Pivot host IP (where attacker currently is)")
    parser.add_argument("--target",   required=True,
                        help="Target host IP (where to move laterally)")
    parser.add_argument("--user",     default="root",
                        help="SSH username (default: root)")
    parser.add_argument("--password", required=True,
                        help="SSH password")
    parser.add_argument("--port",     type=int, default=22,
                        help="SSH port (default: 22)")
    parser.add_argument("--no-cleanup", action="store_true",
                        help="Skip cleanup phase")
    parser.add_argument("--additional-targets", nargs="*", default=[],
                        help="Additional hosts for credential reuse simulation")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print()
    print(c("═" * 60, CYAN))
    print(c("  ATOMIC RED TEAM — Lateral Movement Simulation", BOLD))
    print(c("  MITRE ATT&CK: T1021.002, T1570, T1550.002", BOLD))
    print(c("═" * 60, CYAN))
    print(f"  Pivot Host : {c(args.pivot, BOLD)}")
    print(f"  Target Host: {c(args.target, BOLD)}")
    print(f"  Username   : {c(args.user, BOLD)}")
    print(c("═" * 60, CYAN))
    print()

    # Pre-flight checks
    for host, label in [(args.pivot, "pivot"), (args.target, "target")]:
        if not check_host_reachable(host, args.port):
            print(c(f"[ERROR] Cannot reach {label} host {host}:{args.port}", RED))
            sys.exit(1)
        log.info(f"{label.capitalize()} host {host} is reachable")

    # Execute simulation phases
    print(c("\n  ── Phase 1: Post-Pivot Reconnaissance ──", CYAN))
    phase1_reconnaissance(args.target, args.port, args.user, args.password)

    print(c("\n  ── Phase 2: Lateral Tool Transfer ──", CYAN))
    phase2_tool_transfer(args.target, args.port, args.user, args.password)

    print(c("\n  ── Phase 3: Remote Execution (PSEXESVC-style) ──", CYAN))
    phase3_remote_execution(args.target, args.port, args.user, args.password)

    # Optional credential reuse against additional targets
    if args.additional_targets:
        print(c("\n  ── Credential Reuse Against Additional Targets ──", CYAN))
        simulate_credential_reuse(
            args.additional_targets, args.port, args.user, args.password
        )

    # Cleanup
    if not args.no_cleanup:
        print(c("\n  ── Phase 4: Cleanup ──", CYAN))
        time.sleep(15)   # Let Wazuh detect first
        phase4_cleanup_target(args.target, args.port, args.user, args.password)

    # Summary
    print()
    print(c("═" * 60, CYAN))
    print(c("  SIMULATION COMPLETE", BOLD))
    print(c("═" * 60, CYAN))
    print()
    print(c("  Expected Wazuh Alerts:", BOLD))
    print(c("    100004 — PsExec lateral movement (PSEXESVC in logs)", GREEN))
    print(c("    Syscheck — Tool drop in /tmp detected", GREEN))
    print(c("    Auth logs — SSH from pivot to target", GREEN))
    print()
    print(c("  Verify:", BOLD))
    print(c("  python3 scripts/testing/verify-detections.py "
            "--simulation lateral-movement --since 15", DIM))
    print()


if __name__ == "__main__":
    main()
