#!/usr/bin/env python3
# =============================================================================
# simulate-ransomware.py — Ransomware Behaviour Simulation
# Author: SOC Lab Project
# Description: Simulates ransomware encryption behaviour by:
#              1. Creating a sandbox directory filled with decoy files
#              2. Mass-renaming all files with known ransomware extensions
#              3. Generating the volume of FIM events needed to trigger
#                 Wazuh rule 100006 (frequency=20 in timeframe=30s)
#              NO actual encryption is performed — only file renames.
#              Only operates inside a temporary sandbox directory.
#              ALL changes are automatically cleaned up.
# MITRE ATT&CK: T1486 — Data Encrypted for Impact
# Usage: python3 simulate-ransomware.py [--extension .wncry]
#                                       [--files 30]
#                                       [--no-cleanup]
# =============================================================================

import os
import sys
import time
import random
import argparse
import logging
import tempfile
import shutil
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

RED    = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; BOLD  = "\033[1m";  DIM    = "\033[2m"; RESET = "\033[0m"
def c(text, code): return f"{code}{text}{RESET}"

# Known ransomware extensions — must match rule 100006 regex
RANSOMWARE_EXTENSIONS = [
    ".wncry",       # WannaCry
    ".locky",       # Locky
    ".encrypted",   # Generic
    ".cerber",      # Cerber
    ".ryuk",        # Ryuk
    ".djvu",        # STOP/Djvu
    ".revil",       # REvil
    ".conti",       # Conti
    ".maze",        # Maze
    ".darkside",    # DarkSide
]

# Realistic file types to simulate being encrypted
FAKE_FILE_TYPES = [
    ("quarterly-report-{}.docx",      "Word document content {}\n" * 100),
    ("invoice-2024-{}.xlsx",          "Excel spreadsheet data {}\n" * 80),
    ("customer-database-{}.csv",      "id,name,email,phone\n{},Customer {},user{}@example.com,555-{}\n" * 50),
    ("project-plan-{}.pdf",           "%PDF-1.4 fake pdf content {}\n" * 60),
    ("backup-credentials-{}.txt",     "server{}: admin/password{}\n" * 30),
    ("hr-records-{}.xlsx",            "employee,salary,ssn\nEmployee{},50000,XXX-XX-{}\n" * 40),
    ("source-code-{}.zip",            "PK fake zip archive content {}\n" * 200),
    ("network-diagram-{}.vsdx",       "Visio diagram content {}\n" * 70),
    ("security-audit-{}.pdf",         "%PDF fake security report {}\n" * 90),
    ("domain-passwords-{}.kdbx",      "KeePass database fake content {}\n" * 20),
]


# ── Create decoy file sandbox ─────────────────────────────────────────────────
def create_decoy_sandbox(num_files: int) -> Path:
    """
    Create a temporary directory filled with realistic-looking files
    that will be 'encrypted' (renamed) by the simulation.
    Returns path to sandbox directory.
    """
    sandbox = Path(tempfile.mkdtemp(prefix="ransomware-sim-sandbox-"))
    log.info(f"Creating sandbox with {num_files} decoy files in {sandbox}...")

    # Create subdirectories mirroring real user data structure
    subdirs = [
        "Documents/Finance",
        "Documents/HR",
        "Documents/Projects",
        "Desktop",
        "Downloads",
        "Pictures",
    ]
    for subdir in subdirs:
        (sandbox / subdir).mkdir(parents=True, exist_ok=True)

    # All subdirs as a flat list for file placement
    all_dirs = [sandbox] + [sandbox / d for d in subdirs]

    files_created = 0
    for i in range(num_files):
        template_name, template_content = random.choice(FAKE_FILE_TYPES)
        filename    = template_name.format(i)
        target_dir  = random.choice(all_dirs)
        file_path   = target_dir / filename

        content = template_content.format(i, i, i, i, i, i)
        file_path.write_text(content[:2048])   # Cap at 2KB each
        files_created += 1

    log.info(c(f"  Created {files_created} decoy files in sandbox", GREEN))
    return sandbox


# ── Ransom note drop ──────────────────────────────────────────────────────────
def drop_ransom_notes(sandbox: Path) -> None:
    """
    Drop fake ransom notes in each directory.
    Wazuh FIM detects new file creation in monitored paths.
    """
    note_content = """!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!

[THIS IS A SIMULATION - NO REAL ENCRYPTION OCCURRED]
[THIS FILE IS PART OF THE SOC LAB ATOMIC RED TEAM TEST]

Your files have been encrypted with military-grade encryption.
To recover your files, you must pay 0.5 Bitcoin to:
1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUv

Contact: decrypt@darkweb.onion
Your unique ID: SIM-{id}
Time limit: 72 hours

DO NOT attempt to decrypt files yourself.
DO NOT contact law enforcement.

[SIMULATION END - THIS IS A WAZUH DETECTION TEST]
""".format(id=f"ATOMIC-RED-TEAM-{datetime.now().strftime('%Y%m%d%H%M%S')}")

    # Drop note in sandbox root and each subdir
    for directory in sandbox.rglob("*"):
        if directory.is_dir():
            note_path = directory / "HOW_TO_DECRYPT.txt"
            note_path.write_text(note_content)

    # Drop in root too
    (sandbox / "HOW_TO_DECRYPT.txt").write_text(note_content)
    log.info(c("  Ransom notes dropped in all directories", YELLOW))


# ── Mass file rename (the ransomware behaviour) ───────────────────────────────
def mass_rename_files(sandbox: Path,
                      extension: str,
                      speed: float,
                      report_interval: int = 5) -> dict:
    """
    Rename all decoy files to add the ransomware extension.
    This is the key operation that triggers Wazuh rule 100006
    via the FIM frequency counter.

    The speed parameter controls how fast renames happen —
    fast enough to trigger the frequency/timeframe window.
    """
    log.info(f"Starting mass file rename simulation "
             f"(extension: {extension}, speed: {speed}s delay)...")

    all_files = list(sandbox.rglob("*"))
    files_to_rename = [f for f in all_files
                       if f.is_file()
                       and not f.name.startswith("HOW_TO_DECRYPT")]

    log.info(f"  Target: {len(files_to_rename)} files to rename")
    log.info(c("  Starting rename loop — Wazuh FIM should detect this...", YELLOW))
    print()

    results = {
        "files_renamed":  0,
        "files_failed":   0,
        "start_time":     datetime.now().isoformat(),
        "end_time":       None,
        "renamed_paths":  [],
        "extension_used": extension,
    }

    start = time.monotonic()

    for i, file_path in enumerate(files_to_rename):
        new_path = file_path.with_suffix(
            file_path.suffix + extension
        )

        try:
            file_path.rename(new_path)
            results["files_renamed"] += 1
            results["renamed_paths"].append(str(new_path))

            # Progress indicator
            if (i + 1) % report_interval == 0:
                elapsed = time.monotonic() - start
                rate    = results["files_renamed"] / elapsed if elapsed > 0 else 0
                log.info(c(
                    f"  [{i + 1:>3}/{len(files_to_rename)}] "
                    f"Renamed: {file_path.name} → "
                    f"{new_path.name} | "
                    f"Rate: {rate:.1f} files/sec",
                    YELLOW
                ))

        except Exception as exc:
            results["files_failed"] += 1
            log.warning(f"  Rename failed {file_path}: {exc}")

        # Control rename speed
        # Default 0.1s delay = ~10 renames/sec, crosses 20-in-30s threshold
        time.sleep(speed)

    results["end_time"] = datetime.now().isoformat()
    elapsed = time.monotonic() - start

    print()
    log.info(c(f"  Mass rename complete: "
               f"{results['files_renamed']} files renamed in "
               f"{elapsed:.1f}s", GREEN))

    return results


# ── Simulate note encryption (write + rename) ─────────────────────────────────
def simulate_encryption_markers(sandbox: Path,
                                 extension: str) -> None:
    """
    Create additional files mimicking encryption markers:
    - Empty placeholder files with encrypted extension
    - README_DECRYPT files in multiple formats
    These generate more FIM events to reliably cross the threshold.
    """
    log.info("Creating encryption marker files...")

    markers = [
        f"DECRYPT_INSTRUCTIONS{extension}",
        f"README{extension}",
        f"YOUR_FILES{extension}",
        f"RECOVERY_KEY{extension}",
        f"ENCRYPTED_FILES{extension}",
    ]

    for marker in markers:
        marker_path = sandbox / marker
        marker_path.write_bytes(
            b"\x00" * random.randint(128, 512)  # Random binary header
        )
        time.sleep(0.05)

    log.info(c(f"  Created {len(markers)} encryption marker files", GREEN))


# ── Cleanup ───────────────────────────────────────────────────────────────────
def cleanup_sandbox(sandbox: Path) -> None:
    """Remove the entire sandbox directory and all renamed files."""
    try:
        shutil.rmtree(sandbox, ignore_errors=True)
        log.info(c(f"  [✓] Sandbox cleaned: {sandbox}", GREEN))
    except Exception as exc:
        log.warning(f"  Cleanup error: {exc} — manual cleanup: rm -rf {sandbox}")


# ── Main ──────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulate ransomware file encryption to test Wazuh rule 100006"
    )
    parser.add_argument(
        "--extension",
        choices=RANSOMWARE_EXTENSIONS,
        default=".wncry",
        help="Ransomware extension to use (default: .wncry)"
    )
    parser.add_argument(
        "--files", type=int, default=30,
        help="Number of decoy files to create and rename (default: 30, min: 25)"
    )
    parser.add_argument(
        "--speed", type=float, default=0.1,
        help="Delay between renames in seconds (default: 0.1 = 10 renames/sec)"
    )
    parser.add_argument(
        "--no-cleanup", action="store_true",
        help="Do NOT clean up sandbox after simulation (inspect renamed files)"
    )
    parser.add_argument(
        "--wait", type=int, default=20,
        help="Seconds to wait after simulation before cleanup (default: 20)"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Ensure minimum file count to reliably trigger rule 100006 (frequency=20)
    num_files = max(args.files, 25)

    print()
    print(c("═" * 60, CYAN))
    print(c("  ATOMIC RED TEAM — Ransomware Behaviour Simulation", BOLD))
    print(c("  MITRE ATT&CK: T1486 — Data Encrypted for Impact", BOLD))
    print(c("═" * 60, CYAN))
    print(f"  Extension  : {c(args.extension, RED + BOLD)}")
    print(f"  File Count : {c(str(num_files), BOLD)}")
    print(f"  Rename Rate: {c(str(1 / args.speed) + ' files/sec', BOLD)}")
    print(f"  Cleanup    : {c('YES', GREEN) if not args.no_cleanup else c('NO (manual)', YELLOW)}")
    print(c("  NOTE: Only operates in temporary sandbox — NO real files affected", GREEN))
    print(c("═" * 60, CYAN))
    print()

    # Phase 1: Create sandbox
    print(c("  Phase 1: Creating decoy file sandbox...", CYAN))
    sandbox = create_decoy_sandbox(num_files)

    # Phase 2: Drop ransom notes
    print(c("\n  Phase 2: Dropping ransom notes...", CYAN))
    drop_ransom_notes(sandbox)

    # Phase 3: Mass rename (main detection trigger)
    print(c("\n  Phase 3: Mass file rename simulation (triggers rule 100006)...", CYAN))
    print(c("  Watch Wazuh Dashboard for rule 100006 firing...", YELLOW))
    print()
    rename_results = mass_rename_files(
        sandbox, args.extension, args.speed
    )

    # Phase 4: Encryption markers
    print(c("\n  Phase 4: Creating encryption marker files...", CYAN))
    simulate_encryption_markers(sandbox, args.extension)

    # Wait for detection
    print()
    print(c(f"  Waiting {args.wait}s for Wazuh detection...", YELLOW))
    for remaining in range(args.wait, 0, -5):
        print(c(f"  {remaining}s remaining...", DIM), end="\r")
        time.sleep(min(5, remaining))
    print()

    # Cleanup
    if not args.no_cleanup:
        print(c("\n  Phase 5: Cleanup...", CYAN))
        cleanup_sandbox(sandbox)
    else:
        print()
        print(c(f"  --no-cleanup: Sandbox preserved at {sandbox}", YELLOW))
        print(c("  Renamed files have extension: " + args.extension, YELLOW))
        print(c(f"  Manual cleanup: rm -rf {sandbox}", DIM))

    # Summary
    print()
    print(c("═" * 60, CYAN))
    print(c("  SIMULATION COMPLETE", BOLD))
    print(c("═" * 60, CYAN))
    print(f"\n  Files renamed    : {c(str(rename_results['files_renamed']), RED + BOLD)}")
    print(f"  Extension used   : {c(args.extension, RED)}")
    print(f"  Time to complete : "
          f"{c(rename_results['end_time'][:19], DIM)}")
    print()
    print(c("  Expected Wazuh Alerts:", BOLD))
    print(c("    100006 — RANSOMWARE: Mass file encryption detected", RED + BOLD))
    print(c("    FIM alerts on renamed files (syscheck)", GREEN))
    print()
    print(c("  Verify:", BOLD))
    print(c("  python3 scripts/testing/verify-detections.py "
            "--simulation ransomware --since 5", DIM))
    print()
    print(c("  View in Kibana:", BOLD))
    print(c("  Filter: rule.id:100006 OR rule.groups:ransomware", DIM))
    print()


if __name__ == "__main__":
    main()
