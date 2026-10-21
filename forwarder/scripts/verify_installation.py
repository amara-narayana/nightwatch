"""
NIGHTWATCH Forwarder — Endpoint Pre-flight & Installation Verification Tool
Performs comprehensive diagnostics on OS, Python runtime, file permissions,
certificate validity, event log channels, and receiver network reachability.
"""

import argparse
import datetime
import json
import os
import platform
import socket
import ssl
import sys
from pathlib import Path

# Terminal color constants
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_check(name: str, passed: bool, detail: str = ""):
    status = f"{GREEN}[PASS]{RESET}" if passed else f"{RED}[FAIL]{RESET}"
    msg = f"  {status} {BOLD}{name}{RESET}"
    if detail:
        msg += f" — {detail}"
    print(msg)


def check_python_version() -> bool:
    v = sys.version_info
    ver_str = f"{v.major}.{v.minor}.{v.micro}"
    passed = v >= (3, 10)
    print_check("Python Version >= 3.10", passed, f"Detected: {ver_str}")
    return passed


def check_dependencies() -> bool:
    deps = ["pydantic", "cryptography", "sqlite3", "ssl", "psutil"]
    all_ok = True
    for dep in deps:
        try:
            __import__(dep)
            print_check(f"Module '{dep}'", True, "Installed")
        except ImportError:
            print_check(f"Module '{dep}'", False, "Missing! Run pip install -r requirements.txt")
            all_ok = False

    if platform.system() == "Windows":
        try:
            import win32evtlog  # noqa: F401
            print_check("Windows Module 'pywin32' (win32evtlog)", True, "Installed")
        except ImportError:
            print_check(
                "Windows Module 'pywin32'",
                False,
                "Optional/Fallback available: native wevtutil will be used if win32evtlog is missing"
            )
    return all_ok


def check_certificates(ca_path: str, cert_path: str, key_path: str) -> bool:
    all_ok = True

    for label, p in [("CA Cert", ca_path), ("Client Cert", cert_path), ("Client Key", key_path)]:
        if not os.path.exists(p):
            print_check(f"File exists: {label}", False, f"Not found at {p}")
            all_ok = False
        else:
            print_check(f"File exists: {label}", True, p)

    if not all_ok:
        return False

    # Inspect certificate validity
    try:
        from cryptography import x509
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        now = datetime.datetime.now(datetime.timezone.utc)
        valid = cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
        days_left = (cert.not_valid_after_utc - now).days
        print_check(
            "Certificate Expiration Check",
            valid,
            f"Expires in {days_left} days ({cert.not_valid_after_utc.strftime('%Y-%m-%d')})"
        )
        if not valid:
            all_ok = False
    except Exception as e:
        print_check("Certificate Parse", False, f"Error: {e}")
        all_ok = False

    return all_ok


def check_log_sources(config_data: dict) -> bool:
    os_name = platform.system()
    all_ok = True

    if os_name == "Windows":
        channels = config_data.get("windows_channels", ["System", "Application"])
        try:
            import win32evtlog
            for ch in channels:
                ch_name = ch.get("channel", "System") if isinstance(ch, dict) else str(ch)
                try:
                    h = win32evtlog.OpenEventLog(None, ch_name)
                    num_records = win32evtlog.GetNumberOfEventLogRecords(h)
                    win32evtlog.CloseEventLog(h)
                    print_check(f"Windows Channel '{ch_name}'", True, f"Accessible ({num_records} events available)")
                except Exception as e:
                    print_check(f"Windows Channel '{ch_name}'", False, f"Access error: {e}")
                    all_ok = False
        except ImportError:
            print_check("Windows Event Log Check", True, "Checking via wevtutil fallback...")
            import subprocess
            for ch in channels:
                ch_name = ch.get("channel", "System") if isinstance(ch, dict) else str(ch)
                res = subprocess.run(["wevtutil", "gli", ch_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                passed = res.returncode == 0
                print_check(f"Windows Channel '{ch_name}' (wevtutil)", passed, "Channel verified" if passed else "Channel inaccessible")
                if not passed:
                    all_ok = False

    elif os_name == "Linux":
        files = config_data.get("linux_log_files", [])
        if not files:
            print_check("Linux Log Sources", True, "No files configured")
        for fpath in files:
            if not os.path.exists(fpath):
                print_check(f"Log File '{fpath}'", False, "File does not exist on this system")
            elif not os.access(fpath, os.R_OK):
                print_check(f"Log File '{fpath}'", False, "Permission denied (read access required)")
                all_ok = False
            else:
                sz = os.path.getsize(fpath)
                print_check(f"Log File '{fpath}'", True, f"Readable (size: {sz} bytes)")

    return all_ok


def check_network_reachability(host: str, port: int, ca_cert: str) -> bool:
    print(f"\n{BOLD}Testing network reachability to {host}:{port}...{RESET}")
    try:
        sock = socket.create_connection((host, port), timeout=5.0)
        sock.close()
        print_check(f"TCP Connectivity to {host}:{port}", True, "Port is open and accepting TCP connections")
        return True
    except Exception as e:
        print_check(f"TCP Connectivity to {host}:{port}", False, f"Connection refused/timed out: {e}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="NIGHTWATCH Forwarder Verification Utility")
    parser.add_argument("--config", "-c", required=True, help="Path to agent configuration JSON")
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    print(f"\n{BOLD}{CYAN}================================================================{RESET}")
    print(f"{BOLD}{CYAN}  NIGHTWATCH Forwarder Endpoint Installation Verification       {RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}\n")

    if not config_path.is_file():
        print_check("Configuration File Exists", False, f"File not found: {config_path}")
        sys.exit(1)

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        print_check("Configuration JSON Syntax", True, f"Loaded {config_path.name}")
    except Exception as e:
        print_check("Configuration JSON Syntax", False, str(e))
        sys.exit(1)

    base_dir = config_path.parent

    def resolve(p):
        if not p:
            return ""
        if os.path.isabs(p):
            return p
        p1 = (base_dir / p).resolve()
        if p1.exists():
            return str(p1)
        p2 = Path(p).resolve()
        if p2.exists():
            return str(p2)
        return str(p1)

    ca_path = resolve(cfg.get("ca_cert_path", ""))
    cert_path = resolve(cfg.get("client_cert_path", ""))
    key_path = resolve(cfg.get("client_key_path", ""))
    queue_db = resolve(cfg.get("queue_db_path", "data/agent_queue.db"))

    print(f"\n{BOLD}1. System & Runtime Environment:{RESET}")
    print_check("Operating System", True, f"{platform.system()} {platform.release()} ({platform.machine()})")
    py_ok = check_python_version()
    deps_ok = check_dependencies()

    print(f"\n{BOLD}2. Security & mTLS Credentials:{RESET}")
    cert_ok = check_certificates(ca_path, cert_path, key_path)

    print(f"\n{BOLD}3. Local Queue & State Storage:{RESET}")
    try:
        os.makedirs(os.path.dirname(os.path.abspath(queue_db)), exist_ok=True)
        with open(queue_db + ".test", "w") as tf:
            tf.write("write_test")
        os.remove(queue_db + ".test")
        print_check("Queue Directory Write Access", True, f"Path: {queue_db}")
        queue_ok = True
    except Exception as e:
        print_check("Queue Directory Write Access", False, f"Error: {e}")
        queue_ok = False

    print(f"\n{BOLD}4. Telemetry Log Sources:{RESET}")
    sources_ok = check_log_sources(cfg)

    print(f"\n{BOLD}5. Network Connectivity:{RESET}")
    host = cfg.get("receiver_host", "127.0.0.1")
    port = cfg.get("receiver_port", 9997)
    net_ok = check_network_reachability(host, port, ca_path)

    overall = py_ok and deps_ok and cert_ok and queue_ok and sources_ok
    print(f"\n{BOLD}{CYAN}================================================================{RESET}")
    if overall and net_ok:
        print(f"{GREEN}{BOLD}  RESULT: VERIFICATION PASSED. Agent is ready for live operation!{RESET}")
    elif overall:
        print(f"{YELLOW}{BOLD}  RESULT: LOCAL CONFIG PASSED. (Receiver offline or not started yet){RESET}")
    else:
        print(f"{RED}{BOLD}  RESULT: VERIFICATION FAILED. Review errors above.{RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}\n")


if __name__ == "__main__":
    main()
