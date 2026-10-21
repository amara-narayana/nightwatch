"""
NIGHTWATCH — 1-Command Universal Endpoint Forwarder
Allows any target system (Windows / Linux) to clone the repository and stream
genuine operating system logs directly to your central NIGHTWATCH dashboard.

Usage:
    python run_forwarder.py --server <NIGHTWATCH_SERVER_IP>
    python run_forwarder.py   (prompts for server IP interactively)
"""

import argparse
import datetime
import json
import os
import platform
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# Add nightwatch root to sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"\n{BOLD}{CYAN}================================================================{RESET}")
    print(f"{BOLD}{CYAN}   NIGHTWATCH — Universal Endpoint Telemetry Forwarder          {RESET}")
    print(f"{BOLD}{CYAN}================================================================{RESET}\n")


def check_and_install_dependencies():
    """Ensures required dependencies are installed."""
    missing = []
    for pkg in ["pydantic", "cryptography", "psutil"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if platform.system() == "Windows":
        try:
            import win32evtlog  # noqa: F401
        except ImportError:
            missing.append("pywin32")

    if missing:
        print(f"[*] Installing required dependencies ({', '.join(missing)})...")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
        print(f"{GREEN}[+] Dependencies installed successfully.{RESET}\n")


def enroll_with_server(server_host: str, server_http_port: int, custom_agent_id: str = None) -> dict:
    """Auto-enrolls endpoint with central server and retrieves signed mTLS certificates."""
    enroll_url = f"http://{server_host}:{server_http_port}/api/forwarder/enroll"
    print(f"[*] Enrolling with central NIGHTWATCH server at {enroll_url}...")

    hostname = socket.gethostname()
    plat = platform.system().lower()
    req_body = {
        "hostname": hostname,
        "platform": plat,
        "agent_id": custom_agent_id or f"agent-{hostname.lower()}"
    }

    try:
        req = urllib.request.Request(
            enroll_url,
            data=json.dumps(req_body).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"{GREEN}[+] Successfully enrolled! Assigned Agent ID: '{data['agent_id']}'{RESET}")
            return data
    except urllib.error.URLError as e:
        print(f"{RED}[-] Error connecting to NIGHTWATCH server at {enroll_url}: {e}{RESET}")
        print(f"{YELLOW}[!] Ensure NIGHTWATCH is running on {server_host} (`python main.py`) and port {server_http_port} is reachable.{RESET}")
        sys.exit(1)


def setup_local_config_and_certs(enroll_data: dict, server_host: str) -> Path:
    """Saves certificates and generates agent configuration."""
    certs_dir = BASE_DIR / "forwarder" / "certs" / "agent"
    certs_dir.mkdir(parents=True, exist_ok=True)

    agent_id = enroll_data["agent_id"]
    ca_cert_path = certs_dir / "ca.crt"
    client_cert_path = certs_dir / f"{agent_id}.crt"
    client_key_path = certs_dir / f"{agent_id}.key"

    with open(ca_cert_path, "w", encoding="utf-8") as f:
        f.write(enroll_data["ca_cert"])
    with open(client_cert_path, "w", encoding="utf-8") as f:
        f.write(enroll_data["client_cert"])
    with open(client_key_path, "w", encoding="utf-8") as f:
        f.write(enroll_data["client_key"])

    # Protect key permissions where supported
    try:
        os.chmod(client_key_path, 0o600)
    except Exception:
        pass

    # Detect OS sources
    os_name = platform.system()
    file_sources = []
    windows_channels = []

    if os_name == "Windows":
        for ch in ["System", "Application", "Security"]:
            windows_channels.append({
                "channel": ch,
                "source_type": f"winevt:{ch.lower()}",
                "index": "main",
                "enabled": True
            })
    else:
        for fpath in ["/var/log/auth.log", "/var/log/syslog", "/var/log/secure", "/var/log/messages"]:
            if os.path.exists(fpath):
                file_sources.append({
                    "path": fpath,
                    "source_type": "linux:log",
                    "index": "main",
                    "enabled": True
                })

    agent_cfg = {
        "agent_id": agent_id,
        "receiver_host": server_host,
        "receiver_port": enroll_data.get("receiver_port", 9997),
        "ca_cert_path": str(ca_cert_path),
        "client_cert_path": str(client_cert_path),
        "client_key_path": str(client_key_path),
        "tls_verify_server": False,
        "state_dir": str(BASE_DIR / "forwarder" / "data" / "agent"),
        "batch_size": 100,
        "poll_interval_seconds": 1.0,
        "file_sources": file_sources,
        "windows_channels": windows_channels,
        "log_level": "INFO"
    }

    cfg_path = BASE_DIR / "forwarder" / "config" / "agent.json"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(agent_cfg, f, indent=2)

    return cfg_path


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="NIGHTWATCH 1-Command Universal Endpoint Forwarder")
    parser.add_argument(
        "--server",
        "-s",
        help="Central NIGHTWATCH Server IP or Hostname (e.g. 192.168.1.50 or my-server.com)"
    )
    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=8000,
        help="NIGHTWATCH Web / API Port (default: 8000)"
    )
    parser.add_argument(
        "--agent-id",
        help="Custom agent name (default: auto-detected from hostname)"
    )
    args = parser.parse_args()

    # Prompt interactively if not provided
    server = args.server
    if not server:
        default_srv = "127.0.0.1"
        try:
            val = input(f"Enter NIGHTWATCH Server IP or Hostname [default: {default_srv}]: ").strip()
            server = val if val else default_srv
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            sys.exit(0)

    # 1. Dependency check
    check_and_install_dependencies()

    # 2. Auto-enrollment
    enroll_data = enroll_with_server(server, args.port, args.agent_id)

    # 3. Save certificates & generate config
    cfg_path = setup_local_config_and_certs(enroll_data, server)

    # 4. Start Forwarder Agent Service
    from forwarder.agent.config import AgentConfig
    from forwarder.agent.service import ForwarderAgentService

    cfg = AgentConfig.from_file(str(cfg_path))
    service = ForwarderAgentService(cfg)
    service.start()

    print(f"\n{BOLD}{GREEN}[+] FORWARDER ACTIVE & STREAMING LIVE TELEMETRY!{RESET}")
    print(f"    Endpoint Hostname:  {BOLD}{socket.gethostname()}{RESET} ({platform.system()} {platform.release()})")
    print(f"    Assigned Agent ID:  {BOLD}{cfg.agent_id}{RESET}")
    print(f"    Target Receiver:    {BOLD}{cfg.receiver_host}:{cfg.receiver_port}{RESET} (mTLS Encrypted)")
    print(f"    Live Dashboard:     {CYAN}{BOLD}http://{server}:{args.port}{RESET}")
    print(f"\n[*] Streaming real-time OS logs to your central dashboard... (Press Ctrl+C to stop)\n")

    try:
        last_delivered = 0
        while True:
            time.sleep(2.0)
            metrics = service.health.get_snapshot()
            total_deliv = metrics.get("delivery", {}).get("total_delivered", 0)
            queue_depth = metrics.get("queue", {}).get("pending_events", 0)
            status = metrics.get("connection_status", "connected")
            new_events = total_deliv - last_delivered
            last_delivered = total_deliv
            now_str = datetime.datetime.now().strftime("%H:%M:%S")
            print(
                f"  [{now_str}] Forwarded: {total_deliv} events (+{new_events} new) | "
                f"Queue depth: {queue_depth} | Status: {GREEN}{status.capitalize()}{RESET}"
            )
    except KeyboardInterrupt:
        print("\n[*] Stopping Forwarder Agent gracefully...")
        service.stop()
        print(f"{GREEN}[+] Forwarder stopped cleanly.{RESET}")


if __name__ == "__main__":
    main()
