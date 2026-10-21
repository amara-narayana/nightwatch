"""
NIGHTWATCH — Lightweight Security Intelligence Platform
Main Startup Script
"""

import argparse
import socket
import uvicorn
from app.core.config import get_settings


def get_local_ip() -> str:
    """Detects primary local network IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def main():
    parser = argparse.ArgumentParser(description="NIGHTWATCH — Central SIEM Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind to (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Web/API port (default: 8000)")
    args = parser.parse_args()

    settings = get_settings()
    local_ip = get_local_ip()

    print("=" * 75)
    print("  _   _ _____ _____ _   ___          __       _______ _____ _    _ ")
    print(" | \\ | |_   _/ ____| | | \\ \\        / / /\\   |__   __/ ____| |  | |")
    print(" |  \\| | | || |  __| |_| |\\ \\  /\\  / / /  \\     | | | |    | |__| |")
    print(" | . ` | | || | |_ |  _  | \\ \\/  \\/ / / /\\ \\    | | | |    |  __  |")
    print(" | |\\  |_| || |__| | | | |  \\  /\\  / / ____ \\   | | | |____| |  | |")
    print(" |_| \\_|_____\\_____|_| |_|   \\/  \\/ /_/    \\_\\  |_|  \\_____|_|  |_|")
    print("=" * 75)
    print(f" {settings.app_title} v{settings.version}")
    print(f" Local Web UI:         http://localhost:{args.port}")
    if local_ip != "127.0.0.1":
        print(f" Network Web UI:       http://{local_ip}:{args.port}")
        print(f" Forwarder Receiver:   Port 9997 (mTLS Encrypted)")
        print("-" * 75)
        print(f" [*] TO STREAM LOGS FROM ANY REMOTE CLIENT MACHINE:")
        print(f"     git clone <YOUR_GITHUB_REPO_URL>")
        print(f"     cd nightwatch")
        print(f"     python run_forwarder.py --server {local_ip}")
    print("=" * 75)

    uvicorn.run(
        "app.api.main:app",
        host=args.host,
        port=args.port,
        log_level=settings.server.log_level,
        reload=False
    )


if __name__ == "__main__":
    main()
