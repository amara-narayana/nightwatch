"""
NIGHTWATCH Forwarder Agent — CLI Entry Point
Usage:
  python -m forwarder.agent.main --config config/agent.json
"""

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from forwarder.agent.config import AgentConfig
from forwarder.agent.service import ForwarderAgentService

logger = logging.getLogger("nightwatch.forwarder.agent")


def setup_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )


def main():
    parser = argparse.ArgumentParser(description="NIGHTWATCH Endpoint Forwarder Agent")
    parser.add_argument("--config", "-c", default="forwarder/config/agent.json", help="Path to agent configuration JSON")
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Error: Configuration file not found at {config_path}")
        sys.exit(1)

    try:
        cfg = AgentConfig.from_file(str(config_path))
        cfg.resolve_paths(config_path.parent)
    except Exception as e:
        print(f"Configuration validation error: {e}")
        sys.exit(1)

    setup_logging(cfg.log_level)

    print("=" * 70)
    print(" NIGHTWATCH — Endpoint Forwarder Agent")
    print(f" Agent ID: {cfg.agent_id} | Host: {cfg.hostname}")
    print(f" Target Receiver: {cfg.receiver_host}:{cfg.receiver_port} (mTLS)")
    print("=" * 70)

    service = ForwarderAgentService(cfg)

    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}. Stopping agent service...")
        service.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    service.start()

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        service.stop()


if __name__ == "__main__":
    main()
