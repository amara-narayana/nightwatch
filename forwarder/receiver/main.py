"""
NIGHTWATCH Forwarder Receiver — CLI Entry Point
Starts the production mTLS receiver service, manages lifecycle, and handles signals.
"""

import argparse
import logging
import os
import signal
import sys
import time
from pathlib import Path

# Ensure nightwatch root is in sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from forwarder.receiver.config import ReceiverConfig
from forwarder.receiver.tls_server import TlsReceiverServer

logger = logging.getLogger("nightwatch.forwarder.receiver")


def setup_logging(level_name: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level_name.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] (%(name)s) %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="NIGHTWATCH Central Telemetry Receiver")
    parser.add_argument(
        "--config",
        "-c",
        required=True,
        help="Path to receiver configuration JSON file"
    )
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    if not config_path.is_file():
        print(f"Error: Configuration file not found at {config_path}", file=sys.stderr)
        sys.exit(1)

    try:
        config = ReceiverConfig.from_file(str(config_path))
        config.resolve_paths(config_path.parent)
    except Exception as e:
        print(f"Error: Invalid configuration file: {e}", file=sys.stderr)
        sys.exit(1)

    setup_logging(config.log_level)

    # Verify certificate paths exist
    for cert_label, cert_path in [
        ("CA certificate", config.ca_cert_path),
        ("Server certificate", config.server_cert_path),
        ("Server private key", config.server_key_path)
    ]:
        if not os.path.exists(cert_path):
            logger.error(f"FATAL: Required {cert_label} does not exist: {cert_path}")
            sys.exit(1)

    server = TlsReceiverServer(config)

    def sig_handler(sig, frame):
        logger.info(f"Received shutdown signal ({sig}). Stopping receiver gracefully...")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    logger.info("Starting NIGHTWATCH Central Receiver Service...")
    server.start()

    try:
        while True:
            time.sleep(10)
            metrics = server.health.get_metrics()
            logger.info(
                f"[RECEIVER HEALTH] Connections: active={metrics['active_connections']}, "
                f"total={metrics['total_connections']} | Events: accepted={metrics['total_events_accepted']}, "
                f"duplicates={metrics['total_duplicates_detected']} | Errors: {metrics['total_errors']} | "
                f"RSS: {metrics.get('rss_memory_mb', 0)} MB"
            )
    except (KeyboardInterrupt, SystemExit):
        server.stop()


if __name__ == "__main__":
    main()
