"""
NIGHTWATCH Forwarder Agent — Authenticated mTLS TCP Transport
Establishes mutual TLS encrypted TCP connection to the receiver,
sends length-prefixed event frames, and validates durable acknowledgements.
"""

import json
import logging
import socket
import ssl
import time
from typing import Any, Dict, List, Optional, Tuple

from forwarder.agent.config import AgentConfig
from forwarder.agent.event_schema import ForwarderEvent
from forwarder.receiver.protocol import (
    FrameEncoder,
    MSG_TYPE_ACK_BATCH,
    MSG_TYPE_ERROR,
    MSG_TYPE_NACK_BATCH,
    ProtocolError,
    read_frame_blocking,
)

logger = logging.getLogger("nightwatch.forwarder.transport")


class TransportError(Exception):
    """Raised on non-retryable transport or configuration error."""
    pass


class TlsAgentTransport:
    """
    Mutual TLS (mTLS) client transport.
    Validates receiver certificate and presents agent client certificate.
    """

    def __init__(self, config: AgentConfig):
        self.config = config
        self._raw_sock: Optional[socket.socket] = None
        self._ssl_sock: Optional[ssl.SSLSocket] = None
        self._connected = False

    def is_connected(self) -> bool:
        return self._connected and self._ssl_sock is not None

    def connect(self) -> None:
        """
        Creates and negotiates an authenticated mTLS TCP connection.
        Enforces TLS 1.2+ minimum, strict certificate verification, and hostname checks.
        """
        self.close()

        logger.info(
            f"Connecting to NIGHTWATCH Receiver at {self.config.receiver_host}:{self.config.receiver_port} via mTLS..."
        )

        try:
            # 1. Build strict TLS client context
            ctx = ssl.create_default_context(
                purpose=ssl.Purpose.SERVER_AUTH,
                cafile=self.config.ca_cert_path
            )
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2

            # Mutual TLS: load agent client certificate and private key
            ctx.load_cert_chain(
                certfile=self.config.client_cert_path,
                keyfile=self.config.client_key_path
            )

            # Enforce server hostname and cert verification
            ctx.check_hostname = self.config.tls_verify_server
            ctx.verify_mode = ssl.CERT_REQUIRED

            # 2. Establish TCP socket with timeout
            raw = socket.create_connection(
                (self.config.receiver_host, self.config.receiver_port),
                timeout=self.config.connect_timeout_seconds
            )
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # 3. Perform TLS Handshake
            server_hostname = self.config.receiver_host if self.config.tls_verify_server else None
            ssl_sock = ctx.wrap_socket(
                raw,
                server_hostname=server_hostname,
                do_handshake_on_connect=True
            )

            self._raw_sock = raw
            self._ssl_sock = ssl_sock
            self._connected = True

            peer_cert = ssl_sock.getpeercert()
            cipher = ssl_sock.cipher()
            tls_version = ssl_sock.version()
            logger.info(
                f"mTLS Connection established successfully: {tls_version}, Cipher: {cipher[0] if cipher else 'unknown'}"
            )

        except ssl.SSLCertVerificationError as e:
            self.close()
            logger.error(f"FATAL: TLS Certificate verification failed: {e}")
            raise TransportError(f"TLS certificate verification failed: {e}") from e
        except Exception as e:
            self.close()
            logger.warning(f"Connection to {self.config.receiver_host}:{self.config.receiver_port} failed: {e}")
            raise

    def send_batch(
        self,
        batch_id: str,
        events: List[ForwarderEvent]
    ) -> Tuple[bool, List[str], str]:
        """
        Sends an event batch and awaits durable acknowledgement.
        Returns: (success: bool, acknowledged_event_ids: List[str], error_message: str)
        """
        if not self.is_connected():
            raise ConnectionError("Transport is not connected")

        # Encode frame
        events_dicts = [e.model_dump() for e in events]
        frame_bytes = FrameEncoder.encode_event_batch(batch_id, self.config.agent_id, events_dicts)

        # Transmit frame over TLS
        self._ssl_sock.settimeout(self.config.connect_timeout_seconds)
        self._ssl_sock.sendall(frame_bytes)

        # Await receiver response frame
        msg_type, payload = read_frame_blocking(self._ssl_sock, timeout=self.config.connect_timeout_seconds)

        if msg_type == MSG_TYPE_ACK_BATCH:
            ack_data = json.loads(payload.decode("utf-8"))
            if ack_data.get("batch_id") != batch_id:
                raise ProtocolError(f"Mismatched batch_id in ACK. Expected {batch_id}, got {ack_data.get('batch_id')}")

            accepted = ack_data.get("accepted_event_ids", [])
            duplicates = ack_data.get("duplicate_event_ids", [])
            all_retired = list(set(accepted + duplicates))
            return True, all_retired, ""

        elif msg_type == MSG_TYPE_NACK_BATCH:
            nack_data = json.loads(payload.decode("utf-8"))
            err = nack_data.get("error", "Unknown receiver NACK error")
            return False, [], err

        elif msg_type == MSG_TYPE_ERROR:
            err_data = json.loads(payload.decode("utf-8"))
            err = err_data.get("error", "Receiver protocol error")
            return False, [], err

        else:
            raise ProtocolError(f"Unexpected frame type received awaiting ACK: {hex(msg_type)}")

    def close(self) -> None:
        """Closes TLS and underlying TCP socket cleanly."""
        self._connected = False
        if self._ssl_sock:
            try:
                self._ssl_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self._ssl_sock.close()
            except Exception:
                pass
            self._ssl_sock = None

        if self._raw_sock:
            try:
                self._raw_sock.close()
            except Exception:
                pass
            self._raw_sock = None
