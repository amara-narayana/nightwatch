"""
NIGHTWATCH Forwarder Receiver — Authenticated Mutual TLS (mTLS) Server
Listens for endpoint agent connections, validates client certificates,
enforces agent authorization, processes event frames, commits to durable storage,
and issues cryptographic delivery acknowledgements.
"""

import json
import logging
import socket
import ssl
import threading
import time
from typing import Any, Dict, List, Optional

from forwarder.receiver.authentication import AuthenticationError, extract_client_identity
from forwarder.receiver.authorization import AuthorizationError, authorize_agent
from forwarder.receiver.config import ReceiverConfig
from forwarder.receiver.health import ReceiverHealthMonitor
from forwarder.receiver.protocol import (
    FrameEncoder,
    MSG_TYPE_ACK_BATCH,
    MSG_TYPE_ERROR,
    MSG_TYPE_EVENT_BATCH,
    MSG_TYPE_NACK_BATCH,
    MSG_TYPE_PING,
    MSG_TYPE_PONG,
    ProtocolError,
    read_frame_blocking,
)
from forwarder.receiver.storage import ReceiverStorage
from forwarder.receiver.validation import (
    ValidationError,
    validate_batch_envelope,
    validate_event_dict,
)

logger = logging.getLogger("nightwatch.forwarder.receiver.server")


class TlsReceiverServer:
    """
    Multi-client mTLS TCP Server for NIGHTWATCH Forwarder Agents.
    """

    def __init__(self, config: ReceiverConfig, storage: Optional[ReceiverStorage] = None):
        self.config = config
        self.storage = storage or ReceiverStorage(config)
        self.health = ReceiverHealthMonitor(config.storage_path)

        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._accept_thread: Optional[threading.Thread] = None
        self._client_threads: List[threading.Thread] = []
        self._lock = threading.Lock()

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Configures strict mutual TLS server context."""
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        # Server certificate & private key
        ctx.load_cert_chain(
            certfile=self.config.server_cert_path,
            keyfile=self.config.server_key_path
        )

        if self.config.require_client_cert:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_verify_locations(cafile=self.config.ca_cert_path)
        else:
            ctx.verify_mode = ssl.CERT_NONE

        return ctx

    def start(self) -> None:
        """Starts the mTLS receiver listener in a background thread."""
        if self._running:
            return

        ctx = self._build_ssl_context()

        raw_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_server.bind((self.config.listen_host, self.config.listen_port))
        raw_server.listen(128)
        raw_server.settimeout(1.0)  # Allows checking self._running periodically

        self._server_socket = raw_server
        self._running = True

        self._accept_thread = threading.Thread(
            target=self._accept_loop,
            args=(raw_server, ctx),
            name="NightwatchReceiverAcceptLoop",
            daemon=True
        )
        self._accept_thread.start()

        logger.info(
            f"NIGHTWATCH Receiver mTLS server listening on {self.config.listen_host}:{self.config.listen_port} "
            f"(mTLS required: {self.config.require_client_cert})"
        )

    def _accept_loop(self, raw_server: socket.socket, ctx: ssl.SSLContext) -> None:
        while self._running:
            try:
                client_sock, client_addr = raw_server.accept()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    logger.error(f"Error accepting connection: {e}")
                break

            # Check max connections limit
            if self.health.active_connections >= self.config.max_connections:
                logger.warning(
                    f"Rejecting connection from {client_addr}: max connections ({self.config.max_connections}) reached."
                )
                try:
                    client_sock.close()
                except Exception:
                    pass
                continue

            t = threading.Thread(
                target=self._handle_client_connection,
                args=(client_sock, client_addr, ctx),
                daemon=True
            )
            with self._lock:
                self._client_threads = [th for th in self._client_threads if th.is_alive()]
                self._client_threads.append(t)
            t.start()

    def _handle_client_connection(
        self,
        raw_sock: socket.socket,
        client_addr: tuple,
        ctx: ssl.SSLContext
    ) -> None:
        """Handles an individual endpoint connection over mTLS."""
        self.health.inc_connection()
        ssl_sock: Optional[ssl.SSLSocket] = None
        client_identity: Dict[str, Any] = {}

        try:
            raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            raw_sock.settimeout(self.config.connection_timeout_seconds)

            # 1. TLS Handshake & Client Certificate Verification
            ssl_sock = ctx.wrap_socket(
                raw_sock,
                server_side=True,
                do_handshake_on_connect=True
            )

            if self.config.require_client_cert:
                peer_cert = ssl_sock.getpeercert()
                client_identity = extract_client_identity(peer_cert)
                cn = client_identity.get("common_name")
                logger.info(f"Accepted mTLS connection from {client_addr} (Authenticated Agent CN: '{cn}')")
            else:
                logger.info(f"Accepted connection from {client_addr} (no client cert required)")

            # 2. Main frame processing loop
            while self._running:
                try:
                    msg_type, payload = read_frame_blocking(
                        ssl_sock,
                        timeout=self.config.connection_timeout_seconds
                    )
                except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
                    logger.debug(f"Client {client_addr} disconnected.")
                    break
                except socket.timeout:
                    logger.debug(f"Client {client_addr} timed out awaiting frame.")
                    break
                except ProtocolError as pe:
                    logger.warning(f"Protocol violation from {client_addr}: {pe}")
                    self.health.record_error()
                    err_frame = FrameEncoder.encode_error(str(pe))
                    try:
                        ssl_sock.sendall(err_frame)
                    except Exception:
                        pass
                    break

                # Dispatch frame type
                self._dispatch_frame(ssl_sock, client_identity, msg_type, payload, client_addr)

        except ssl.SSLCertVerificationError as sve:
            logger.warning(f"Client certificate verification rejected for {client_addr}: {sve}")
            self.health.record_error()
        except AuthenticationError as ae:
            logger.warning(f"Authentication failure for {client_addr}: {ae}")
            self.health.record_error()
        except Exception as e:
            logger.error(f"Unexpected error handling client {client_addr}: {e}")
            self.health.record_error()
        finally:
            self.health.dec_connection()
            if ssl_sock:
                try:
                    ssl_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    ssl_sock.close()
                except Exception:
                    pass
            elif raw_sock:
                try:
                    raw_sock.close()
                except Exception:
                    pass

    def _dispatch_frame(
        self,
        ssl_sock: ssl.SSLSocket,
        client_identity: Dict[str, Any],
        msg_type: int,
        payload: bytes,
        client_addr: tuple
    ) -> None:
        """Processes a single validated frame."""
        if msg_type == MSG_TYPE_PING:
            ssl_sock.sendall(FrameEncoder.encode_pong())
            return

        if msg_type == MSG_TYPE_EVENT_BATCH:
            self._handle_event_batch(ssl_sock, client_identity, payload, client_addr)
            return

        logger.warning(f"Unexpected frame type {hex(msg_type)} from {client_addr}")
        ssl_sock.sendall(FrameEncoder.encode_error(f"Unsupported frame type: {hex(msg_type)}"))

    def _handle_event_batch(
        self,
        ssl_sock: ssl.SSLSocket,
        client_identity: Dict[str, Any],
        payload: bytes,
        client_addr: tuple
    ) -> None:
        """Validates, authorizes, persists, and acknowledges an event batch."""
        raw_size = len(payload)
        batch_id = "unknown"

        try:
            try:
                body = json.loads(payload.decode("utf-8"))
            except Exception as e:
                raise ValidationError(f"Invalid JSON payload: {e}")

            batch_id, claimed_agent_id, events = validate_batch_envelope(body)

            # 1. Authorize: Cryptographic identity binding
            if self.config.require_client_cert:
                authorize_agent(claimed_agent_id, client_identity, self.config.allowed_agents)

            # 2. Schema validation on all events
            for ev in events:
                validate_event_dict(ev)

            # 3. Durable Storage & Deduplication commit
            accepted_ids, duplicate_ids = self.storage.commit_batch(
                batch_id=batch_id,
                agent_id=claimed_agent_id,
                events=events
            )

            # 4. Transmit durable ACK to agent
            ack_frame = FrameEncoder.encode_ack(batch_id, accepted_ids, duplicate_ids)
            ssl_sock.sendall(ack_frame)

            self.health.record_batch(len(events), len(accepted_ids), len(duplicate_ids), raw_size)
            self.health.record_ack()

            logger.info(
                f"Committed batch '{batch_id}' from agent '{claimed_agent_id}': "
                f"{len(accepted_ids)} accepted, {len(duplicate_ids)} duplicates"
            )

        except (ValidationError, AuthorizationError) as err:
            logger.warning(f"Batch '{batch_id}' rejected from {client_addr}: {err}")
            self.health.record_nack()
            try:
                nack_frame = FrameEncoder.encode_nack(batch_id, str(err))
                ssl_sock.sendall(nack_frame)
            except Exception:
                pass

        except Exception as e:
            logger.error(f"Storage error committing batch '{batch_id}': {e}", exc_info=True)
            self.health.record_error()
            self.health.record_nack()
            try:
                nack_frame = FrameEncoder.encode_nack(batch_id, f"Receiver internal storage failure: {e}")
                ssl_sock.sendall(nack_frame)
            except Exception:
                pass

    def stop(self) -> None:
        """Gracefully stops the receiver server."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
            self._server_socket = None

        if self._accept_thread:
            self._accept_thread.join(timeout=2.0)

        logger.info("NIGHTWATCH Receiver mTLS server stopped.")
