"""
NIGHTWATCH Forwarder Protocol & Binary Wire Framing
Defines the binary length-prefixed protocol over TCP/TLS:
  [2B Magic b'NW'] [1B Version 0x01] [1B Type] [4B Length uint32-BE] [Payload...]
"""

import json
import struct
from typing import Any, Dict, List, Optional, Tuple

MAGIC = b"NW"
VERSION = 0x01

# Message Types
MSG_TYPE_EVENT_BATCH = 0x01  # Agent -> Receiver
MSG_TYPE_ACK_BATCH   = 0x02  # Receiver -> Agent
MSG_TYPE_NACK_BATCH  = 0x03  # Receiver -> Agent
MSG_TYPE_PING        = 0x04  # Agent -> Receiver
MSG_TYPE_PONG        = 0x05  # Receiver -> Agent
MSG_TYPE_ERROR       = 0xFF  # Either -> Either

HEADER_STRUCT = ">2sBBI"  # Magic(2s), Version(B), MsgType(B), Length(I)
HEADER_SIZE = struct.calcsize(HEADER_STRUCT)  # 8 bytes

MAX_FRAME_SIZE = 4 * 1024 * 1024  # 4 MB max frame size


class ProtocolError(Exception):
    """Raised when encountering protocol violation, bad framing, or invalid magic."""
    pass


class FrameEncoder:
    """Encodes messages into length-prefixed binary frames."""

    @staticmethod
    def encode_frame(msg_type: int, payload_bytes: bytes) -> bytes:
        payload_len = len(payload_bytes)
        if payload_len > MAX_FRAME_SIZE:
            raise ProtocolError(f"Payload size ({payload_len} bytes) exceeds limit ({MAX_FRAME_SIZE} bytes)")
        header = struct.pack(HEADER_STRUCT, MAGIC, VERSION, msg_type, payload_len)
        return header + payload_bytes

    @classmethod
    def encode_event_batch(cls, batch_id: str, agent_id: str, events: List[Dict[str, Any]]) -> bytes:
        body = {
            "batch_id": batch_id,
            "agent_id": agent_id,
            "count": len(events),
            "events": events
        }
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        return cls.encode_frame(MSG_TYPE_EVENT_BATCH, payload)

    @classmethod
    def encode_ack(cls, batch_id: str, accepted_ids: List[str], duplicate_ids: Optional[List[str]] = None) -> bytes:
        body = {
            "batch_id": batch_id,
            "status": "ACK",
            "accepted_event_ids": accepted_ids,
            "duplicate_event_ids": duplicate_ids or []
        }
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        return cls.encode_frame(MSG_TYPE_ACK_BATCH, payload)

    @classmethod
    def encode_nack(cls, batch_id: str, error: str, rejected_ids: Optional[List[str]] = None) -> bytes:
        body = {
            "batch_id": batch_id,
            "status": "NACK",
            "error": error,
            "rejected_event_ids": rejected_ids or []
        }
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        return cls.encode_frame(MSG_TYPE_NACK_BATCH, payload)

    @classmethod
    def encode_ping(cls) -> bytes:
        return cls.encode_frame(MSG_TYPE_PING, b"PING")

    @classmethod
    def encode_pong(cls) -> bytes:
        return cls.encode_frame(MSG_TYPE_PONG, b"PONG")

    @classmethod
    def encode_error(cls, message: str) -> bytes:
        payload = json.dumps({"error": message}).encode("utf-8")
        return cls.encode_frame(MSG_TYPE_ERROR, payload)


class StreamBuffer:
    """
    Manages partial byte reception from a non-blocking or blocking TCP stream,
    reassembling complete frames with zero framing boundary leaks.
    """

    def __init__(self):
        self._buffer = bytearray()

    def append(self, data: bytes) -> None:
        self._buffer.extend(data)

    def extract_frame(self) -> Optional[Tuple[int, bytes]]:
        """
        Extracts one complete frame from buffer if available.
        Returns (msg_type, payload_bytes) or None if more data is needed.
        """
        if len(self._buffer) < HEADER_SIZE:
            return None

        # Peek header
        magic, version, msg_type, payload_len = struct.unpack_from(HEADER_STRUCT, self._buffer, 0)

        if magic != MAGIC:
            raise ProtocolError(f"Invalid protocol magic: {magic!r}. Expected {MAGIC!r}")

        if version != VERSION:
            raise ProtocolError(f"Unsupported protocol version: {version}. Expected {VERSION}")

        if payload_len > MAX_FRAME_SIZE:
            raise ProtocolError(f"Frame length {payload_len} exceeds max size {MAX_FRAME_SIZE}")

        total_frame_len = HEADER_SIZE + payload_len
        if len(self._buffer) < total_frame_len:
            # Need more bytes from network
            return None

        # Complete frame available
        payload_bytes = bytes(self._buffer[HEADER_SIZE:total_frame_len])
        del self._buffer[:total_frame_len]
        return msg_type, payload_bytes


def read_frame_blocking(sock, timeout: float = 30.0) -> Tuple[int, bytes]:
    """
    Reads exactly one complete frame from a blocking socket, handling partial reads.
    Raises ProtocolError on bad framing, socket.timeout on timeout, ConnectionError on EOF.
    """
    import socket
    sock.settimeout(timeout)

    # 1. Read header (8 bytes)
    header_bytes = bytearray()
    while len(header_bytes) < HEADER_SIZE:
        chunk = sock.recv(HEADER_SIZE - len(header_bytes))
        if not chunk:
            raise ConnectionResetError("Connection closed while awaiting frame header")
        header_bytes.extend(chunk)

    magic, version, msg_type, payload_len = struct.unpack(HEADER_STRUCT, bytes(header_bytes))
    if magic != MAGIC:
        raise ProtocolError(f"Invalid protocol magic: {magic!r}")
    if version != VERSION:
        raise ProtocolError(f"Unsupported protocol version: {version}")
    if payload_len > MAX_FRAME_SIZE:
        raise ProtocolError(f"Payload length {payload_len} exceeds max {MAX_FRAME_SIZE}")

    # 2. Read exact payload bytes
    payload_bytes = bytearray()
    while len(payload_bytes) < payload_len:
        needed = payload_len - len(payload_bytes)
        chunk = sock.recv(min(needed, 65536))
        if not chunk:
            raise ConnectionResetError("Connection closed while reading frame payload")
        payload_bytes.extend(chunk)

    return msg_type, bytes(payload_bytes)
