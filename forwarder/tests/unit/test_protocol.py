"""
Unit Tests for Binary Protocol Framing & Stream Buffer
"""

import json
import pytest

from forwarder.receiver.protocol import (
    FrameEncoder,
    MAGIC,
    MAX_FRAME_SIZE,
    MSG_TYPE_ACK_BATCH,
    MSG_TYPE_EVENT_BATCH,
    MSG_TYPE_PING,
    MSG_TYPE_PONG,
    ProtocolError,
    StreamBuffer,
)


def test_frame_encode_and_stream_buffer():
    # Encode an ACK frame
    accepted = ["id-1", "id-2"]
    encoded = FrameEncoder.encode_ack(batch_id="batch-01", accepted_ids=accepted)
    assert encoded.startswith(b"NW")

    # Reassemble using StreamBuffer
    buf = StreamBuffer()
    buf.append(encoded)
    frame = buf.extract_frame()
    assert frame is not None
    msg_type, payload = frame
    assert msg_type == MSG_TYPE_ACK_BATCH

    data = json.loads(payload.decode("utf-8"))
    assert data["batch_id"] == "batch-01"
    assert data["accepted_event_ids"] == accepted


def test_stream_buffer_partial_chunks():
    encoded = FrameEncoder.encode_ping()
    assert len(encoded) == 12  # 8 byte header + 4 byte b'PING'

    buf = StreamBuffer()
    # Feed 1 byte at a time
    for i in range(len(encoded) - 1):
        buf.append(encoded[i:i+1])
        assert buf.extract_frame() is None

    # Feed last byte
    buf.append(encoded[-1:])
    frame = buf.extract_frame()
    assert frame is not None
    msg_type, payload = frame
    assert msg_type == MSG_TYPE_PING
    assert payload == b"PING"


def test_stream_buffer_multiple_frames_in_one_chunk():
    f1 = FrameEncoder.encode_ping()
    f2 = FrameEncoder.encode_pong()

    buf = StreamBuffer()
    buf.append(f1 + f2)

    frame1 = buf.extract_frame()
    assert frame1 is not None and frame1[0] == MSG_TYPE_PING

    frame2 = buf.extract_frame()
    assert frame2 is not None and frame2[0] == MSG_TYPE_PONG

    # Buffer should now be empty
    assert buf.extract_frame() is None


def test_protocol_invalid_magic():
    bad_frame = b"XX\x01\x04\x00\x00\x00\x04PING"
    buf = StreamBuffer()
    buf.append(bad_frame)
    with pytest.raises(ProtocolError, match="Invalid protocol magic"):
        buf.extract_frame()


def test_oversized_payload_rejection():
    with pytest.raises(ProtocolError, match="exceeds limit"):
        FrameEncoder.encode_frame(MSG_TYPE_EVENT_BATCH, b"X" * (MAX_FRAME_SIZE + 1))
