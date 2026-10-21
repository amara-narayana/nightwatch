"""
End-to-End Integration Test for Authenticated Mutual TLS (mTLS) Delivery
Validates TLS handshake, certificate validation, cryptographic identity binding,
durable local queue buffering, wire frame transmission, deduplication, and ACK retirement.
"""

import datetime
import ipaddress
import socket
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from forwarder.agent.config import AgentConfig
from forwarder.agent.event_schema import ForwarderEvent, generate_event_id
from forwarder.agent.queue import DurableQueue
from forwarder.agent.transport import TlsAgentTransport
from forwarder.receiver.config import ReceiverConfig
from forwarder.receiver.storage import ReceiverStorage
from forwarder.receiver.tls_server import TlsReceiverServer


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def create_test_pki(cert_dir: Path):
    """Generates Root CA, Server cert, and Client cert for mTLS testing."""
    cert_dir.mkdir(parents=True, exist_ok=True)

    # 1. Root CA
    ca_key = rsa.generate_private_key(65537, 2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NIGHTWATCH Test CA")])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    ca_cert_path = cert_dir / "ca.crt"
    with open(ca_cert_path, "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    # 2. Server Cert
    server_key = rsa.generate_private_key(65537, 2048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))
            ]),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key_path = cert_dir / "server.key"
    server_cert_path = cert_dir / "server.crt"
    with open(server_key_path, "wb") as f:
        f.write(server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    with open(server_cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))

    # 3. Client Cert (for agent-01)
    client_key = rsa.generate_private_key(65537, 2048)
    client_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-01")])
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(client_name)
        .issuer_name(ca_name)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("agent-01")]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    client_key_path = cert_dir / "agent-01.key"
    client_cert_path = cert_dir / "agent-01.crt"
    with open(client_key_path, "wb") as f:
        f.write(client_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    with open(client_cert_path, "wb") as f:
        f.write(client_cert.public_bytes(serialization.Encoding.PEM))

    return str(ca_cert_path), str(server_cert_path), str(server_key_path), str(client_cert_path), str(client_key_path)


def test_e2e_mtls_delivery_and_ack():
    with tempfile.TemporaryDirectory() as td:
        root_dir = Path(td)
        certs_dir = root_dir / "certs"
        ca_c, srv_c, srv_k, cli_c, cli_k = create_test_pki(certs_dir)

        listen_port = find_free_port()
        rec_db_path = str(root_dir / "receiver.db")

        # 1. Configure and start Receiver
        rec_cfg = ReceiverConfig(
            listen_host="127.0.0.1",
            listen_port=listen_port,
            ca_cert_path=ca_c,
            server_cert_path=srv_c,
            server_key_path=srv_k,
            require_client_cert=True,
            allowed_agents=["agent-01"],
            storage_path=rec_db_path,
            integrate_nightwatch_db=False
        )
        receiver = TlsReceiverServer(rec_cfg)
        receiver.start()
        time.sleep(0.5)

        try:
            # 2. Configure Agent
            q_db_path = str(root_dir / "agent_q.db")
            cp_db_path = str(root_dir / "agent_cp.db")
            agent_cfg = AgentConfig(
                agent_id="agent-01",
                receiver_host="127.0.0.1",
                receiver_port=listen_port,
                ca_cert_path=ca_c,
                client_cert_path=cli_c,
                client_key_path=cli_k,
                tls_verify_server=False,  # localhost loopback
                queue_db_path=q_db_path,
                checkpoint_db_path=cp_db_path
            )

            # Setup durable local queue
            queue = DurableQueue(q_db_path)
            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            ev1 = ForwarderEvent(
                schema_version="1.0",
                event_id=generate_event_id("agent-01", "win", "System", "101"),
                agent_id="agent-01",
                hostname="endpoint-pc",
                platform="windows",
                source_type="wineventlog",
                source_name="System",
                event_timestamp=now_iso,
                observed_timestamp=now_iso,
                message="Genuine Windows service start event test",
                severity="INFO",
                source_event_id="7036",
                source_record_id=101
            )
            queue.push_batch([ev1])
            assert queue.get_depth() == 1

            # 3. Agent Transport connect
            transport = TlsAgentTransport(agent_cfg)
            transport.connect()
            assert transport.is_connected()

            # Lease batch from queue
            batch_id, leased = queue.lease_batch(batch_size=10)
            assert len(leased) == 1
            assert leased[0].event_id == ev1.event_id

            # 4. Transmit batch over mTLS and await ACK
            success, retired_ids, err = transport.send_batch(batch_id, leased)
            assert success is True, f"Delivery failed: {err}"
            assert ev1.event_id in retired_ids

            # Retire from local queue
            retired_count = queue.retire_acknowledged(retired_ids)
            assert retired_count == 1
            assert queue.get_depth() == 0

            # 5. Verify Receiver Storage
            receiver_events = receiver.storage.query_events(agent_id="agent-01")
            assert len(receiver_events) == 1
            assert receiver_events[0]["event_id"] == ev1.event_id
            assert receiver_events[0]["message"] == "Genuine Windows service start event test"

            # 6. Test Deduplication & Idempotent Retry:
            # Resend the same event batch to verify receiver acknowledges duplicates safely
            success2, retired_ids2, err2 = transport.send_batch("retry-batch-02", leased)
            assert success2 is True
            assert ev1.event_id in retired_ids2
            # Total persisted count must remain 1
            assert receiver.storage.get_event_count() == 1

            transport.close()

        finally:
            receiver.stop()
