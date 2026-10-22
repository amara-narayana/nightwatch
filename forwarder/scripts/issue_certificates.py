"""
NIGHTWATCH PKI Management & Certificate Tool
Generates Root CA, Server Certificates (with SANs), and Endpoint Agent Certificates
with strict Key Usages and Common Name identity binding using standard cryptography library.

Commands:
  python issue_certificates.py init-ca --out-dir certs/ca
  python issue_certificates.py issue-server --ca-dir certs/ca --out-dir certs/server --hostname localhost --ip 127.0.0.1
  python issue_certificates.py issue-agent --ca-dir certs/ca --out-dir certs/agent --agent-id agent-win-01
"""

import argparse
import datetime
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def generate_rsa_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )


def save_key(key: rsa.RSAPrivateKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # Protect file permissions where applicable
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def save_cert(cert: x509.Certificate, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    try:
        os.chmod(path, 0o644)
    except Exception:
        pass


def cmd_init_ca(args) -> None:
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    key_path = out_dir / "ca.key"
    cert_path = out_dir / "ca.crt"

    if key_path.exists() and not args.force:
        print(f"CA key already exists at {key_path}. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    print("Generating NIGHTWATCH Root CA RSA Private Key...")
    ca_key = generate_rsa_key(4096)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NIGHTWATCH Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, "NIGHTWATCH Root CA"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        )
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
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    save_key(ca_key, key_path)
    save_cert(cert, cert_path)
    print(f"Successfully created Root CA:\n  CA Key:  {key_path}\n  CA Cert: {cert_path}")


def load_ca(ca_dir: Path):
    key_path = ca_dir / "ca.key"
    cert_path = ca_dir / "ca.crt"
    if not key_path.exists() or not cert_path.exists():
        raise FileNotFoundError(f"CA files missing in {ca_dir} (expected ca.key and ca.crt)")

    with open(key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert


def cmd_issue_server(args) -> None:
    ca_dir = Path(args.ca_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    ca_key, ca_cert = load_ca(ca_dir)

    key_path = out_dir / "server.key"
    cert_path = out_dir / "server.crt"

    print("Generating Server RSA Private Key...")
    server_key = generate_rsa_key(2048)

    common_name = args.hostname or "localhost"
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NIGHTWATCH Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Build SANs
    san_list = [x509.DNSName(common_name)]
    if common_name != "localhost":
        san_list.append(x509.DNSName("localhost"))

    if args.ip:
        for ip in args.ip:
            san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
    # Always include 127.0.0.1
    if not any(isinstance(s, x509.IPAddress) and str(s.value) == "127.0.0.1" for s in san_list):
        san_list.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    save_key(server_key, key_path)
    save_cert(cert, cert_path)
    # Also copy or link ca.crt to out_dir for convenience
    save_cert(ca_cert, out_dir / "ca.crt")

    print(f"Successfully issued Receiver Server Certificate (CN: {common_name}):")
    print(f"  Server Key:  {key_path}")
    print(f"  Server Cert: {cert_path}")
    print(f"  CA Cert:     {out_dir / 'ca.crt'}")


def cmd_issue_agent(args) -> None:
    ca_dir = Path(args.ca_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    ca_key, ca_cert = load_ca(ca_dir)

    agent_id = args.agent_id
    key_path = out_dir / f"{agent_id}.key"
    cert_path = out_dir / f"{agent_id}.crt"

    print(f"Generating Endpoint Agent RSA Private Key for '{agent_id}'...")
    agent_key = generate_rsa_key(2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NIGHTWATCH Endpoint"),
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(agent_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=args.days))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(agent_id)]),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )

    save_key(agent_key, key_path)
    save_cert(cert, cert_path)
    save_cert(ca_cert, out_dir / "ca.crt")

    print(f"Successfully issued Endpoint Agent Certificate (CN: {agent_id}):")
    print(f"  Agent Key:  {key_path}")
    print(f"  Agent Cert: {cert_path}")
    print(f"  CA Cert:    {out_dir / 'ca.crt'}")


def create_agent_credentials_pem(ca_dir: Path, agent_id: str, days: int = 365) -> tuple[str, str, str]:
    """Generates and returns (ca_cert_pem, agent_cert_pem, agent_key_pem) as strings."""
    ca_key, ca_cert = load_ca(ca_dir)
    agent_key = generate_rsa_key(2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NIGHTWATCH Endpoint"),
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(agent_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(agent_id)]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    key_pem = agent_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    return ca_pem, cert_pem, key_pem


def ensure_ca_and_server_certs(base_certs_dir: Path = None) -> None:
    """Ensures Root CA and Receiver Server certificates exist, auto-generating them if missing."""
    if base_certs_dir is None:
        base_certs_dir = Path("forwarder/certs")
    ca_dir = base_certs_dir / "ca"
    server_dir = base_certs_dir / "server"

    ca_key = ca_dir / "ca.key"
    ca_crt = ca_dir / "ca.crt"
    if not ca_key.exists() or not ca_crt.exists():
        class MockArgs:
            out_dir = str(ca_dir)
            force = True
        cmd_init_ca(MockArgs)

    server_key = server_dir / "server.key"
    server_crt = server_dir / "server.crt"
    if not server_key.exists() or not server_crt.exists():
        class MockServerArgs:
            ca_dir = str(ca_dir)
            out_dir = str(server_dir)
            hostname = "localhost"
            ip = ["127.0.0.1", "0.0.0.0"]
            days = 825
        cmd_issue_server(MockServerArgs)

    # Ensure server directory has a copy of ca.crt for the receiver
    server_ca_copy = server_dir / "ca.crt"
    if not server_ca_copy.exists() and ca_crt.exists():
        import shutil
        shutil.copy2(ca_crt, server_ca_copy)


def main() -> None:
    parser = argparse.ArgumentParser(description="NIGHTWATCH PKI Certificate Management Utility")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init-ca
    p_ca = subparsers.add_parser("init-ca", help="Initialize Root CA certificate and key")
    p_ca.add_argument("--out-dir", default="forwarder/certs/ca", help="Directory to save CA key and certificate")
    p_ca.add_argument("--force", action="store_true", help="Overwrite existing CA key/cert")

    # issue-server
    p_srv = subparsers.add_parser("issue-server", help="Issue Receiver TLS Server certificate")
    p_srv.add_argument("--ca-dir", default="forwarder/certs/ca", help="Path to CA directory containing ca.key and ca.crt")
    p_srv.add_argument("--out-dir", default="forwarder/certs/server", help="Directory to save server key and cert")
    p_srv.add_argument("--hostname", default="localhost", help="Server primary Common Name / DNS SAN")
    p_srv.add_argument("--ip", action="append", help="Server IP address SAN (repeatable)")
    p_srv.add_argument("--days", type=int, default=825, help="Certificate validity period in days (default: 825)")

    # issue-agent
    p_agt = subparsers.add_parser("issue-agent", help="Issue Endpoint Agent TLS Client certificate")
    p_agt.add_argument("--ca-dir", default="forwarder/certs/ca", help="Path to CA directory containing ca.key and ca.crt")
    p_agt.add_argument("--out-dir", default="forwarder/certs/agent", help="Directory to save agent key and cert")
    p_agt.add_argument("--agent-id", required=True, help="Agent unique identifier (sets cert CN and DNS SAN)")
    p_agt.add_argument("--days", type=int, default=365, help="Certificate validity period in days (default: 365)")

    args = parser.parse_args()
    if args.command == "init-ca":
        cmd_init_ca(args)
    elif args.command == "issue-server":
        cmd_issue_server(args)
    elif args.command == "issue-agent":
        cmd_issue_agent(args)


if __name__ == "__main__":
    main()
