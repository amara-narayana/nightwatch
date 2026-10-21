"""
NIGHTWATCH Forwarder Receiver — Client TLS Certificate Authentication
Inspects and extracts authenticated client identity from mutual TLS peer certificates.
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("nightwatch.forwarder.receiver.auth")


class AuthenticationError(Exception):
    """Raised when client certificate authentication fails."""
    pass


def extract_client_identity(peer_cert: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extracts CN and SAN identities from an ssl.getpeercert() dictionary.
    """
    if not peer_cert:
        raise AuthenticationError("No client certificate presented by peer")

    common_name = None
    subject = peer_cert.get("subject", ())
    for rdn in subject:
        for key, value in rdn:
            if key == "commonName":
                common_name = value
                break

    sans: List[str] = []
    san_entries = peer_cert.get("subjectAltName", ())
    for san_type, san_val in san_entries:
        if san_type in ("DNS", "IP Address"):
            sans.append(san_val)

    if not common_name and not sans:
        raise AuthenticationError("Client certificate lacks both Common Name and Subject Alternative Names")

    return {
        "common_name": common_name,
        "sans": sans,
        "serial_number": peer_cert.get("serialNumber"),
        "not_before": peer_cert.get("notBefore"),
        "not_after": peer_cert.get("notAfter"),
        "issuer": peer_cert.get("issuer")
    }
