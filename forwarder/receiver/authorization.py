"""
NIGHTWATCH Forwarder Receiver — Agent Authorization Engine
Enforces cryptographic identity binding: ensures claimed agent_id matches client certificate CN/SAN
and validates agent against the explicit allowlist policy.
"""

import logging
from typing import Any, Dict, List

logger = logging.getLogger("nightwatch.forwarder.receiver.authz")


class AuthorizationError(Exception):
    """Raised when an authenticated agent is not authorized to transmit telemetry."""
    pass


def authorize_agent(
    claimed_agent_id: str,
    client_identity: Dict[str, Any],
    allowed_agents: List[str]
) -> None:
    """
    Validates identity binding and authorization allowlist.
    """
    cn = client_identity.get("common_name")
    sans = client_identity.get("sans", [])

    # 1. Identity Binding: claimed agent_id must match cert CN or one of the SANs
    valid_names = set([cn] + sans) if cn else set(sans)
    if claimed_agent_id not in valid_names:
        logger.warning(
            f"SECURITY: Identity mismatch! Claimed agent_id '{claimed_agent_id}' does not match "
            f"certificate CN '{cn}' or SANs {sans}"
        )
        raise AuthorizationError(
            f"Forbidden: Claimed agent_id '{claimed_agent_id}' does not match client certificate identity"
        )

    # 2. Allowlist Policy check (if configured)
    if allowed_agents:
        if claimed_agent_id not in allowed_agents:
            logger.warning(
                f"SECURITY: Agent '{claimed_agent_id}' is not in configured allowed_agents allowlist"
            )
            raise AuthorizationError(
                f"Unauthorized: Agent '{claimed_agent_id}' is not permitted by receiver policy"
            )

    logger.debug(f"Agent '{claimed_agent_id}' authorized successfully.")
