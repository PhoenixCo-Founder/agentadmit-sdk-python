"""
agentadmit.keys
---------------
DEPRECATED — AgentAdmit is a hosted service. All token signing and key
management is handled by the hosted service at api.agentadmit.com.

The SDK does NOT need local RSA keys. This module exists only for backward
compatibility and will be removed in a future version.

Developers should NOT generate, store, or manage RSA keys locally.
"""

import logging

logger = logging.getLogger(__name__)


def generate_key_pair(output_dir: str = "keys") -> tuple[str, str]:
    """DEPRECATED — AgentAdmit hosted service manages all keys."""
    raise NotImplementedError(
        "Local key generation is not supported. AgentAdmit is a hosted service — "
        "all token signing is handled by api.agentadmit.com. "
        "Remove private_key_path and public_key_path from your agentadmit.yaml."
    )


def load_private_key(path: str = "") -> str:
    """DEPRECATED — AgentAdmit hosted service manages all keys."""
    logger.warning(
        "load_private_key() called but AgentAdmit is a hosted service. "
        "Local keys are not needed. Remove private_key_path from agentadmit.yaml."
    )
    return ""


def load_public_key(path: str = "") -> str:
    """DEPRECATED — AgentAdmit hosted service manages all keys."""
    logger.warning(
        "load_public_key() called but AgentAdmit is a hosted service. "
        "Local keys are not needed. Remove public_key_path from agentadmit.yaml."
    )
    return ""
