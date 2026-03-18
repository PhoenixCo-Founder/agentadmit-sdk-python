"""
agentadmit.keys
---------------
RS256 key pair generation and loading for token signing/verification.
"""

import os
import logging
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger(__name__)

# Cache loaded keys
_private_key: Optional[str] = None
_public_key: Optional[str] = None


def generate_key_pair(output_dir: str = "keys") -> tuple[str, str]:
    """
    Generate an RS256 key pair and save to files.

    Args:
        output_dir: Directory to save the key files. Created if it doesn't exist.

    Returns:
        Tuple of (private_key_path, public_key_path)
    """
    keys_dir = Path(output_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)

    private_path = keys_dir / "agentadmit_private.pem"
    public_path = keys_dir / "agentadmit_public.pem"

    # Generate 2048-bit RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Serialize private key (PEM, no encryption)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key (PEM)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    # Set restrictive permissions on private key
    os.chmod(private_path, 0o600)

    logger.info("Generated AgentAdmit RS256 key pair in %s", keys_dir)
    return str(private_path), str(public_path)


def load_private_key(path: str = "keys/agentadmit_private.pem") -> str:
    """Load the private key from file or environment variable."""
    global _private_key
    if _private_key:
        return _private_key

    # Try environment variable first
    env_key = os.environ.get("AGENTADMIT_PRIVATE_KEY")
    if env_key:
        _private_key = env_key
        return _private_key

    key_path = Path(path)
    if not key_path.exists():
        from agentadmit.exceptions import ConfigurationError
        raise ConfigurationError(
            f"Private key not found at {path}. "
            "Run 'agentadmit init' to generate keys, "
            "or set AGENTADMIT_PRIVATE_KEY environment variable."
        )

    _private_key = key_path.read_text()
    return _private_key


def load_public_key(path: str = "keys/agentadmit_public.pem") -> str:
    """Load the public key from file or environment variable."""
    global _public_key
    if _public_key:
        return _public_key

    # Try environment variable first
    env_key = os.environ.get("AGENTADMIT_PUBLIC_KEY")
    if env_key:
        _public_key = env_key
        return _public_key

    key_path = Path(path)
    if not key_path.exists():
        from agentadmit.exceptions import ConfigurationError
        raise ConfigurationError(
            f"Public key not found at {path}. "
            "Run 'agentadmit init' to generate keys, "
            "or set AGENTADMIT_PUBLIC_KEY environment variable."
        )

    _public_key = key_path.read_text()
    return _public_key
