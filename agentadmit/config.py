"""
agentadmit.config
-----------------
Configuration loader for the AgentAdmit SDK.

App owners define their scopes, durations, tiers, and settings in agentadmit.yaml.
This module loads that config and makes it available to the rest of the SDK.
"""

import os
import logging
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic models for config validation
# ---------------------------------------------------------------------------

class ScopeDefinition(BaseModel):
    """A single scope definition."""
    name: str                    # e.g., "read:orders"
    description: str             # e.g., "View order history and delivery status"
    category: str = "General"    # e.g., "Shopping", "Business", "Admin"
    role: str = "user"           # e.g., "user", "admin", "trainer", etc.


class DurationOption(BaseModel):
    """A connection duration option."""
    label: str                   # e.g., "1 Hour", "Until I Revoke"
    seconds: Optional[int] = None  # None = "until revoked" (no expiry)


class TierDefinition(BaseModel):
    """A subscription tier with connection and API call limits."""
    name: str                         # e.g., "trial", "standard", "enterprise"
    connections_limit: int = 100      # max active connections
    api_calls_monthly: int = 2000000  # max API verification calls per month
    hard_cap: bool = False            # if True, block at limit. if False, allow overage.
    overage_per_thousand: float = 0.50  # overage cost per 1K calls


class StorageConfig(BaseModel):
    """Database/storage configuration."""
    backend: str = "mongodb"     # "mongodb", "postgresql", "sqlite", "memory"
    uri: str = ""                # connection string
    database: str = "agentadmit"
    # Collection/table names (customizable)
    connections_collection: str = "agentadmit_connections"
    audit_log_collection: str = "agentadmit_audit_log"
    tokens_collection: str = "agentadmit_tokens"


class AgentAdmitConfig(BaseModel):
    """Root configuration for the AgentAdmit SDK."""
    # App identity
    app_name: str = "My App"
    app_id: str = ""
    api_base_url: str = ""       # e.g., "https://api.myapp.com"

    # Hosted service connection (REQUIRED — no self-hosted mode)
    agentadmit_api_url: str = "https://api.agentadmit.com"
    agentadmit_verify_url: str = "https://api.agentadmit.com/api/v1/verify"
    api_key: str = ""  # aa_live_xxxx or aa_test_xxxx — from AgentAdmit dashboard

    # Keys (managed by AgentAdmit — app owner does NOT generate these)
    # Only used internally by the SDK for hosted service communication
    private_key_path: str = ""  # Not used in hosted mode — AgentAdmit holds the keys
    public_key_path: str = ""   # Not used in hosted mode — validation via introspection

    # Token settings
    token_prefix_connection: str = "ag_ct_"
    token_prefix_access: str = "ag_at_"
    algorithm: str = "RS256"
    audience: str = "agentadmit"
    connection_token_ttl: int = 900  # 15 minutes for connection tokens

    # Scopes
    scopes: list[ScopeDefinition] = Field(default_factory=list)

    # Duration options
    durations: list[DurationOption] = Field(default_factory=lambda: [
        DurationOption(label="1 Hour", seconds=3600),
        DurationOption(label="24 Hours", seconds=86400),
        DurationOption(label="7 Days", seconds=604800),
        DurationOption(label="30 Days", seconds=2592000),
        DurationOption(label="Until I Revoke", seconds=None),
    ])

    # Tiers
    tiers: list[TierDefinition] = Field(default_factory=lambda: [
        TierDefinition(name="trial", connections_limit=3, hard_cap=True),
        TierDefinition(name="standard", connections_limit=100, api_calls_monthly=2000000),
    ])
    default_tier: str = "standard"

    # Storage
    storage: StorageConfig = Field(default_factory=StorageConfig)

    # Route prefix for AgentAdmit endpoints
    route_prefix: str = "/agentadmit"

    # Discovery
    discovery_path: str = "/.well-known/agentadmit"

    # Introspection (hosted service)
    introspection_url: Optional[str] = None  # if set, validates via hosted service instead of local

    # User lookup function name (app provides this)
    user_lookup_field: str = "user_id"  # the field in your users table/collection that matches JWT sub

    # Rate limiting — introspection retry policy
    max_retries: int = 3  # max retries on 429 before raising RateLimitError

    @field_validator("api_key")
    @classmethod
    def _validate_api_key_prefix(cls, v: str) -> str:
        if v and not (v.startswith("aa_test_") or v.startswith("aa_live_")):
            # Never echo the key itself.
            raise ValueError("api_key must start with 'aa_test_' or 'aa_live_'")
        return v


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

_config: Optional[AgentAdmitConfig] = None


def load_config(path: str = "agentadmit.yaml") -> AgentAdmitConfig:
    """
    Load AgentAdmit configuration from a YAML file.

    Args:
        path: Path to the YAML config file. Default: agentadmit.yaml in cwd.

    Returns:
        AgentAdmitConfig instance.

    Raises:
        ConfigurationError if the file doesn't exist or is invalid.
    """
    global _config

    config_path = Path(path)
    if not config_path.exists():
        # Check environment variable
        env_path = os.environ.get("AGENTADMIT_CONFIG")
        if env_path:
            config_path = Path(env_path)

    if not config_path.exists():
        from agentadmit.exceptions import ConfigurationError
        raise ConfigurationError(
            f"Config file not found: {path}. "
            "Run 'agentadmit init' to generate one, or set AGENTADMIT_CONFIG env var."
        )

    with open(config_path) as f:
        raw = yaml.safe_load(f) or {}

    # Parse scopes from simplified YAML format
    if "scopes" in raw and isinstance(raw["scopes"], list):
        parsed_scopes = []
        for s in raw["scopes"]:
            if isinstance(s, dict):
                parsed_scopes.append(ScopeDefinition(**s))
            elif isinstance(s, str):
                # Simple string format: "read:orders" -> auto-generate description
                parsed_scopes.append(ScopeDefinition(
                    name=s,
                    description=s.replace(":", " ").replace("_", " ").title(),
                ))
        raw["scopes"] = parsed_scopes

    # Parse durations
    if "durations" in raw and isinstance(raw["durations"], list):
        parsed = []
        for d in raw["durations"]:
            if isinstance(d, dict):
                parsed.append(DurationOption(**d))
        raw["durations"] = parsed

    # Parse tiers
    if "tiers" in raw and isinstance(raw["tiers"], list):
        parsed = []
        for t in raw["tiers"]:
            if isinstance(t, dict):
                parsed.append(TierDefinition(**t))
        raw["tiers"] = parsed

    # Parse storage
    if "storage" in raw and isinstance(raw["storage"], dict):
        raw["storage"] = StorageConfig(**raw["storage"])

    _config = AgentAdmitConfig(**raw)
    logger.info("AgentAdmit config loaded: %s (%d scopes)", config_path, len(_config.scopes))
    return _config


def get_config() -> AgentAdmitConfig:
    """Get the loaded config. Raises if not loaded yet."""
    global _config
    if _config is None:
        from agentadmit.exceptions import ConfigurationError
        raise ConfigurationError("AgentAdmit config not loaded. Call load_config() first.")
    return _config


def get_scope_metadata() -> list[dict]:
    """Return scope definitions as dicts for the /scopes endpoint."""
    config = get_config()
    return [s.model_dump() for s in config.scopes]


def get_tier_limits(tier_name: str) -> dict:
    """Get limits for a specific tier."""
    config = get_config()
    for t in config.tiers:
        if t.name == tier_name:
            return t.model_dump()
    # Fallback to default tier
    for t in config.tiers:
        if t.name == config.default_tier:
            return t.model_dump()
    return {"connections_limit": 100, "hard_cap": False}


def get_duration_options() -> list[dict]:
    """Return duration options as dicts for the frontend."""
    config = get_config()
    return [d.model_dump() for d in config.durations]
