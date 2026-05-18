"""
agentadmit.models
-----------------
Pydantic request/response models for AgentAdmit API endpoints.
"""

from typing import Any, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Token generation (user-authenticated)
# ---------------------------------------------------------------------------

class GenerateTokenRequest(BaseModel):
    """Request body for POST /agentadmit/connections/generate-token"""
    scopes: list[str] = Field(..., description="List of scopes to grant the agent")
    duration_seconds: Optional[int] = Field(
        None,
        description="How long the access token should last (seconds). None = use default.",
        ge=300,          # min 5 minutes
        le=315360000,    # max ~10 years
    )
    label: Optional[str] = Field(None, description="Human-readable label for this connection (e.g. 'Phoenix — Workout Tracker')")


class GenerateTokenResponse(BaseModel):
    """Response for POST /agentadmit/connections/generate-token"""
    connection_token: str = Field(..., description="The ag_ct_ token to give to your agent")
    expires_in: int = Field(..., description="Seconds until this connection token expires (use it before then)")
    scopes: list[str] = Field(..., description="Scopes that will be granted upon exchange")


# ---------------------------------------------------------------------------
# Token exchange (agent-facing, no auth required)
# ---------------------------------------------------------------------------

class TokenExchangeRequest(BaseModel):
    """Request body for POST /agentadmit/token"""
    grant_type: str = Field(
        ...,
        description="Must be 'connection_token'",
        pattern="^connection_token$",
    )
    connection_token: Optional[str] = Field(
        None,
        description="The ag_ct_ connection token received from the user",
    )
    agent_id: Optional[str] = Field(None, description="Agent identifier (e.g., 'openclaw-main')")
    agent_label: Optional[str] = Field(None, description="Human-readable agent name (e.g., 'Phoenix')")
    agent_metadata: Optional[dict[str, Any]] = Field(None, description="Optional agent metadata")


class TokenExchangeResponse(BaseModel):
    """Response for POST /agentadmit/token"""
    access_token: str = Field(..., description="The ag_at_ access token for API access")
    token_type: str = Field(default="bearer")
    expires_in: int = Field(..., description="Seconds until this access token expires")
    scopes: list[str] = Field(..., description="Granted scopes")
    role: str = Field(..., description="User's role in the app")
    connection_id: str = Field(..., description="Unique connection identifier")
    app_name: str = Field(..., description="Name of the app")
    api_base_url: str = Field(..., description="Base URL for API requests")
    endpoints: Optional[list[dict]] = Field(None, description="Available endpoints for granted scopes")


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

class RevokeRequest(BaseModel):
    """Request body for POST /agentadmit/revoke"""
    reason: Optional[str] = Field(default="user_requested", description="Reason for revocation")


class RevokeResponse(BaseModel):
    """Response for POST /agentadmit/revoke and DELETE /agentadmit/connections/{id}"""
    revoked: bool = Field(..., description="Whether the connection was successfully revoked")
    connection_id: str = Field(..., description="The revoked connection ID")


# ---------------------------------------------------------------------------
# Connections list
# ---------------------------------------------------------------------------

class ConnectionInfo(BaseModel):
    """A single connection in the connections list."""
    connection_id: str
    scopes: list[str]
    role: str
    agent_label: Optional[str] = None
    label: Optional[str] = None  # Alias for agent_label — both are returned for frontend compatibility
    agent_id: Optional[str] = None
    status: str
    created_at: Optional[str] = None
    last_used: Optional[str] = None
    expires_at: Optional[str] = None
    duration_seconds: Optional[int] = None


# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------

class UsageSummary(BaseModel):
    """Current billing period usage."""
    tier: str
    billing_period_start: str
    billing_period_end: str
    api_calls_used: int
    api_calls_limit: int
    active_connections: int
    connections_limit: int
