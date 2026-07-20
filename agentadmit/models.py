"""
agentadmit.models
-----------------
Pydantic request/response models for AgentAdmit API endpoints.
"""

from typing import Any, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Verify (introspection) error codes — returned by the hosted service as
# {"active": false, "error": <code>} with HTTP 200.
# ---------------------------------------------------------------------------

VERIFY_ERROR_CODES = (
    "invalid_token",
    "token_expired",
    "token_revoked",
    "connection_revoked",
    "connection_expired",
    "environment_mismatch",
    "insufficient_scope",
)


# ---------------------------------------------------------------------------
# Token generation (user-authenticated)
# ---------------------------------------------------------------------------

class GenerateTokenRequest(BaseModel):
    """Request body for POST /agentadmit/connections/generate-token"""
    scopes: list[str] = Field(..., description="List of scopes to grant the agent")
    duration_seconds: Optional[int] = Field(
        None,
        description=(
            "Connection duration in seconds (60–31536000). "
            "Omit the field for the AgentAdmit default (30 days). "
            "Pass an explicit null for an until-revoked connection."
        ),
        ge=60,           # min 1 minute (hosted service contract)
        le=31536000,     # max 1 year (hosted service contract)
    )
    label: Optional[str] = Field(None, description="Human-readable label for this connection (e.g. 'MyAssistant — Workout Tracker')")
    presence_attestation_id: Optional[str] = Field(
        None,
        description=(
            "Optional app-origin human-presence attestation handle. The SDK "
            "does not validate this directly; pass require_token_mint_presence "
            "to create_agentadmit_router() to verify and consume it before minting."
        ),
    )
    presence_session_id: Optional[str] = Field(
        None,
        description=(
            "Optional hosted-presence session handle for applications that use "
            "AgentAdmit's hosted ceremony."
        ),
    )


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
    agent_id: Optional[str] = Field(None, description="Agent identifier (e.g., 'my-assistant-v1')")
    agent_label: Optional[str] = Field(None, description="Human-readable agent name (e.g., 'MyAssistant')")
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
