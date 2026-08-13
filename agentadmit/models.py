"""
agentadmit.models
-----------------
Pydantic request/response models for AgentAdmit API endpoints.
"""

import re
from datetime import datetime
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field, field_validator


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
# Verify (introspection) response
# ---------------------------------------------------------------------------

class VerifyResponse(BaseModel):
    """Typed view of the hosted POST /api/v1/verify introspection response.

    The SDK's middleware/decorators consume the raw dict internally; this
    model is for integrators who call /verify directly (e.g. STDIO MCP
    servers) and want a typed result. Unknown fields from newer servers are
    ignored, so parsing stays forward-compatible.
    """
    active: bool = Field(False, description="RFC 7662-style active flag. False for invalid/expired/revoked tokens (still HTTP 200).")
    error: Optional[str] = Field(None, description="One of VERIFY_ERROR_CODES when active is false.")
    user_id: Optional[str] = None
    connection_id: Optional[str] = None
    agent_id: Optional[str] = None
    agent_label: Optional[str] = None
    scopes: list[str] = Field(default_factory=list, description="Granted scopes")
    purpose: Optional[str] = Field(
        None,
        description=(
            "Declared purpose: the user-facing reason recorded on the grant at "
            "the consent moment. Review-time record only, never an enforcement "
            "input; authorization decisions ride scopes, connection status, "
            "and consent. Null/absent on older servers and on grants recorded "
            "without one."
        ),
    )
    user_intent: Optional[str] = Field(
        None,
        description=(
            "User-declared intent: the user's own words, typed at the consent "
            "moment (distinct from purpose, which is the app's words). "
            "Review-time record only, never an enforcement input; "
            "authorization decisions ride scopes, connection status, and "
            "consent. Null/absent on older servers and on grants recorded "
            "without one."
        ),
    )
    consent: Optional[dict[str, Any]] = Field(None, description="Consent Ledger verdict, when the platform returns it.")
    presence: Optional[dict[str, Any]] = Field(None, description="Human-presence fact (WebAuthn step-up), when the platform returns it.")


# ---------------------------------------------------------------------------
# App-attested presence (typed forwarding at token issuance)
# ---------------------------------------------------------------------------

_PRESENCE_METHOD_RE = re.compile(r"^[a-z0-9_]+$")


class AppAttestedPresence(BaseModel):
    """A ceremony fact your app attests at token issuance.

    Return an instance from the ``require_token_mint_presence`` hook AFTER
    verifying and consuming your own fresh, purpose-bound WebAuthn/passkey
    attestation. The SDK forwards it to the hosted mint as
    ``presence: {verified: true, uv: true, method, verified_at}``; the hosted
    service stores it method-prefixed ``app:<method>`` — the provenance marker
    that keeps app-attested facts distinct from hosted-witnessed ceremonies.

    Honesty ceiling: this is YOUR attestation, recorded and provenance-marked,
    not witnessed by AgentAdmit and not independently verifiable. Only
    construct one for a ceremony that verified the user with UV (biometric or
    PIN user verification); ``verified``/``uv`` are literal ``True`` — a
    ceremony without UV carries no presence fact, so simply return ``None``.

    ``verified_at`` MUST be timezone-aware (the hosted service rejects naive
    timestamps) and recent — the hosted mint enforces a 10-minute freshness
    window with 60 seconds of future clock-skew slack.
    """

    verified: Literal[True] = True
    uv: Literal[True] = True
    method: str = Field(
        ...,
        min_length=1,
        max_length=60,
        description=(
            "Your ceremony mechanism, lowercase alphanumeric/underscore "
            "(e.g. 'tt_webauthn'). Stored as 'app:<method>'."
        ),
    )
    verified_at: datetime = Field(
        ...,
        description=(
            "When the ceremony completed. Must be timezone-aware; serialized "
            "RFC 3339 with offset. The hosted service enforces freshness "
            "(10 minutes, 60 s future skew)."
        ),
    )

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str) -> str:
        if not _PRESENCE_METHOD_RE.match(v):
            raise ValueError(
                "method must be lowercase alphanumeric/underscore (e.g. 'tt_webauthn')"
            )
        return v

    @field_validator("verified_at")
    @classmethod
    def _require_offset_aware(cls, v: datetime) -> datetime:
        # A naive datetime serializes without an offset and the hosted mint
        # rejects it with 400 — a proven production-outage class. Fail here,
        # at construction, where the fix is obvious.
        if v.tzinfo is None or v.tzinfo.utcoffset(v) is None:
            raise ValueError(
                "verified_at must be timezone-aware (e.g. datetime.now(timezone.utc)); "
                "naive timestamps serialize without an offset and the hosted mint rejects them"
            )
        return v

    def to_wire(self) -> dict[str, Any]:
        """The exact JSON object forwarded to the hosted mint."""
        return {
            "verified": True,
            "uv": True,
            "method": self.method,
            "verified_at": self.verified_at.isoformat(),
        }


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
    purpose: Optional[str] = Field(
        None,
        description=(
            "Declared purpose: the user-facing reason recorded on the grant at "
            "the consent moment (1–300 characters). Review-time record only, "
            "never an enforcement input; authorization decisions ride scopes, "
            "connection status, and consent. Length is enforced by the route "
            "handler (400 invalid_request), and the field is omitted from the "
            "hosted mint call when absent."
        ),
    )
    user_intent: Optional[str] = Field(
        None,
        description=(
            "User-declared intent: the user's own words, typed at the consent "
            "moment (1–300 characters). Distinct from purpose, which is the "
            "app's words. Review-time record only, never an enforcement "
            "input; authorization decisions ride scopes, connection status, "
            "and consent. Length is enforced by the route handler (400 "
            "invalid_request), and the field is omitted from the hosted mint "
            "call when absent."
        ),
    )
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
