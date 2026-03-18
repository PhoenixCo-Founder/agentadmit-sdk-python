"""
agentadmit.auth
---------------
Token validation, scope enforcement, and audit logging.

Generalized from TrainerTracer's agentadmit_auth.py.
All app-specific references removed — works with any FastAPI app.
"""

import logging
from datetime import datetime
from typing import Callable, Optional

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from agentadmit.config import get_config
from agentadmit.keys import load_public_key
from agentadmit.exceptions import (
    InvalidTokenError,
    InsufficientScopeError,
    ConnectionRevokedError,
    ConnectionLimitError,
    ConfigurationError,
)

logger = logging.getLogger(__name__)

# Bearer token extractor
security = HTTPBearer(auto_error=False)

# Storage backend reference — set by middleware during startup
_storage = None

# App's user verification function — set by middleware during startup
# Signature: (token: str) -> str (returns user_id)
_verify_user_token: Optional[Callable] = None


def _set_storage(storage):
    """Called by middleware to inject the storage backend."""
    global _storage
    _storage = storage


def _set_user_verifier(fn: Callable):
    """Called by middleware to inject the app's user token verification function."""
    global _verify_user_token
    _verify_user_token = fn


def _get_storage():
    """Get the storage backend. Raises if not initialized."""
    if _storage is None:
        raise ConfigurationError("AgentAdmit storage not initialized. Did you add AgentAdmitMiddleware?")
    return _storage


# ---------------------------------------------------------------------------
# get_agentadmit_user — primary agent token validation
# ---------------------------------------------------------------------------

def get_agentadmit_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """
    Validates an AgentAdmit access token (ag_at_ prefixed RS256 JWT).

    Validation steps:
      1. Authorization header present
      2. Token starts with ag_at_ prefix
      3. JWT signature valid (RS256)
      4. JWT not expired
      5. Audience matches
      6. Connection record exists with status == "active"
      7. User account exists

    Returns:
        {
            "user": <user document>,
            "connection": <connection document>,
            "scopes": <list[str]>,
        }
    """
    config = get_config()
    storage = _get_storage()

    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": "Authorization header is required"},
        )

    token = credentials.credentials

    # Prefix check
    if not token.startswith(config.token_prefix_access):
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": f"Not an AgentAdmit access token (expected {config.token_prefix_access} prefix)"},
        )

    raw_token = token[len(config.token_prefix_access):]

    # MANDATORY INTROSPECTION — validate via AgentAdmit hosted service
    # No local JWT decode. Every verification call goes through AgentAdmit.
    # This is how we meter usage, seed the marketplace, and enforce billing.
    import requests as _requests

    try:
        verify_response = _requests.post(
            config.agentadmit_verify_url,
            headers={
                "Authorization": f"Bearer {token}",
                "X-App-Id": config.app_id,
                "X-Api-Key": config.api_key,
            },
            timeout=5,
        )
    except _requests.exceptions.RequestException as exc:
        logger.error("AgentAdmit introspection failed (network): %s", exc)
        raise HTTPException(
            status_code=502,
            detail={"error": "introspection_failed", "error_description": "Could not reach AgentAdmit verification service"},
        )

    if verify_response.status_code == 401:
        raise HTTPException(
            status_code=401,
            detail=verify_response.json() if verify_response.headers.get("content-type", "").startswith("application/json") else {"error": "invalid_token", "error_description": "Token validation failed"},
        )

    if verify_response.status_code != 200:
        logger.error("AgentAdmit introspection returned %d: %s", verify_response.status_code, verify_response.text)
        raise HTTPException(
            status_code=502,
            detail={"error": "introspection_failed", "error_description": f"Verification service returned {verify_response.status_code}"},
        )

    introspection_data = verify_response.json()

    # Extract validated data from introspection response
    scopes = introspection_data.get("scopes", [])
    user_id = introspection_data.get("user_id")
    connection_id = introspection_data.get("connection_id")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": "Introspection returned no user"},
        )

    # User lookup from app's local database
    user = storage.get_user(user_id, config.user_lookup_field) if storage else None
    connection = {"connection_id": connection_id, "scopes": scopes, "agent_label": introspection_data.get("agent_label", "Unknown Agent")}

    return {"user": user or {"user_id": user_id}, "connection": connection, "scopes": scopes}


# ---------------------------------------------------------------------------
# require_scope — strict scope enforcement (agent-only endpoints)
# ---------------------------------------------------------------------------

def require_scope(scope: str):
    """
    FastAPI dependency factory. Checks the agent's granted scopes include
    the required scope, then logs access.

    Usage:
        @app.get("/api/orders")
        async def get_orders(agent_ctx=Depends(require_scope("read:orders"))):
            user = agent_ctx["user"]
            ...
    """
    def scope_checker(
        agent_ctx: dict = Depends(get_agentadmit_user),
    ) -> dict:
        granted_scopes = agent_ctx.get("scopes", [])

        if scope not in granted_scopes:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "insufficient_scope",
                    "required_scope": scope,
                    "granted_scopes": granted_scopes,
                    "message": f"This action requires '{scope}' scope. The user can grant additional scopes through the AI Agent Access settings.",
                },
            )

        log_agent_access(agent_ctx=agent_ctx, scope_used=scope)
        return agent_ctx

    return scope_checker


# ---------------------------------------------------------------------------
# require_scope_if_agent — dual-token scope enforcement
# ---------------------------------------------------------------------------

def require_scope_if_agent(scope: str):
    """
    FastAPI dependency factory for dual-token endpoints.

    - Regular user JWT → passes silently (no scope enforcement)
    - AgentAdmit token (ag_at_) → validates and enforces scope

    Usage:
        @app.get("/api/orders")
        async def get_orders(
            auth_ctx=Depends(get_current_user_or_agent),
            _scope=Depends(require_scope_if_agent("read:orders")),
        ):
            user = auth_ctx["user"]
            ...
    """
    config = get_config()

    def scope_checker(
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ) -> Optional[dict]:
        if credentials is None:
            return None

        token = credentials.credentials

        # Not an agent token — regular user, no scope enforcement
        if not token.startswith(config.token_prefix_access):
            return None

        # Agent token — validate and enforce
        agent_ctx = get_agentadmit_user(credentials)
        granted_scopes = agent_ctx.get("scopes", [])

        if scope not in granted_scopes:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "insufficient_scope",
                    "required_scope": scope,
                    "granted_scopes": granted_scopes,
                    "message": f"This action requires '{scope}' scope. The user can grant additional scopes through the AI Agent Access settings.",
                },
            )

        log_agent_access(agent_ctx=agent_ctx, scope_used=scope)
        return agent_ctx

    return scope_checker


# ---------------------------------------------------------------------------
# get_current_user_or_agent — unified dual-token resolver
# ---------------------------------------------------------------------------

def get_current_user_or_agent(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """
    Accepts both regular app JWTs and AgentAdmit tokens.

    - Regular JWT → auth_type="user", scopes=["*"]
    - AgentAdmit token → auth_type="agent", scopes=[granted list]

    The app must provide a user token verifier via AgentAdmitMiddleware(verify_user_token=fn).
    """
    config = get_config()

    if credentials is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = credentials.credentials

    if token.startswith(config.token_prefix_access):
        # AgentAdmit path
        agent_ctx = get_agentadmit_user(credentials)
        return {"auth_type": "agent", **agent_ctx}
    else:
        # Regular user path — delegate to app's verifier
        if _verify_user_token is None:
            raise ConfigurationError(
                "No user token verifier configured. "
                "Pass verify_user_token to AgentAdmitMiddleware."
            )

        try:
            user_id = _verify_user_token(token)
        except Exception:
            raise HTTPException(status_code=401, detail="Invalid or expired authentication token")

        storage = _get_storage()
        user = storage.get_user(user_id, config.user_lookup_field)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return {
            "auth_type": "user",
            "user": user,
            "scopes": ["*"],
            "connection": None,
        }


# ---------------------------------------------------------------------------
# log_agent_access — per-request audit trail
# ---------------------------------------------------------------------------

def log_agent_access(
    agent_ctx: dict,
    scope_used: str,
    resource: str = "",
    method: str = "",
    status_code: int = 200,
) -> None:
    """Write a structured audit entry. Errors are swallowed — must not break API calls."""
    try:
        storage = _get_storage()
        connection = agent_ctx.get("connection") or {}
        user = agent_ctx.get("user") or {}
        config = get_config()

        entry = {
            "timestamp": datetime.utcnow(),
            "connection_id": connection.get("connection_id", "unknown"),
            "user_id": user.get(config.user_lookup_field, "unknown"),
            "scope_used": scope_used,
            "resource": resource,
            "method": method,
            "status_code": status_code,
            "agent_label": connection.get("agent_label", "Unknown Agent"),
            "agent_id": connection.get("agent_id"),
        }

        storage.log_access(entry)

    except Exception as exc:
        logger.error("Failed to write AgentAdmit audit log: %s", exc)


# ---------------------------------------------------------------------------
# check_connection_cap — tier enforcement for new connections
# ---------------------------------------------------------------------------

def check_connection_cap(user_id: str, tier: str) -> None:
    """
    Check if user is at their connection hard cap before allowing a new connection.

    Raises HTTPException 429 if at limit with hard_cap=True.
    """
    from agentadmit.config import get_tier_limits as _get_tier_limits

    limits = _get_tier_limits(tier)
    storage = _get_storage()

    if not limits.get("hard_cap", False):
        return

    connections_limit = limits["connections_limit"]
    active_count = storage.count_active_connections(user_id)

    if active_count >= connections_limit:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "connection_limit_reached",
                "error_description": f"Your {tier} plan allows a maximum of {connections_limit} active agent connections.",
                "connections_used": active_count,
                "connections_limit": connections_limit,
                "tier": tier,
            },
        )
