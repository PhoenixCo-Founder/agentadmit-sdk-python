"""
agentadmit.auth
---------------
Token validation, scope enforcement, and audit logging.

Generalized from TrainerTracer's agentadmit_auth.py.
All app-specific references removed — works with any FastAPI app.
"""

import logging
import random
import time
from datetime import datetime
from typing import Callable, Optional

import httpx
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
    RateLimitError,
)

logger = logging.getLogger(__name__)

# Hard cap on any single retry wait — including a server-supplied Retry-After.
MAX_RETRY_WAIT_SECONDS = 30.0
# Hard cap on cumulative wait across all retries of a single verify call.
MAX_RETRY_BUDGET_SECONDS = 120.0

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
# _introspect_with_retry — HTTP call with 429 exponential backoff + jitter
# ---------------------------------------------------------------------------

def _introspect_with_retry(
    url: str,
    token: str,
    app_id: str,
    api_key: str,
    timeout: int = 5,
    max_retries: int = 3,
) -> "httpx.Response":
    """
    POST to the AgentAdmit introspection endpoint with automatic 429 retry.

    Retry policy:
      - Initial delay: 1 second
      - Each retry doubles the delay (exponential backoff), capped at 30 seconds
      - Each delay adds 0–500 ms of random jitter
      - Honors Retry-After header if present, capped at 30 seconds
        (Retry-After is untrusted server input and must not pin the caller)
      - Cumulative wait across retries is capped at 120 seconds
      - After max_retries or the wait budget is exhausted on 429, raises
        RateLimitError

    Returns the successful Response object (status 200 or non-429 error).
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {"token": token}

    delay = 1.0  # seconds — initial backoff
    waited = 0.0  # cumulative wait across retries

    for attempt in range(max_retries + 1):
        try:
            response = httpx.post(url, headers=headers, json=payload, timeout=timeout)
        except httpx.HTTPError as exc:
            logger.error("AgentAdmit introspection failed (network): %s", exc)
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "introspection_failed",
                    "error_description": "Could not reach AgentAdmit verification service",
                },
            )

        if response.status_code != 429:
            return response

        # --- 429 handling ---
        # Parse rate-limit headers for error context
        rl_limit = _parse_int_header(response, "X-RateLimit-Limit")
        rl_remaining = _parse_int_header(response, "X-RateLimit-Remaining")
        rl_reset = _parse_int_header(response, "X-RateLimit-Reset")
        retry_after_hdr = _parse_float_header(response, "Retry-After")

        if attempt >= max_retries:
            # All retries exhausted — raise RateLimitError
            raise RateLimitError(
                message=(
                    f"AgentAdmit rate limit exceeded. "
                    f"Max retries ({max_retries}) exhausted."
                ),
                retry_after=retry_after_hdr,
                limit=rl_limit,
                remaining=rl_remaining,
                reset=rl_reset,
            )

        # Compute wait time: Retry-After beats exponential backoff, but both
        # are capped — Retry-After is untrusted server input.
        requested = retry_after_hdr if retry_after_hdr is not None else delay
        wait = min(max(0.0, requested), MAX_RETRY_WAIT_SECONDS)
        jitter = random.uniform(0, 0.5)  # 0–500 ms
        wait_total = wait + jitter

        if waited + wait_total > MAX_RETRY_BUDGET_SECONDS:
            raise RateLimitError(
                message=(
                    f"AgentAdmit rate limit retry budget "
                    f"({MAX_RETRY_BUDGET_SECONDS:.0f}s) exhausted."
                ),
                retry_after=retry_after_hdr,
                limit=rl_limit,
                remaining=rl_remaining,
                reset=rl_reset,
            )
        waited += wait_total

        logger.warning(
            "AgentAdmit introspection rate-limited (attempt %d/%d). "
            "Retrying in %.2fs (delay=%.1fs, jitter=%.3fs).",
            attempt + 1,
            max_retries,
            wait_total,
            wait,
            jitter,
        )

        time.sleep(wait_total)
        delay = min(delay * 2, 30.0)  # double for next attempt, cap at 30s

    # Should never be reached
    raise RuntimeError("Unexpected exit from retry loop")  # pragma: no cover


def _parse_int_header(response: "httpx.Response", name: str) -> Optional[int]:
    """Parse an integer HTTP response header, returning None if missing or invalid."""
    val = response.headers.get(name)
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_float_header(response: "httpx.Response", name: str) -> Optional[float]:
    """Parse a float HTTP response header, returning None if missing or invalid."""
    val = response.headers.get(name)
    if val is None:
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


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

    max_retries = getattr(config, "max_retries", 3)
    try:
        verify_response = _introspect_with_retry(
            url=config.agentadmit_verify_url,
            token=token,
            app_id=config.app_id,
            api_key=config.api_key,
            timeout=5,
            max_retries=max_retries,
        )
    except RateLimitError:
        raise  # Let RateLimitError propagate as-is for caller to handle

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

    # Check active flag (RFC 7662 introspection pattern).
    # The verify endpoint returns {active: false} with HTTP 200 for invalid/
    # expired/revoked tokens. Without this check, we'd read empty scopes.
    # The error code is one of VERIFY_ERROR_CODES (e.g. token_expired,
    # connection_expired, environment_mismatch); unknown codes pass through.
    #
    # IMPORTANT: active must be the boolean True — not just truthy. A crafted
    # response {"active": 1} or {"active": "yes"} must not bypass this check.
    if introspection_data.get("active") is not True:
        reason = introspection_data.get("error", "invalid_token")
        raise HTTPException(
            status_code=403 if reason == "insufficient_scope" else 401,
            detail={"error": reason, "error_description": f"Token is not active: {reason}"},
        )

    # --- M5: Validate introspection response field types ---
    # A malicious introspection response (e.g. {"active":true,"user_id":{"$ne":null}})
    # can inject arbitrary values into downstream Mongo queries.
    # Reject any response where the fields the SDK consumes are not the expected types.
    user_id = introspection_data.get("user_id")
    connection_id = introspection_data.get("connection_id")
    agent_id = introspection_data.get("agent_id")
    scopes = introspection_data.get("scopes", [])

    type_errors = []
    if user_id is not None and not isinstance(user_id, str):
        type_errors.append(f"user_id must be str, got {type(user_id).__name__}")
    if connection_id is not None and not isinstance(connection_id, str):
        type_errors.append(f"connection_id must be str, got {type(connection_id).__name__}")
    if agent_id is not None and not isinstance(agent_id, str):
        type_errors.append(f"agent_id must be str, got {type(agent_id).__name__}")
    if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
        type_errors.append("scopes must be a list of str")

    if type_errors:
        logger.warning(
            "AgentAdmit introspection response failed type validation: %s",
            "; ".join(type_errors),
        )
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": "Introspection response failed type validation"},
        )

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail={"error": "invalid_token", "error_description": "Introspection returned no user"},
        )

    # User lookup from app's local database.
    # Guard: user_id is guaranteed str at this point (type-checked above).
    if not isinstance(user_id, str):
        raise HTTPException(  # pragma: no cover — belt-and-suspenders guard
            status_code=401,
            detail={"error": "invalid_token", "error_description": "user_id must be a string"},
        )
    user = storage.get_user(user_id, config.user_lookup_field) if storage else None
    connection = {"connection_id": connection_id, "scopes": scopes, "agent_label": introspection_data.get("agent_label", "Unknown Agent")}

    context = {"user": user or {"user_id": user_id}, "connection": connection, "scopes": scopes}

    # Consent Ledger verdict rides along when the platform returns it (additive).
    consent = introspection_data.get("consent")
    if isinstance(consent, dict) and isinstance(consent.get("granted"), bool):
        context["consent"] = consent

    return context


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
                    "message": f"This action requires '{scope}' scope. The user can grant additional scopes through AgentAdmit settings.",
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
                    "message": f"This action requires '{scope}' scope. The user can grant additional scopes through AgentAdmit settings.",
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
