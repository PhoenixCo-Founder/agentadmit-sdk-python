"""
agentadmit.routes
-----------------
Auto-generated FastAPI router with all AgentAdmit endpoints.

Call create_agentadmit_router() and include the returned routers in your FastAPI app.
The SDK handles discovery, JWKS, token exchange, revocation, connections, and scopes.

Generalized from TrainerTracer's agentadmit_routes.py — all app-specific references removed.
"""

import base64
import logging
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Callable, Optional

import jwt as pyjwt
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials

from agentadmit.auth import (
    _get_storage,
    check_connection_cap,
    get_agentadmit_user,
    security,
)
from agentadmit.config import get_config, get_scope_metadata, get_duration_options, get_tier_limits
from agentadmit.keys import load_private_key, load_public_key
from agentadmit.models import (
    GenerateTokenRequest,
    GenerateTokenResponse,
    RevokeRequest,
    RevokeResponse,
    TokenExchangeRequest,
)

logger = logging.getLogger(__name__)

AGENTADMIT_VERSION = "0.1"


def _build_jwks_key(public_key_pem: str) -> Optional[dict]:
    """Build a JWKS key entry from the public PEM key."""
    try:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
        pub = load_pem_public_key(public_key_pem.encode())
        numbers = pub.public_numbers()

        def _b64url(n: int, length: int = None) -> str:
            if length is None:
                length = (n.bit_length() + 7) // 8
            return base64.urlsafe_b64encode(n.to_bytes(length, "big")).decode().rstrip("=")

        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": "agentadmit-1",
            "n": _b64url(numbers.n),
            "e": _b64url(numbers.e),
        }
    except Exception as exc:
        logger.warning("Failed to build JWKS key: %s", exc)
        return None


def _create_jwt(
    user_id: str,
    scopes: list,
    connection_id: str,
    role: str,
    agent_label: str = "Unknown Agent",
    lifetime_seconds: int = 2592000,
) -> str:
    """
    Create a signed RS256 JWT for AgentAdmit access.

    Returns the raw JWT string (no ag_at_ prefix — caller adds it).
    """
    config = get_config()
    private_key = load_private_key(config.private_key_path)

    now = datetime.utcnow()
    jti = str(uuid.uuid4())

    payload = {
        "iss": config.api_base_url.rstrip("/"),
        "sub": user_id,
        "aud": config.audience,
        "iat": now,
        "exp": now + timedelta(seconds=lifetime_seconds),
        "jti": jti,
        "agentadmit": {
            "version": AGENTADMIT_VERSION,
            "scopes": scopes,
            "connection_id": connection_id,
            "agent_label": agent_label,
            "role": role,
        },
    }

    token_str = pyjwt.encode(
        payload,
        private_key,
        algorithm=config.algorithm,
        headers={"kid": "agentadmit-1"},
    )

    if isinstance(token_str, bytes):
        token_str = token_str.decode("utf-8")

    # Store jti for revocation tracking (best-effort)
    try:
        storage = _get_storage()
        storage.store_token({
            "jti": jti,
            "token_hash": jti,  # using jti as hash for access tokens
            "connection_id": connection_id,
            "user_id": user_id,
            "issued_at": now,
            "expires_at": now + timedelta(seconds=lifetime_seconds),
            "used": True,  # access tokens are "used" immediately
        })
    except Exception as exc:
        logger.warning("Failed to record access token jti: %s", exc)

    return token_str


def create_agentadmit_router(
    get_current_user: Callable = None,
    determine_role: Callable = None,
    get_user_tier: Callable = None,
    validate_scopes: Callable = None,
    get_endpoints_for_scopes: Callable = None,
) -> tuple[APIRouter, APIRouter]:
    """
    Create the AgentAdmit FastAPI routers.

    Args:
        get_current_user: FastAPI dependency that returns the authenticated user dict.
            Must return a dict with at least the user ID field (configurable via user_lookup_field).
        determine_role: Function(user_dict) -> str. Returns the user's role (e.g., "user", "admin").
            Default: returns "user" for everyone.
        get_user_tier: Function(user_dict) -> str. Returns the user's AgentAdmit tier.
            Default: returns the default tier from config.
        validate_scopes: Function(scopes: list, user_dict) -> tuple[bool, list].
            Returns (all_valid, invalid_scopes). Default: all scopes are valid.
        get_endpoints_for_scopes: Function(scopes: list) -> list[dict].
            Returns endpoint definitions for the granted scopes. Default: empty list.

    Returns:
        Tuple of (wellknown_router, agentadmit_router).
        Include both in your FastAPI app:
            app.include_router(wellknown_router)
            app.include_router(agentadmit_router, prefix="/agentadmit")
    """
    config = get_config()
    storage = _get_storage()

    # Defaults for optional callbacks
    if determine_role is None:
        determine_role = lambda user: "user"

    if get_user_tier is None:
        get_user_tier = lambda user: config.default_tier

    if validate_scopes is None:
        valid_scope_names = {s.name for s in config.scopes}
        def validate_scopes(scopes, user):
            invalid = [s for s in scopes if s not in valid_scope_names]
            return (len(invalid) == 0, invalid)

    if get_endpoints_for_scopes is None:
        get_endpoints_for_scopes = lambda scopes: []

    # Build JWKS key once
    try:
        public_key_pem = load_public_key(config.public_key_path)
        jwks_key = _build_jwks_key(public_key_pem)
    except Exception:
        jwks_key = None

    # ── Routers ──────────────────────────────────────────────────────────────
    wellknown_router = APIRouter(tags=["AgentAdmit Discovery"])
    agentadmit_router = APIRouter(tags=["AgentAdmit"])

    # ── Discovery ────────────────────────────────────────────────────────────

    @wellknown_router.get("/.well-known/agentadmit", summary="AgentAdmit discovery document")
    async def discovery():
        base = config.api_base_url.rstrip("/")
        scope_names = [s.name for s in config.scopes]
        roles = list(set(s.role for s in config.scopes))

        return {
            "agentadmit_version": AGENTADMIT_VERSION,
            "issuer": base,
            "app_name": config.app_name,
            "api_base_url": base,
            "token_endpoint": f"{base}{config.route_prefix}/token",
            "revocation_endpoint": f"{base}{config.route_prefix}/revoke",
            "scopes_endpoint": f"{base}{config.route_prefix}/scopes",
            "jwks_uri": f"{base}{config.route_prefix}/.well-known/jwks.json",
            "scopes_supported": scope_names,
            "roles_supported": roles,
            "duration_options": get_duration_options(),
            "documentation_url": f"{base}/docs/agentadmit",
        }

    # ── Scopes ───────────────────────────────────────────────────────────────

    @agentadmit_router.get("/scopes", summary="Available scopes and roles")
    async def scopes_endpoint():
        return {
            "scopes": get_scope_metadata(),
            "roles": list(set(s.role for s in config.scopes)),
        }

    # ── JWKS ─────────────────────────────────────────────────────────────────

    @agentadmit_router.get("/.well-known/jwks.json", summary="JWKS public key")
    async def jwks_endpoint():
        keys = [jwks_key] if jwks_key else []
        return JSONResponse(
            content={"keys": keys},
            headers={"Cache-Control": "public, max-age=3600"},
        )

    # ── Generate Connection Token (user-authenticated) ───────────────────────

    @agentadmit_router.post(
        "/connections/generate-token",
        response_model=GenerateTokenResponse,
        summary="Generate a connection token (user-authenticated)",
    )
    def generate_token(
        body: GenerateTokenRequest,
        current_user: dict = Depends(get_current_user),
    ):
        # Validate scopes
        all_valid, invalid = validate_scopes(body.scopes, current_user)
        if not all_valid:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "invalid_scope",
                    "error_description": "One or more requested scopes are not available for your account.",
                    "invalid_scopes": invalid,
                },
            )

        # Duration validation
        duration = body.duration_seconds or config.connection_token_ttl
        if duration < 300:
            raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "duration_seconds must be at least 300 (5 minutes)"})
        if duration > 315360000:
            raise HTTPException(status_code=400, detail={"error": "invalid_request", "error_description": "duration_seconds must not exceed 315360000 (~10 years)"})

        # Generate self-describing token
        exchange_url = f"{config.api_base_url.rstrip('/')}{config.route_prefix}/token"
        url_part = base64.urlsafe_b64encode(exchange_url.encode()).decode().rstrip("=")
        secret_part = secrets.token_urlsafe(24)
        raw_token = f"{config.token_prefix_connection}{url_part}.{secret_part}"

        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=config.connection_token_ttl)
        user_id = current_user.get(config.user_lookup_field)
        role = determine_role(current_user)

        # Store token
        import hashlib
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        storage.store_token({
            "token_hash": token_hash,
            "token": raw_token,
            "user_id": user_id,
            "scopes": body.scopes,
            "role": role,
            "duration_seconds": duration,
            "used": False,
            "created_at": now,
            "expires_at": expires_at,
        })

        logger.info("Connection token generated for user %s with %d scopes", user_id, len(body.scopes))

        return GenerateTokenResponse(
            connection_token=raw_token,
            expires_in=config.connection_token_ttl,
            scopes=body.scopes,
        )

    # ── Token Exchange (agent-facing, no auth) ───────────────────────────────

    @agentadmit_router.post("/token", summary="Token exchange: connection_token → access_token")
    def token_exchange(body: TokenExchangeRequest):
        if body.grant_type != "connection_token":
            raise HTTPException(
                status_code=400,
                detail={"error": "unsupported_grant_type", "error_description": "grant_type must be 'connection_token'"},
            )

        if not body.connection_token:
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_request", "error_description": "connection_token is required"},
            )

        # Look up token
        import hashlib
        token_hash = hashlib.sha256(body.connection_token.encode()).hexdigest()
        now = datetime.utcnow()
        token_doc = storage.get_token(token_hash)

        if not token_doc:
            # Try direct token match (backward compat)
            # Some storage backends may store the raw token
            token_doc = storage.get_token(body.connection_token)

        if not token_doc or token_doc.get("used") or token_doc.get("expires_at", now) <= now:
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_token", "error_description": "Connection token has expired, already been used, or does not exist"},
            )

        # Tier enforcement
        user_tier = config.default_tier
        user = storage.get_user(token_doc["user_id"], config.user_lookup_field)
        if user and get_user_tier:
            user_tier = get_user_tier(user)
        check_connection_cap(token_doc["user_id"], user_tier)

        # Mark used
        storage.mark_token_used(token_hash)

        # Create connection
        connection_id = f"conn_{secrets.token_urlsafe(16)}"
        agent_label = body.agent_label or "Unknown Agent"
        token_duration = token_doc.get("duration_seconds", 2592000)

        storage.store_connection({
            "connection_id": connection_id,
            "user_id": token_doc["user_id"],
            "scopes": token_doc["scopes"],
            "role": token_doc.get("role", "user"),
            "agent_id": body.agent_id,
            "agent_label": agent_label,
            "agent_metadata": body.agent_metadata,
            "duration_seconds": token_duration,
            "expires_at": now + timedelta(seconds=token_duration),
            "status": "active",
            "created_at": now,
            "last_used": None,
            "revoked_at": None,
        })

        # Issue JWT
        raw_jwt = _create_jwt(
            user_id=token_doc["user_id"],
            scopes=token_doc["scopes"],
            connection_id=connection_id,
            role=token_doc.get("role", "user"),
            agent_label=agent_label,
            lifetime_seconds=token_duration,
        )
        access_token = f"{config.token_prefix_access}{raw_jwt}"

        logger.info(
            "Token exchanged: connection=%s user=%s scopes=%s duration=%ds",
            connection_id, token_doc["user_id"], token_doc["scopes"], token_duration,
        )

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "expires_in": token_duration,
            "scopes": token_doc["scopes"],
            "role": token_doc.get("role", "user"),
            "connection_id": connection_id,
            "app_name": config.app_name,
            "api_base_url": config.api_base_url,
            "endpoints": get_endpoints_for_scopes(token_doc["scopes"]),
        }

    # ── Revoke (agent or user) ───────────────────────────────────────────────

    @agentadmit_router.post("/revoke", summary="Revoke an agent connection")
    def revoke(
        body: RevokeRequest,
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        if credentials is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        token = credentials.credentials
        now = datetime.utcnow()
        reason = body.reason or "user_requested"

        if token.startswith(config.token_prefix_access):
            # Agent-initiated
            agent_ctx = get_agentadmit_user(credentials)
            conn_id = agent_ctx["connection"]["connection_id"]
            storage.revoke_connection(conn_id)
            logger.info("Connection revoked by agent: %s reason=%s", conn_id, reason)
            return RevokeResponse(revoked=True, connection_id=conn_id)
        else:
            raise HTTPException(
                status_code=400,
                detail={"error": "invalid_request", "error_description": "Use DELETE /agentadmit/connections/{connection_id} for user-initiated revocation"},
            )

    # ── Delete connection by ID (user-authenticated) ─────────────────────────

    @agentadmit_router.delete("/connections/{connection_id}", summary="Revoke a specific connection")
    def delete_connection(
        connection_id: str,
        reason: Optional[str] = Body(default="user_requested"),
        current_user: dict = Depends(get_current_user),
    ):
        user_id = current_user.get(config.user_lookup_field)
        conn = storage.get_connection(connection_id)

        if not conn or conn.get("user_id") != user_id:
            raise HTTPException(status_code=404, detail={"error": "not_found", "error_description": "Connection not found"})

        if conn.get("status") != "active":
            raise HTTPException(status_code=400, detail={"error": "already_revoked", "error_description": "Connection is already revoked or expired"})

        storage.revoke_connection(connection_id)
        logger.info("Connection revoked by user: %s reason=%s", connection_id, reason)
        return RevokeResponse(revoked=True, connection_id=connection_id)

    # ── List connections (user-authenticated) ────────────────────────────────

    @agentadmit_router.get("/connections", summary="List your agent connections")
    def list_connections(current_user: dict = Depends(get_current_user)):
        user_id = current_user.get(config.user_lookup_field)
        connections = storage.list_connections(user_id)

        result = []
        for c in connections:
            result.append({
                "connection_id": c.get("connection_id"),
                "scopes": c.get("scopes", []),
                "role": c.get("role", "user"),
                "agent_label": c.get("agent_label"),
                "agent_id": c.get("agent_id"),
                "status": c.get("status"),
                "created_at": str(c.get("created_at", "")),
                "last_used": str(c.get("last_used", "")) if c.get("last_used") else None,
                "expires_at": str(c.get("expires_at", "")) if c.get("expires_at") else None,
                "duration_seconds": c.get("duration_seconds"),
            })

        return {"connections": result, "total": len(result)}

    # ── Duration options (for frontend) ──────────────────────────────────────

    @agentadmit_router.get("/durations", summary="Available connection duration options")
    async def durations_endpoint():
        return {"durations": get_duration_options()}

    return wellknown_router, agentadmit_router
