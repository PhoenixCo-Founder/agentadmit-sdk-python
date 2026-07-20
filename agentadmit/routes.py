"""
agentadmit.routes
-----------------
Auto-generated FastAPI router with all AgentAdmit endpoints.

ALL token operations go through the AgentAdmit hosted service. The SDK does NOT
sign JWTs, generate RSA keys, or serve JWKS endpoints. The hosted service owns
all cryptographic operations — this is how we meter usage, seed the marketplace,
and enforce billing.

Call create_agentadmit_router() and include the returned routers in your FastAPI app.
"""

import logging
import secrets
from typing import Callable, Optional

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials

from agentadmit.auth import (
    _get_storage,
    check_connection_cap,
    get_agentadmit_user,
    security,
)
from agentadmit.config import get_config, get_scope_metadata, get_duration_options, get_tier_limits
from agentadmit.models import (
    GenerateTokenRequest,
    GenerateTokenResponse,
    RevokeRequest,
    RevokeResponse,
    TokenExchangeRequest,
)

logger = logging.getLogger(__name__)

from agentadmit._version import __version__ as AGENTADMIT_VERSION


def _call_hosted_service(method: str, path: str, json: dict = None, timeout: float = 10.0, authenticated: bool = True) -> httpx.Response:
    """
    Make a request to the AgentAdmit hosted service.
    Uses the app's API key for server-to-server auth, except for /exchange
    (authenticated=False) where the connection token itself is the credential.
    """
    config = get_config()
    url = f"{config.agentadmit_api_url.rstrip('/')}{path}"
    headers = {
        "Content-Type": "application/json",
        "X-App-Id": config.app_id,
    }
    if authenticated:
        headers["Authorization"] = f"Bearer {config.api_key}"
    try:
        with httpx.Client(timeout=timeout) as client:
            if method.upper() == "GET":
                return client.get(url, headers=headers)
            elif method.upper() == "POST":
                return client.post(url, headers=headers, json=json or {})
            elif method.upper() == "DELETE":
                return client.delete(url, headers=headers)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
    except httpx.RequestError as exc:
        logger.error("Failed to reach AgentAdmit hosted service at %s: %s", url, exc)
        raise HTTPException(
            status_code=502,
            detail={
                "error": "service_unavailable",
                "error_description": "Could not reach AgentAdmit authorization service",
            },
        )


def _run_token_mint_presence_hook(
    hook: Optional[Callable],
    *,
    request: Request,
    current_user: dict,
    body: GenerateTokenRequest,
):
    """Run the app's token-mint presence hook when configured.

    The hook is intentionally app-owned: WebAuthn/passkey ceremonies are
    origin-bound, so the SDK can only enforce that the operator verifies and
    consumes a fresh, purpose-bound attestation before token minting.

    Contract: the hook DENIES by RAISING (e.g. HTTPException). Returning None
    allows the mint. A non-None return is a contract violation and FAILS
    CLOSED (500, mint not reached) so a malformed hook (e.g. one that returns
    a plain dict) can never produce a misleading success response.
    """
    if hook is None:
        return

    result = hook(request=request, current_user=current_user, body=body)
    if result is not None:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "presence_hook_misconfigured",
                "error_description": (
                    "The token-mint presence hook must raise to deny; it must "
                    "not return a value."
                ),
            },
        )


def create_agentadmit_router(
    get_current_user: Callable = None,
    determine_role: Callable = None,
    get_user_tier: Callable = None,
    validate_scopes: Callable = None,
    get_endpoints_for_scopes: Callable = None,
    filter_scopes_for_user: Callable = None,
    require_token_mint_presence: Callable = None,
) -> tuple[APIRouter, APIRouter]:
    """
    Create the AgentAdmit FastAPI routers.

    Args:
        get_current_user: FastAPI dependency that returns the authenticated user dict.
        determine_role: Function(user_dict) -> str. Returns the user's role.
        get_user_tier: Function(user_dict) -> str. Returns the user's subscription tier.
        validate_scopes: Function(scopes: list, user_dict) -> tuple[bool, list].
        get_endpoints_for_scopes: Function(scopes: list) -> list[dict].
        filter_scopes_for_user: Optional Function(scopes: list[dict], user: dict) ->
            tuple[list[dict], dict]. If provided, the /scopes endpoint becomes user-aware.
            Returns (filtered_scopes, metadata) where metadata may contain
            {"user_role": str, "user_tier": str, "total_platform": int}.
        require_token_mint_presence: Optional callable invoked before
            /connections/generate-token contacts the hosted service, so a
            computer-use agent riding the user's session cannot mint itself a
            token. Called as hook(request=..., current_user=..., body=...).
            RAISE (e.g. HTTPException) to deny; the hook must verify AND
            consume a fresh, single-use, purpose-bound presence attestation
            (see body.presence_attestation_id). Returning None allows the
            mint; any non-None return fails closed (500). Without this hook the
            route is session-auth-only (previous behavior).

    Returns:
        Tuple of (wellknown_router, agentadmit_router).
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
            "app_id": config.app_id,
            "api_base_url": base,
            # Token operations go through the HOSTED service:
            "agentadmit_service_url": config.agentadmit_api_url,
            "scopes_endpoint": f"{base}{config.route_prefix}/scopes",
            "discovery_endpoint": f"{base}{config.route_prefix}/discovery",
            "connections_endpoint": f"{base}{config.route_prefix}/connections",
            "scopes_supported": scope_names,
            "roles_supported": roles,
            "duration_options": get_duration_options(),
        }

    # ── Scopes ───────────────────────────────────────────────────────────────

    if filter_scopes_for_user is not None and get_current_user is not None:
        @agentadmit_router.get("/scopes", summary="Available scopes and roles (user-filtered)")
        async def scopes_endpoint(current_user: dict = Depends(get_current_user)):
            all_scopes = get_scope_metadata()
            roles = list(set(s.role for s in config.scopes))
            try:
                filtered, meta = filter_scopes_for_user(all_scopes, current_user)
                return {"scopes": filtered, "roles": roles, **meta}
            except Exception as exc:
                logger.warning("filter_scopes_for_user raised: %s — returning all scopes", exc)
                return {"scopes": all_scopes, "roles": roles}
    else:
        @agentadmit_router.get("/scopes", summary="Available scopes and roles")
        async def scopes_endpoint():
            return {
                "scopes": get_scope_metadata(),
                "roles": list(set(s.role for s in config.scopes)),
            }

    # ── Generate Connection Token (user-authenticated) ───────────────────────
    # Calls the AgentAdmit hosted service to create the token.

    @agentadmit_router.post(
        "/connections/generate-token",
        response_model=GenerateTokenResponse,
        summary="Generate a connection token (user-authenticated)",
    )
    def generate_token(
        request: Request,
        body: GenerateTokenRequest,
        current_user: dict = Depends(get_current_user),
    ):
        # Validate scopes locally first (fast check before hitting hosted service)
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

        user_id = current_user.get(config.user_lookup_field)
        role = determine_role(current_user)
        user_tier = get_user_tier(current_user)

        # Check connection cap locally (fast fail)
        check_connection_cap(user_id, user_tier)

        # Presence gate (consume-before-mint): runs after scope + cap
        # validation so a rejected request never spends an attestation. The
        # hook raises to deny.
        _run_token_mint_presence_hook(
            require_token_mint_presence,
            request=request,
            current_user=current_user,
            body=body,
        )

        # Call AgentAdmit hosted service to generate the connection token.
        # duration_seconds is tri-state: omitted → hosted default (30 days);
        # explicit null → until revoked; integer → explicit duration.
        payload = {
            "user_id": str(user_id),
            "scopes": body.scopes,
            "role": role,
        }
        if "duration_seconds" in body.model_fields_set:
            payload["duration_seconds"] = body.duration_seconds

        resp = _call_hosted_service("POST", f"/api/v1/apps/{config.app_id}/token", json=payload)

        if resp.status_code not in (200, 201):
            logger.error("Hosted token generation failed: %s %s", resp.status_code, resp.text[:500])
            raise HTTPException(
                status_code=502,
                detail={"error": "token_generation_failed", "error_description": "Authorization service could not generate token"},
            )

        token_data = resp.json()

        # Store local record for the connections list
        # Use hosted service's connection_id if provided; generate a local one as fallback
        # (prevents MongoDB duplicate key on connection_id: "unknown" when hosting service omits it)
        storage.store_connection({
            "connection_id": token_data.get("connection_id") or f"conn_{secrets.token_urlsafe(16)}",
            "user_id": str(user_id),
            "scopes": body.scopes,
            "role": role,
            "agent_label": body.label,
            "duration_seconds": body.duration_seconds if "duration_seconds" in body.model_fields_set else None,
            "status": "active",
        })

        logger.info("Connection token generated via hosted service for user %s with %d scopes", user_id, len(body.scopes))

        return GenerateTokenResponse(
            connection_token=token_data.get("token"),
            expires_in=token_data.get("expires_in") or config.connection_token_ttl,
            scopes=body.scopes,
        )

    # ── Token Exchange (agent-facing, no auth) ───────────────────────────────
    # The agent sends the connection token here. We forward it to the hosted
    # service which handles all cryptographic operations (signing, etc.).

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

        # Forward the exchange to the AgentAdmit hosted service.
        # No API key on this call — the connection token is the credential.
        # Optional fields must be OMITTED when absent: the hosted /api/v1/exchange
        # rejects explicit JSON nulls ("Expected string, received null").
        payload = {"token": body.connection_token}
        if body.agent_label is not None:
            payload["agent_label"] = body.agent_label
        if body.agent_id is not None:
            payload["agent_id"] = body.agent_id
        if body.agent_metadata is not None:
            payload["agent_metadata"] = body.agent_metadata

        resp = _call_hosted_service("POST", "/api/v1/exchange", json=payload,
                                    authenticated=False)

        if resp.status_code != 200:
            detail = {"error": "exchange_failed", "error_description": "Token exchange failed"}
            try:
                detail = resp.json()
            except Exception:
                pass
            raise HTTPException(status_code=resp.status_code if resp.status_code < 500 else 502, detail=detail)

        exchange_data = resp.json()

        # Add the endpoint map if we have one locally
        if get_endpoints_for_scopes and exchange_data.get("scopes"):
            exchange_data["endpoints"] = get_endpoints_for_scopes(exchange_data["scopes"])

        logger.info(
            "Token exchanged via hosted service: connection=%s scopes=%s",
            exchange_data.get("connection_id"),
            exchange_data.get("scopes"),
        )

        return exchange_data

    # ── Revoke (agent or user) ───────────────────────────────────────────────

    @agentadmit_router.post("/revoke", summary="Revoke an agent connection")
    def revoke(
        body: RevokeRequest,
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ):
        if credentials is None:
            raise HTTPException(status_code=401, detail="Not authenticated")

        token = credentials.credentials
        reason = body.reason or "user_requested"

        if token.startswith(config.token_prefix_access):
            # Agent-initiated revocation
            agent_ctx = get_agentadmit_user(credentials)
            conn_id = agent_ctx["connection"]["connection_id"]

            # Revoke at the hosted service FIRST — that's where enforcement
            # happens. If this fails, the token still verifies, so claiming
            # revoked=True would be false comfort. 404 means the hosted
            # service has no such connection — nothing to revoke there.
            resp = _call_hosted_service("POST", "/api/v1/revoke", json={
                "connection_id": conn_id,
                "reason": reason,
            })
            if not (200 <= resp.status_code < 300 or resp.status_code == 404):
                logger.error("Hosted revoke failed for %s: HTTP %s", conn_id, resp.status_code)
                raise HTTPException(
                    status_code=502,
                    detail={
                        "error": "revoke_failed",
                        "error_description": "Authorization service could not revoke the connection. Try again.",
                    },
                )

            # Also revoke locally
            try:
                storage.revoke_connection(conn_id)
            except Exception:
                pass

            logger.info("Connection revoked by agent via hosted service: %s reason=%s", conn_id, reason)
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

        if not conn or conn.get("user_id") != str(user_id):
            raise HTTPException(status_code=404, detail={"error": "not_found", "error_description": "Connection not found"})

        if conn.get("status") != "active":
            raise HTTPException(status_code=400, detail={"error": "already_revoked", "error_description": "Connection is already revoked or expired"})

        # Revoke at the hosted service FIRST — that's where enforcement
        # happens. If this fails, the agent's token still verifies, so
        # claiming revoked=True would be false comfort. 404 means the hosted
        # service has no such connection — nothing to revoke there.
        resp = _call_hosted_service("POST", "/api/v1/revoke", json={
            "connection_id": connection_id,
            "reason": reason,
        })
        if not (200 <= resp.status_code < 300 or resp.status_code == 404):
            logger.error("Hosted revoke failed for %s: HTTP %s", connection_id, resp.status_code)
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "revoke_failed",
                    "error_description": "Authorization service could not revoke the connection. Try again.",
                },
            )

        storage.revoke_connection(connection_id)
        logger.info("Connection revoked by user via hosted service: %s reason=%s", connection_id, reason)
        return RevokeResponse(revoked=True, connection_id=connection_id)

    # ── List connections (user-authenticated) ────────────────────────────────

    @agentadmit_router.get("/connections", summary="List your agent connections")
    def list_connections(current_user: dict = Depends(get_current_user)):
        user_id = current_user.get(config.user_lookup_field)
        connections = storage.list_connections(str(user_id))

        def _serialize_dt(value):
            """Serialize a date/datetime value to ISO-8601 string, or None if missing."""
            if value is None:
                return None
            if hasattr(value, "isoformat"):
                return value.isoformat()
            s = str(value)
            return s if s else None

        result = []
        for c in connections:
            agent_label = c.get("agent_label")
            result.append({
                "connection_id": c.get("connection_id"),
                "scopes": c.get("scopes", []),
                "role": c.get("role", "user"),
                "agent_label": agent_label,
                "label": agent_label,  # alias for frontend compatibility
                "agent_id": c.get("agent_id"),
                "status": c.get("status"),
                "created_at": _serialize_dt(c.get("created_at")),
                "last_used": _serialize_dt(c.get("last_used")),
                "expires_at": _serialize_dt(c.get("expires_at")),
                "duration_seconds": c.get("duration_seconds"),
            })

        return {"connections": result, "total": len(result)}

    # ── Agent Discovery (authenticated with ag_at_ token) ────────────────────

    @agentadmit_router.get("/discovery", summary="API discovery for AI agents")
    def agent_discovery(agent_ctx: dict = Depends(get_agentadmit_user)):
        """Returns the endpoint map filtered by the agent's granted scopes."""
        granted_scopes = agent_ctx.get("scopes", [])
        endpoints = get_endpoints_for_scopes(granted_scopes)

        return {
            "app_name": config.app_name,
            "api_base_url": config.api_base_url,
            "granted_scopes": granted_scopes,
            "endpoints": endpoints,
            "auth_instructions": "Include the access token in the Authorization header: Authorization: Bearer ag_at_<your_token>",
        }

    # ── Agent Status (authenticated with ag_at_ token) ───────────────────────

    @agentadmit_router.get("/agent/status", summary="Agent connection health check")
    def agent_status(agent_ctx: dict = Depends(get_agentadmit_user)):
        return {
            "status": "active",
            "connection_id": agent_ctx.get("connection", {}).get("connection_id"),
            "scopes": agent_ctx.get("scopes", []),
            "app_name": config.app_name,
        }

    # ── Duration options (for frontend) ──────────────────────────────────────

    @agentadmit_router.get("/durations", summary="Available connection duration options")
    async def durations_endpoint():
        return {"durations": get_duration_options()}

    return wellknown_router, agentadmit_router
