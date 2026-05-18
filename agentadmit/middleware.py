"""
agentadmit.middleware
---------------------
FastAPI middleware for AgentAdmit integration.

One line to add to your app:
    app.add_middleware(AgentAdmitMiddleware, config_path="agentadmit.yaml")

This middleware:
1. Loads configuration from YAML
2. Initializes storage backend
3. Syncs scopes to the AgentAdmit hosted service (auto-sync on startup)
4. Provides create_agentadmit_router() for manual route registration

NOTE: Due to Starlette's middleware wrapping, routes cannot be auto-registered
from within __init__. Use the manual pattern shown in the docstring below.
"""

import logging
from typing import Callable, Optional

import httpx
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from agentadmit.config import load_config, get_config
from agentadmit.storage import create_storage
from agentadmit.auth import _set_storage, _set_user_verifier
from agentadmit.routes import create_agentadmit_router

logger = logging.getLogger(__name__)


def _sync_scopes_to_hosted_service(config) -> bool:
    """
    Push scopes from agentadmit.yaml to the AgentAdmit hosted service.
    Called automatically on startup. Idempotent (upsert by app_id + scope name).

    Returns True if sync succeeded, False otherwise.
    """
    if not config.app_id or not config.api_key:
        logger.warning(
            "Cannot sync scopes — app_id or api_key not set. "
            "Get these from your AgentAdmit dashboard."
        )
        return False

    if not config.scopes:
        logger.info("No scopes defined in agentadmit.yaml — nothing to sync.")
        return True

    url = f"{config.agentadmit_api_url.rstrip('/')}/api/v1/apps/{config.app_id}/scopes"
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "Content-Type": "application/json",
        "X-App-Id": config.app_id,
    }
    payload = {
        "scopes": [
            {
                "name": s.name,
                "description": s.description,
                "category": s.category,
                "role": s.role,
            }
            for s in config.scopes
        ]
    }

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post(url, headers=headers, json=payload)

        if resp.status_code == 200:
            data = resp.json()
            count = data.get("count", len(config.scopes))
            logger.info("Scopes synced to hosted service: %d scopes registered", count)
            return True
        else:
            logger.warning(
                "Scope sync failed (HTTP %d): %s",
                resp.status_code,
                resp.text[:300],
            )
            return False
    except httpx.RequestError as exc:
        logger.warning(
            "Could not reach AgentAdmit hosted service for scope sync: %s. "
            "Scopes will need to be registered manually via the dashboard or API.",
            exc,
        )
        return False


class AgentAdmitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that initializes and configures AgentAdmit.

    IMPORTANT: Due to Starlette's middleware wrapping, this middleware CANNOT
    auto-register routes from within __init__. After adding the middleware,
    register routes manually:

        from agentadmit import AgentAdmitMiddleware
        from agentadmit.config import load_config, get_config
        from agentadmit.routes import create_agentadmit_router
        from agentadmit.storage import create_storage
        from agentadmit.auth import _set_storage, _set_user_verifier

        # Option 1: Let middleware handle init, register routes manually
        app.add_middleware(AgentAdmitMiddleware, config_path="agentadmit.yaml", ...)

        config = get_config()  # Available after middleware init
        wellknown, router = create_agentadmit_router(get_current_user=your_auth)
        app.include_router(wellknown)
        app.include_router(router, prefix=config.route_prefix)

        # Option 2: Do everything manually (recommended)
        load_config("agentadmit.yaml")
        config = get_config()
        storage = create_storage(config)
        _set_storage(storage)
        _set_user_verifier(your_token_verifier)

        wellknown, router = create_agentadmit_router(get_current_user=your_auth)
        app.include_router(wellknown)
        app.include_router(router, prefix=config.route_prefix)
    """

    def __init__(
        self,
        app,
        config_path: str = "agentadmit.yaml",
        get_current_user: Callable = None,
        verify_user_token: Callable = None,
        determine_role: Callable = None,
        get_user_tier: Callable = None,
        validate_scopes: Callable = None,
        get_endpoints_for_scopes: Callable = None,
        users_collection: str = "users",
        sync_scopes: bool = True,
    ):
        super().__init__(app)

        # Load config
        config = load_config(config_path)
        logger.info("AgentAdmit SDK v0.1 initialized: %s (%d scopes)", config.app_name, len(config.scopes))

        # Verify hosted service credentials
        if not config.app_id:
            logger.warning("AgentAdmit app_id not set. Get it from your AgentAdmit dashboard.")
        if not config.api_key:
            logger.warning("AgentAdmit api_key not set. Get it from your AgentAdmit dashboard.")

        # Initialize storage
        storage = create_storage(config)
        _set_storage(storage)

        # Set users collection for MongoDB storage
        if hasattr(storage, 'set_users_collection'):
            storage.set_users_collection(users_collection)

        # Set user token verifier for dual-token auth
        if verify_user_token:
            _set_user_verifier(verify_user_token)

        # Auto-sync scopes to hosted service on startup
        if sync_scopes and config.app_id and config.api_key:
            _sync_scopes_to_hosted_service(config)

        # NOTE: Route registration cannot happen here due to Starlette's
        # middleware wrapping. The app instance passed to __init__ is already
        # wrapped by other middleware, so app.include_router() won't reach
        # the actual FastAPI instance. See class docstring for manual pattern.
        if get_current_user is not None:
            logger.info(
                "AgentAdmit routes available via create_agentadmit_router(). "
                "Register them manually: app.include_router(wellknown); "
                "app.include_router(router, prefix='%s')",
                config.route_prefix,
            )

    async def dispatch(self, request: Request, call_next) -> Response:
        """Pass-through middleware — initialization happens in __init__."""
        return await call_next(request)
