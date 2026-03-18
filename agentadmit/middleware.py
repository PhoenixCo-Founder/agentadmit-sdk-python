"""
agentadmit.middleware
---------------------
FastAPI middleware for AgentAdmit integration.

One line to add to your app:
    app.add_middleware(AgentAdmitMiddleware, config_path="agentadmit.yaml")

This middleware:
1. Loads configuration from YAML
2. Initializes storage backend
3. Generates keys if they don't exist
4. Registers AgentAdmit routes (discovery, token exchange, etc.)
"""

import logging
from typing import Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from agentadmit.config import load_config
from agentadmit.storage import create_storage
from agentadmit.auth import _set_storage, _set_user_verifier
from agentadmit.routes import create_agentadmit_router
from agentadmit.keys import generate_key_pair, load_private_key, load_public_key

logger = logging.getLogger(__name__)


class AgentAdmitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that initializes and configures AgentAdmit.

    Usage:
        from agentadmit import AgentAdmitMiddleware

        app = FastAPI()
        app.add_middleware(
            AgentAdmitMiddleware,
            config_path="agentadmit.yaml",
            get_current_user=your_auth_dependency,      # required
            verify_user_token=your_token_verifier,      # required for dual-token
            determine_role=your_role_function,           # optional
            get_user_tier=your_tier_function,            # optional
            validate_scopes=your_scope_validator,        # optional
            get_endpoints_for_scopes=your_endpoints_fn,  # optional
            users_collection="users",                    # MongoDB collection name
        )
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
        auto_generate_keys: bool = True,
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

        # Create and register routes
        if get_current_user is not None:
            wellknown_router, agentadmit_router = create_agentadmit_router(
                get_current_user=get_current_user,
                determine_role=determine_role,
                get_user_tier=get_user_tier,
                validate_scopes=validate_scopes,
                get_endpoints_for_scopes=get_endpoints_for_scopes,
            )

            # Register routers with the FastAPI app
            # We need to access the underlying FastAPI app from Starlette
            from fastapi import FastAPI
            fastapi_app = app
            while hasattr(fastapi_app, 'app'):
                fastapi_app = fastapi_app.app
                if isinstance(fastapi_app, FastAPI):
                    break

            if isinstance(fastapi_app, FastAPI):
                fastapi_app.include_router(wellknown_router)
                fastapi_app.include_router(agentadmit_router, prefix=config.route_prefix)
                logger.info(
                    "AgentAdmit routes registered: %s (discovery) + %s/* (API)",
                    config.discovery_path,
                    config.route_prefix,
                )
            else:
                logger.warning("Could not auto-register routes — include them manually")
        else:
            logger.warning(
                "No get_current_user provided — AgentAdmit routes not registered. "
                "Pass get_current_user to enable token generation and management endpoints."
            )

    async def dispatch(self, request: Request, call_next) -> Response:
        """Pass-through middleware — initialization happens in __init__."""
        return await call_next(request)
