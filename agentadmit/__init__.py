"""
AgentAdmit SDK for Python
=========================

User-mediated AI agent authorization. Plug-and-play for any FastAPI app.

Quick Start:
    from agentadmit import AgentAdmitMiddleware, require_scope, require_scope_if_agent

    app.add_middleware(AgentAdmitMiddleware, config_path="agentadmit.yaml")

    @app.get("/api/orders")
    async def get_orders(
        auth_ctx=Depends(get_current_user_or_agent),
        _scope=Depends(require_scope_if_agent("read:orders")),
    ):
        ...
"""

__version__ = "0.1.0"

from agentadmit.config import AgentAdmitConfig, load_config
from agentadmit.middleware import AgentAdmitMiddleware
from agentadmit.auth import (
    get_agentadmit_user,
    get_current_user_or_agent,
    require_scope,
    require_scope_if_agent,
    log_agent_access,
    check_connection_cap,
)
from agentadmit.routes import create_agentadmit_router
# keys.py is deprecated — AgentAdmit is a hosted service, no local keys needed
from agentadmit.exceptions import (
    AgentAdmitError,
    InvalidTokenError,
    InsufficientScopeError,
    ConnectionRevokedError,
    ConnectionLimitError,
    ConfigurationError,
)

__all__ = [
    "AgentAdmitMiddleware",
    "AgentAdmitConfig",
    "load_config",
    "get_agentadmit_user",
    "get_current_user_or_agent",
    "require_scope",
    "require_scope_if_agent",
    "log_agent_access",
    "check_connection_cap",
    "create_agentadmit_router",

    "AgentAdmitError",
    "InvalidTokenError",
    "InsufficientScopeError",
    "ConnectionRevokedError",
    "ConnectionLimitError",
    "ConfigurationError",
]
