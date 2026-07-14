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

from agentadmit._version import __version__

from agentadmit.config import AgentAdmitConfig, load_config
from agentadmit.middleware import AgentAdmitMiddleware
from agentadmit.auth import (
    get_agentadmit_user,
    get_current_user_or_agent,
    require_scope,
    require_scope_if_agent,
    require_presence,
    presence_verified,
    log_agent_access,
    check_connection_cap,
)
from agentadmit.routes import create_agentadmit_router
# keys.py is deprecated — AgentAdmit is a hosted service, no local keys needed
from agentadmit.alerts import (
    configure_alerts,
    list_alerts,
    get_alert_config,
    ALERT_TYPES,
)
from agentadmit.consent import check_consent, CALLER_CLASSES
from agentadmit.callerconsent import caller_consent, classify_caller
from agentadmit.models import VERIFY_ERROR_CODES
from agentadmit.webhooks import (
    verify_webhook_signature,
    is_valid_webhook_signature,
)
from agentadmit.exceptions import (
    AgentAdmitError,
    InvalidTokenError,
    InsufficientScopeError,
    ConnectionRevokedError,
    ConnectionLimitError,
    ConfigurationError,
    WebhookSignatureError,
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

    # Consent Ledger
    "check_consent",
    "CALLER_CLASSES",

    # Caller-Identity Consent middleware
    "caller_consent",
    "classify_caller",

    # Presence verification (WebAuthn step-up)
    "require_presence",
    "presence_verified",

    # Alerts API
    "configure_alerts",
    "list_alerts",
    "get_alert_config",
    "ALERT_TYPES",

    # Verify error codes + webhook signature verification
    "VERIFY_ERROR_CODES",
    "verify_webhook_signature",
    "is_valid_webhook_signature",

    "AgentAdmitError",
    "InvalidTokenError",
    "InsufficientScopeError",
    "ConnectionRevokedError",
    "ConnectionLimitError",
    "ConfigurationError",
    "WebhookSignatureError",
]
