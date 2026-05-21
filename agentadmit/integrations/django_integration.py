"""
agentadmit.integrations.django_integration
-------------------------------------------
Django integration for AgentAdmit.

Usage:
    # settings.py
    MIDDLEWARE = [
        ...
        'agentadmit.integrations.django_integration.AgentAdmitMiddleware',
    ]

    AGENTADMIT_CONFIG = {
        'config_path': 'agentadmit.yaml',
        'users_collection': 'users',
        # ... or pass get_current_user, verify_user_token, etc.
    }

    # views.py
    from agentadmit.integrations.django_integration import require_scope_if_agent

    @require_scope_if_agent("read:orders")
    def get_orders(request):
        user = request.agentadmit_user
        ...

    # urls.py
    from agentadmit.integrations.django_integration import agentadmit_urls
    urlpatterns = [
        path('', include(agentadmit_urls)),
    ]
"""

import functools
import json
import logging
from datetime import datetime
from typing import Callable, Optional

import requests as _requests
from django.http import JsonResponse
from django.urls import path
from django.conf import settings

from agentadmit.config import load_config, get_config, get_scope_metadata, get_duration_options
from agentadmit.storage import create_storage

logger = logging.getLogger(__name__)

AGENTADMIT_VERSION = "0.1"

# Module-level state (initialized by middleware)
_storage = None
_config = None
_get_current_user = None
_verify_user_token = None
_determine_role = lambda u: "user"
_get_user_tier = None
_validate_scopes = None
_get_endpoints_for_scopes = lambda s: []


def _init():
    """Initialize AgentAdmit from Django settings."""
    global _storage, _config, _get_current_user, _verify_user_token
    global _determine_role, _get_user_tier, _validate_scopes, _get_endpoints_for_scopes

    if _config is not None:
        return  # Already initialized

    aa_settings = getattr(settings, 'AGENTADMIT_CONFIG', {})
    config_path = aa_settings.get('config_path', 'agentadmit.yaml')

    _config = load_config(config_path)
    _storage = create_storage(_config)

    if hasattr(_storage, 'set_users_collection'):
        _storage.set_users_collection(aa_settings.get('users_collection', 'users'))

    # Callbacks from settings
    _get_current_user = aa_settings.get('get_current_user')
    _verify_user_token = aa_settings.get('verify_user_token')
    _determine_role = aa_settings.get('determine_role', lambda u: "user")
    _get_user_tier = aa_settings.get('get_user_tier', lambda u: _config.default_tier)
    _get_endpoints_for_scopes = aa_settings.get('get_endpoints_for_scopes', lambda s: [])

    if aa_settings.get('validate_scopes'):
        _validate_scopes = aa_settings['validate_scopes']
    else:
        valid_names = {s.name for s in _config.scopes}
        _validate_scopes = lambda scopes, user: (
            all(s in valid_names for s in scopes),
            [s for s in scopes if s not in valid_names],
        )

    logger.info("AgentAdmit Django integration initialized: %d scopes", len(_config.scopes))


def _get_bearer_token(request) -> Optional[str]:
    """Extract bearer token from request."""
    auth = request.META.get('HTTP_AUTHORIZATION', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    return None


def _validate_agent_token(token: str) -> dict:
    """Validate an ag_at_ token via mandatory introspection."""
    _init()
    if not token.startswith(_config.token_prefix_access):
        raise ValueError("Not an AgentAdmit token")

    # MANDATORY INTROSPECTION — validate via AgentAdmit hosted service
    import requests as _requests

    try:
        resp = _requests.post(
            _config.agentadmit_verify_url,
            headers={
                "Authorization": f"Bearer {_config.api_key}",
                "Content-Type": "application/json",
            },
            json={"token": token},
            timeout=5,
        )
    except _requests.exceptions.RequestException as exc:
        raise ValueError(f"Introspection failed: {exc}")

    if resp.status_code == 401:
        err_data = resp.json() if "application/json" in resp.headers.get("content-type", "") else {}
        raise ValueError(err_data.get("error_description", "Token validation failed"))

    if resp.status_code != 200:
        raise ValueError(f"Verification service returned {resp.status_code}")

    data = resp.json()

    # Check active flag (RFC 7662 introspection pattern).
    if not data.get("active"):
        reason = data.get("error", "invalid_token")
        raise ValueError(f"Token is not active: {reason}")

    scopes = data.get("scopes", [])
    user_id = data.get("user_id")
    connection_id = data.get("connection_id")

    if not user_id:
        raise ValueError("Introspection returned no user")

    user = _storage.get_user(user_id, _config.user_lookup_field) or {"user_id": user_id}
    connection = {"connection_id": connection_id, "scopes": scopes, "agent_label": data.get("agent_label", "Unknown Agent")}

    return {"user": user, "connection": connection, "scopes": scopes}


def _log_access(ctx, scope, request):
    """Write audit log."""
    try:
        conn = ctx.get("connection") or {}
        user = ctx.get("user") or {}
        _storage.log_access({
            "timestamp": datetime.utcnow(),
            "connection_id": conn.get("connection_id", "unknown"),
            "user_id": user.get(_config.user_lookup_field, "unknown"),
            "scope_used": scope,
            "resource": request.path,
            "method": request.method,
            "agent_label": conn.get("agent_label", "Unknown Agent"),
        })
    except Exception as exc:
        logger.error("Audit log failed: %s", exc)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class AgentAdmitMiddleware:
    """Django middleware that initializes AgentAdmit and attaches auth context to requests."""

    def __init__(self, get_response):
        self.get_response = get_response
        _init()

    def __call__(self, request):
        token = _get_bearer_token(request)
        if token and token.startswith(_config.token_prefix_access):
            try:
                ctx = _validate_agent_token(token)
                request.agentadmit_user = {"auth_type": "agent", **ctx}
            except Exception:
                request.agentadmit_user = None
        else:
            request.agentadmit_user = None

        return self.get_response(request)


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def require_scope(scope: str):
    """Decorator: require scope (agent-only)."""
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped(request, *args, **kwargs):
            _init()
            token = _get_bearer_token(request)
            if not token or not token.startswith(_config.token_prefix_access):
                return JsonResponse({"error": "invalid_token"}, status=401)

            try:
                ctx = _validate_agent_token(token)
            except Exception as e:
                return JsonResponse({"error": "invalid_token", "error_description": str(e)}, status=401)

            if scope not in ctx.get("scopes", []):
                return JsonResponse({"error": "insufficient_scope", "required_scope": scope}, status=403)

            _log_access(ctx, scope, request)
            request.agentadmit_user = {"auth_type": "agent", **ctx}
            return view_func(request, *args, **kwargs)
        return wrapped
    return decorator


def require_scope_if_agent(scope: str):
    """Decorator: enforce scope only for agent tokens."""
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped(request, *args, **kwargs):
            _init()
            token = _get_bearer_token(request)
            if not token or not token.startswith(_config.token_prefix_access):
                return view_func(request, *args, **kwargs)

            try:
                ctx = _validate_agent_token(token)
            except Exception as e:
                return JsonResponse({"error": "invalid_token", "error_description": str(e)}, status=401)

            if scope not in ctx.get("scopes", []):
                return JsonResponse({"error": "insufficient_scope", "required_scope": scope}, status=403)

            _log_access(ctx, scope, request)
            request.agentadmit_user = {"auth_type": "agent", **ctx}
            return view_func(request, *args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------------------
# JWT helper — DEPRECATED: AgentAdmit is a hosted service. All token
# operations go through the hosted service at agentadmit_api_url.
# No local JWT signing, no local key management.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# URL views
# ---------------------------------------------------------------------------

def discovery_view(request):
    _init()
    base = _config.api_base_url.rstrip("/")
    return JsonResponse({
        "agentadmit_version": AGENTADMIT_VERSION,
        "issuer": base,
        "app_name": _config.app_name,
        "api_base_url": base,
        "agentadmit_service_url": _config.agentadmit_api_url,
        "token_endpoint": f"{base}{_config.route_prefix}/token",
        "revocation_endpoint": f"{base}{_config.route_prefix}/revoke",
        "scopes_endpoint": f"{base}{_config.route_prefix}/scopes",
        "scopes_supported": [s.name for s in _config.scopes],
        "duration_options": get_duration_options(),
    })


def scopes_view(request):
    _init()
    return JsonResponse({"scopes": get_scope_metadata(), "roles": list(set(s.role for s in _config.scopes))})


def generate_token_view(request):
    """Generate a connection token via the AgentAdmit hosted service."""
    _init()
    if request.method != "POST":
        return JsonResponse({"error": "method_not_allowed"}, status=405)

    if not _get_current_user:
        return JsonResponse({"error": "not_configured"}, status=500)

    current_user = _get_current_user(request)
    if not current_user:
        return JsonResponse({"error": "unauthorized"}, status=401)

    data = json.loads(request.body)
    scopes = data.get("scopes", [])
    duration = data.get("duration_seconds", _config.connection_token_ttl)

    all_valid, invalid = _validate_scopes(scopes, current_user)
    if not all_valid:
        return JsonResponse({"error": "invalid_scope", "invalid_scopes": invalid}, status=400)

    user_id = current_user.get(_config.user_lookup_field)
    role = _determine_role(current_user)

    try:
        resp = _requests.post(
            f"{_config.agentadmit_api_url.rstrip('/')}/api/v1/apps/{_config.app_id}/token",
            headers={
                "Authorization": f"Bearer {_config.api_key}",
                "Content-Type": "application/json",
                "X-App-Id": _config.app_id,
            },
            json={
                "user_id": str(user_id),
                "scopes": scopes,
                "duration_hours": max(1, duration // 3600),
                "label": data.get("label"),
                "user_role": role,
            },
            timeout=10,
        )
    except _requests.exceptions.RequestException as exc:
        return JsonResponse({"error": "service_unavailable", "error_description": str(exc)}, status=502)

    if resp.status_code not in (200, 201):
        logger.error("Hosted token generation failed: %s %s", resp.status_code, resp.text[:500])
        return JsonResponse({"error": "token_generation_failed", "error_description": "Authorization service could not generate token"}, status=502)

    token_data = resp.json()
    return JsonResponse({
        "connection_token": token_data.get("token") or token_data.get("connection_token"),
        "expires_in": duration,
        "scopes": scopes,
    })


def token_exchange_view(request):
    """Exchange a connection token for an access token via the AgentAdmit hosted service."""
    _init()
    if request.method != "POST":
        return JsonResponse({"error": "method_not_allowed"}, status=405)

    data = json.loads(request.body)
    if data.get("grant_type") != "connection_token":
        return JsonResponse({"error": "unsupported_grant_type"}, status=400)

    connection_token = data.get("connection_token")
    if not connection_token:
        return JsonResponse({"error": "invalid_request"}, status=400)

    try:
        resp = _requests.post(
            f"{_config.agentadmit_api_url.rstrip('/')}/api/v1/exchange",
            headers={
                "Authorization": f"Bearer {_config.api_key}",
                "Content-Type": "application/json",
                "X-App-Id": _config.app_id,
            },
            json={
                "token": connection_token,
                "agent_label": data.get("agent_label"),
                "agent_id": data.get("agent_id"),
                "agent_metadata": data.get("agent_metadata"),
            },
            timeout=10,
        )
    except _requests.exceptions.RequestException as exc:
        return JsonResponse({"error": "service_unavailable", "error_description": str(exc)}, status=502)

    if resp.status_code != 200:
        try:
            return JsonResponse(resp.json(), status=resp.status_code if resp.status_code < 500 else 502)
        except Exception:
            return JsonResponse({"error": "exchange_failed"}, status=502)

    exchange_data = resp.json()
    if _get_endpoints_for_scopes and exchange_data.get("scopes"):
        exchange_data["endpoints"] = _get_endpoints_for_scopes(exchange_data["scopes"])
    return JsonResponse(exchange_data)


def connections_view(request):
    _init()
    if not _get_current_user:
        return JsonResponse({"error": "not_configured"}, status=500)
    current_user = _get_current_user(request)
    if not current_user:
        return JsonResponse({"error": "unauthorized"}, status=401)
    user_id = current_user.get(_config.user_lookup_field)
    connections = _storage.list_connections(user_id)
    return JsonResponse({"connections": connections, "total": len(connections)})


def delete_connection_view(request, connection_id):
    _init()
    if request.method != "DELETE":
        return JsonResponse({"error": "method_not_allowed"}, status=405)
    if not _get_current_user:
        return JsonResponse({"error": "not_configured"}, status=500)
    current_user = _get_current_user(request)
    if not current_user:
        return JsonResponse({"error": "unauthorized"}, status=401)
    user_id = current_user.get(_config.user_lookup_field)
    conn = _storage.get_connection(connection_id)
    if not conn or conn.get("user_id") != user_id:
        return JsonResponse({"error": "not_found"}, status=404)
    # Call hosted service to revoke
    try:
        _requests.post(
            f"{_config.agentadmit_api_url.rstrip('/')}/api/v1/revoke",
            headers={
                "Authorization": f"Bearer {_config.api_key}",
                "Content-Type": "application/json",
                "X-App-Id": _config.app_id,
            },
            json={"connection_id": connection_id, "reason": "user_requested"},
            timeout=10,
        )
    except Exception as exc:
        logger.warning("Hosted revoke failed for %s: %s (revoking locally anyway)", connection_id, exc)
    _storage.revoke_connection(connection_id)
    return JsonResponse({"revoked": True, "connection_id": connection_id})


def durations_view(request):
    _init()
    return JsonResponse({"durations": get_duration_options()})


# URL patterns — include in your urls.py:
#   from agentadmit.integrations.django_integration import agentadmit_urls
#   urlpatterns = [ path('', include(agentadmit_urls)) ]
agentadmit_urls = [
    path(".well-known/agentadmit", discovery_view),
    path("agentadmit/scopes", scopes_view),
    path("agentadmit/connections/generate-token", generate_token_view),
    path("agentadmit/token", token_exchange_view),
    path("agentadmit/connections", connections_view),
    path("agentadmit/connections/<str:connection_id>", delete_connection_view),
    path("agentadmit/durations", durations_view),
]
