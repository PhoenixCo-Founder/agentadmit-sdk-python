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
import hashlib
import json
import logging
import secrets
import uuid
import base64
from datetime import datetime, timedelta
from typing import Callable, Optional

import jwt as pyjwt
from django.http import JsonResponse
from django.urls import path
from django.conf import settings

from agentadmit.config import load_config, get_config, get_scope_metadata, get_duration_options
from agentadmit.keys import generate_key_pair, load_private_key, load_public_key
from agentadmit.storage import create_storage

logger = logging.getLogger(__name__)

AGENTADMIT_VERSION = "0.1"

# Module-level state (initialized by middleware)
_storage = None
_config = None
_jwks_key = None
_get_current_user = None
_verify_user_token = None
_determine_role = lambda u: "user"
_get_user_tier = None
_validate_scopes = None
_get_endpoints_for_scopes = lambda s: []


def _init():
    """Initialize AgentAdmit from Django settings."""
    global _storage, _config, _jwks_key, _get_current_user, _verify_user_token
    global _determine_role, _get_user_tier, _validate_scopes, _get_endpoints_for_scopes

    if _config is not None:
        return  # Already initialized

    aa_settings = getattr(settings, 'AGENTADMIT_CONFIG', {})
    config_path = aa_settings.get('config_path', 'agentadmit.yaml')

    _config = load_config(config_path)
    _storage = create_storage(_config)

    if hasattr(_storage, 'set_users_collection'):
        _storage.set_users_collection(aa_settings.get('users_collection', 'users'))

    # Auto-generate keys
    try:
        load_private_key(_config.private_key_path)
        load_public_key(_config.public_key_path)
    except Exception:
        import os
        keys_dir = os.path.dirname(_config.private_key_path) or "keys"
        generate_key_pair(keys_dir)

    # Build JWKS
    try:
        from agentadmit.routes import _build_jwks_key
        pub_pem = load_public_key(_config.public_key_path)
        _jwks_key = _build_jwks_key(pub_pem)
    except Exception:
        _jwks_key = None

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
    """Validate an ag_at_ token."""
    _init()
    if not token.startswith(_config.token_prefix_access):
        raise ValueError("Not an AgentAdmit token")

    raw = token[len(_config.token_prefix_access):]
    pub_key = load_public_key(_config.public_key_path)

    payload = pyjwt.decode(raw, pub_key, algorithms=[_config.algorithm], audience=_config.audience)
    claims = payload.get("agentadmit", {})
    conn_id = claims.get("connection_id")
    scopes = claims.get("scopes", [])
    user_id = payload.get("sub")

    if not conn_id or not user_id:
        raise ValueError("Missing claims")

    connection = _storage.get_active_connection(conn_id)
    if not connection:
        raise ValueError("Connection revoked")

    user = _storage.get_user(user_id, _config.user_lookup_field)
    if not user:
        raise ValueError("User not found")

    try:
        _storage.update_connection(conn_id, {"last_used": datetime.utcnow()})
    except Exception:
        pass

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
# JWT helper
# ---------------------------------------------------------------------------

def _create_jwt(user_id, scopes, connection_id, role, agent_label, lifetime):
    """Create signed RS256 JWT."""
    private_key = load_private_key(_config.private_key_path)
    now = datetime.utcnow()
    payload = {
        "iss": _config.api_base_url.rstrip("/"),
        "sub": user_id,
        "aud": _config.audience,
        "iat": now,
        "exp": now + timedelta(seconds=lifetime),
        "jti": str(uuid.uuid4()),
        "agentadmit": {
            "version": AGENTADMIT_VERSION,
            "scopes": scopes,
            "connection_id": connection_id,
            "agent_label": agent_label,
            "role": role,
        },
    }
    token_str = pyjwt.encode(payload, private_key, algorithm=_config.algorithm)
    if isinstance(token_str, bytes):
        token_str = token_str.decode("utf-8")
    return token_str


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
        "token_endpoint": f"{base}{_config.route_prefix}/token",
        "revocation_endpoint": f"{base}{_config.route_prefix}/revoke",
        "scopes_endpoint": f"{base}{_config.route_prefix}/scopes",
        "jwks_uri": f"{base}{_config.route_prefix}/.well-known/jwks.json",
        "scopes_supported": [s.name for s in _config.scopes],
        "duration_options": get_duration_options(),
    })


def scopes_view(request):
    _init()
    return JsonResponse({"scopes": get_scope_metadata(), "roles": list(set(s.role for s in _config.scopes))})


def jwks_view(request):
    _init()
    keys = [_jwks_key] if _jwks_key else []
    response = JsonResponse({"keys": keys})
    response["Cache-Control"] = "public, max-age=3600"
    return response


def generate_token_view(request):
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

    exchange_url = f"{_config.api_base_url.rstrip('/')}{_config.route_prefix}/token"
    url_part = base64.urlsafe_b64encode(exchange_url.encode()).decode().rstrip("=")
    secret_part = secrets.token_urlsafe(24)
    raw_token = f"{_config.token_prefix_connection}{url_part}.{secret_part}"

    now = datetime.utcnow()
    user_id = current_user.get(_config.user_lookup_field)
    role = _determine_role(current_user)

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    _storage.store_token({
        "token_hash": token_hash,
        "token": raw_token,
        "user_id": user_id,
        "scopes": scopes,
        "role": role,
        "duration_seconds": duration,
        "used": False,
        "created_at": now,
        "expires_at": now + timedelta(seconds=_config.connection_token_ttl),
    })

    return JsonResponse({"connection_token": raw_token, "expires_in": _config.connection_token_ttl, "scopes": scopes})


def token_exchange_view(request):
    _init()
    if request.method != "POST":
        return JsonResponse({"error": "method_not_allowed"}, status=405)

    data = json.loads(request.body)
    if data.get("grant_type") != "connection_token":
        return JsonResponse({"error": "unsupported_grant_type"}, status=400)

    connection_token = data.get("connection_token")
    if not connection_token:
        return JsonResponse({"error": "invalid_request"}, status=400)

    token_hash = hashlib.sha256(connection_token.encode()).hexdigest()
    now = datetime.utcnow()
    token_doc = _storage.get_token(token_hash)

    if not token_doc or token_doc.get("used") or token_doc.get("expires_at", now) <= now:
        return JsonResponse({"error": "invalid_token"}, status=400)

    _storage.mark_token_used(token_hash)

    connection_id = f"conn_{secrets.token_urlsafe(16)}"
    agent_label = data.get("agent_label", "Unknown Agent")
    token_duration = token_doc.get("duration_seconds", 2592000)

    _storage.store_connection({
        "connection_id": connection_id,
        "user_id": token_doc["user_id"],
        "scopes": token_doc["scopes"],
        "role": token_doc.get("role", "user"),
        "agent_id": data.get("agent_id"),
        "agent_label": agent_label,
        "agent_metadata": data.get("agent_metadata"),
        "duration_seconds": token_duration,
        "expires_at": now + timedelta(seconds=token_duration),
        "status": "active",
        "created_at": now,
        "last_used": None,
        "revoked_at": None,
    })

    raw_jwt = _create_jwt(
        user_id=token_doc["user_id"],
        scopes=token_doc["scopes"],
        connection_id=connection_id,
        role=token_doc.get("role", "user"),
        agent_label=agent_label,
        lifetime=token_duration,
    )

    return JsonResponse({
        "access_token": f"{_config.token_prefix_access}{raw_jwt}",
        "token_type": "bearer",
        "expires_in": token_duration,
        "scopes": token_doc["scopes"],
        "role": token_doc.get("role", "user"),
        "connection_id": connection_id,
        "app_name": _config.app_name,
        "api_base_url": _config.api_base_url,
        "endpoints": _get_endpoints_for_scopes(token_doc["scopes"]),
    })


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
    path("agentadmit/.well-known/jwks.json", jwks_view),
    path("agentadmit/connections/generate-token", generate_token_view),
    path("agentadmit/token", token_exchange_view),
    path("agentadmit/connections", connections_view),
    path("agentadmit/connections/<str:connection_id>", delete_connection_view),
    path("agentadmit/durations", durations_view),
]
