"""
agentadmit.integrations.flask_integration
------------------------------------------
Flask integration for AgentAdmit.

Usage:
    from flask import Flask
    from agentadmit.integrations.flask_integration import AgentAdmitFlask

    app = Flask(__name__)
    aa = AgentAdmitFlask(app, config_path="agentadmit.yaml")

    @app.route("/api/orders")
    @aa.require_scope_if_agent("read:orders")
    def get_orders():
        user = aa.get_current_user_or_agent()
        ...
"""

import functools
import hashlib
import logging
import secrets
import uuid
import base64
from datetime import datetime, timedelta
from typing import Callable, Optional

import jwt as pyjwt
from flask import Blueprint, Flask, g, jsonify, request

from agentadmit.config import load_config, get_config, get_scope_metadata, get_duration_options, get_tier_limits
from agentadmit.keys import generate_key_pair, load_private_key, load_public_key
from agentadmit.storage import create_storage, StorageBackend
from agentadmit.exceptions import ConfigurationError

logger = logging.getLogger(__name__)

AGENTADMIT_VERSION = "0.1"


class AgentAdmitFlask:
    """
    Flask integration for AgentAdmit.

    Registers a Blueprint with all AgentAdmit endpoints and provides
    decorators for scope enforcement.
    """

    def __init__(
        self,
        app: Flask = None,
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
        self.config = load_config(config_path)
        self.storage = create_storage(self.config)
        self._get_current_user = get_current_user
        self._verify_user_token = verify_user_token
        self._determine_role = determine_role or (lambda u: "user")
        self._get_user_tier = get_user_tier or (lambda u: self.config.default_tier)
        self._get_endpoints_for_scopes = get_endpoints_for_scopes or (lambda s: [])

        if validate_scopes:
            self._validate_scopes = validate_scopes
        else:
            valid_names = {s.name for s in self.config.scopes}
            self._validate_scopes = lambda scopes, user: (
                all(s in valid_names for s in scopes),
                [s for s in scopes if s not in valid_names],
            )

        # Set users collection
        if hasattr(self.storage, 'set_users_collection'):
            self.storage.set_users_collection(users_collection)

        # Auto-generate keys
        if auto_generate_keys:
            try:
                load_private_key(self.config.private_key_path)
                load_public_key(self.config.public_key_path)
            except Exception:
                import os
                keys_dir = os.path.dirname(self.config.private_key_path) or "keys"
                generate_key_pair(keys_dir)

        # Build JWKS key
        try:
            from agentadmit.routes import _build_jwks_key
            pub_pem = load_public_key(self.config.public_key_path)
            self._jwks_key = _build_jwks_key(pub_pem)
        except Exception:
            self._jwks_key = None

        if app:
            self.init_app(app)

    def init_app(self, app: Flask):
        """Register the AgentAdmit blueprint with the Flask app."""
        bp = self._create_blueprint()
        app.register_blueprint(bp)
        logger.info("AgentAdmit Flask integration registered: %d scopes", len(self.config.scopes))

    def _get_bearer_token(self) -> Optional[str]:
        """Extract bearer token from Authorization header."""
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        return None

    def _validate_agent_token(self, token: str) -> dict:
        """Validate an ag_at_ token via mandatory introspection."""
        if not token.startswith(self.config.token_prefix_access):
            raise ValueError("Not an AgentAdmit access token")

        # MANDATORY INTROSPECTION — validate via AgentAdmit hosted service
        import requests as _requests

        try:
            resp = _requests.post(
                self.config.agentadmit_verify_url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-App-Id": self.config.app_id,
                    "X-Api-Key": self.config.api_key,
                },
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
        scopes = data.get("scopes", [])
        user_id = data.get("user_id")
        connection_id = data.get("connection_id")

        if not user_id:
            raise ValueError("Introspection returned no user")

        user = self.storage.get_user(user_id, self.config.user_lookup_field) or {"user_id": user_id}
        connection = {"connection_id": connection_id, "scopes": scopes, "agent_label": data.get("agent_label", "Unknown Agent")}

        return {"user": user, "connection": connection, "scopes": scopes}

    def get_current_user_or_agent(self) -> dict:
        """Get the current user or agent from the request."""
        token = self._get_bearer_token()
        if not token:
            return None

        if token.startswith(self.config.token_prefix_access):
            ctx = self._validate_agent_token(token)
            return {"auth_type": "agent", **ctx}
        else:
            if self._verify_user_token:
                user_id = self._verify_user_token(token)
                user = self.storage.get_user(user_id, self.config.user_lookup_field)
                return {"auth_type": "user", "user": user, "scopes": ["*"], "connection": None}
            return None

    def require_scope(self, scope: str):
        """Decorator: require a specific scope (agent-only endpoints)."""
        def decorator(f):
            @functools.wraps(f)
            def wrapped(*args, **kwargs):
                token = self._get_bearer_token()
                if not token or not token.startswith(self.config.token_prefix_access):
                    return jsonify({"error": "invalid_token", "error_description": "AgentAdmit token required"}), 401

                try:
                    ctx = self._validate_agent_token(token)
                except Exception as e:
                    return jsonify({"error": "invalid_token", "error_description": str(e)}), 401

                if scope not in ctx.get("scopes", []):
                    return jsonify({
                        "error": "insufficient_scope",
                        "required_scope": scope,
                        "granted_scopes": ctx.get("scopes", []),
                    }), 403

                self._log_access(ctx, scope)
                g.agent_ctx = ctx
                return f(*args, **kwargs)
            return wrapped
        return decorator

    def require_scope_if_agent(self, scope: str):
        """Decorator: enforce scope only if caller is an agent. Pass through for regular users."""
        def decorator(f):
            @functools.wraps(f)
            def wrapped(*args, **kwargs):
                token = self._get_bearer_token()
                if not token or not token.startswith(self.config.token_prefix_access):
                    return f(*args, **kwargs)

                try:
                    ctx = self._validate_agent_token(token)
                except Exception as e:
                    return jsonify({"error": "invalid_token", "error_description": str(e)}), 401

                if scope not in ctx.get("scopes", []):
                    return jsonify({
                        "error": "insufficient_scope",
                        "required_scope": scope,
                        "granted_scopes": ctx.get("scopes", []),
                    }), 403

                self._log_access(ctx, scope)
                g.agent_ctx = ctx
                return f(*args, **kwargs)
            return wrapped
        return decorator

    def _log_access(self, ctx: dict, scope: str):
        """Write audit log entry."""
        try:
            conn = ctx.get("connection") or {}
            user = ctx.get("user") or {}
            self.storage.log_access({
                "timestamp": datetime.utcnow(),
                "connection_id": conn.get("connection_id", "unknown"),
                "user_id": user.get(self.config.user_lookup_field, "unknown"),
                "scope_used": scope,
                "resource": request.path,
                "method": request.method,
                "agent_label": conn.get("agent_label", "Unknown Agent"),
            })
        except Exception as exc:
            logger.error("Audit log failed: %s", exc)

    def _create_jwt(self, user_id, scopes, connection_id, role, agent_label, lifetime):
        """Create a signed RS256 JWT."""
        private_key = load_private_key(self.config.private_key_path)
        now = datetime.utcnow()
        jti = str(uuid.uuid4())
        payload = {
            "iss": self.config.api_base_url.rstrip("/"),
            "sub": user_id,
            "aud": self.config.audience,
            "iat": now,
            "exp": now + timedelta(seconds=lifetime),
            "jti": jti,
            "agentadmit": {
                "version": AGENTADMIT_VERSION,
                "scopes": scopes,
                "connection_id": connection_id,
                "agent_label": agent_label,
                "role": role,
            },
        }
        token_str = pyjwt.encode(payload, private_key, algorithm=self.config.algorithm)
        if isinstance(token_str, bytes):
            token_str = token_str.decode("utf-8")
        return token_str

    def _create_blueprint(self) -> Blueprint:
        """Create the Flask blueprint with all AgentAdmit routes."""
        bp = Blueprint("agentadmit", __name__, url_prefix=self.config.route_prefix)
        aa = self  # reference for closures

        @bp.route("/../.well-known/agentadmit", methods=["GET"])
        def discovery():
            base = aa.config.api_base_url.rstrip("/")
            return jsonify({
                "agentadmit_version": AGENTADMIT_VERSION,
                "issuer": base,
                "app_name": aa.config.app_name,
                "api_base_url": base,
                "token_endpoint": f"{base}{aa.config.route_prefix}/token",
                "revocation_endpoint": f"{base}{aa.config.route_prefix}/revoke",
                "scopes_endpoint": f"{base}{aa.config.route_prefix}/scopes",
                "jwks_uri": f"{base}{aa.config.route_prefix}/.well-known/jwks.json",
                "scopes_supported": [s.name for s in aa.config.scopes],
                "roles_supported": list(set(s.role for s in aa.config.scopes)),
                "duration_options": get_duration_options(),
            })

        @bp.route("/scopes", methods=["GET"])
        def scopes_endpoint():
            return jsonify({"scopes": get_scope_metadata(), "roles": list(set(s.role for s in aa.config.scopes))})

        @bp.route("/.well-known/jwks.json", methods=["GET"])
        def jwks():
            keys = [aa._jwks_key] if aa._jwks_key else []
            return jsonify({"keys": keys})

        @bp.route("/connections/generate-token", methods=["POST"])
        def generate_token():
            if not aa._get_current_user:
                return jsonify({"error": "not_configured"}), 500

            current_user = aa._get_current_user()
            if not current_user:
                return jsonify({"error": "unauthorized"}), 401

            data = request.get_json()
            scopes = data.get("scopes", [])
            duration = data.get("duration_seconds", aa.config.connection_token_ttl)

            all_valid, invalid = aa._validate_scopes(scopes, current_user)
            if not all_valid:
                return jsonify({"error": "invalid_scope", "invalid_scopes": invalid}), 400

            exchange_url = f"{aa.config.api_base_url.rstrip('/')}{aa.config.route_prefix}/token"
            url_part = base64.urlsafe_b64encode(exchange_url.encode()).decode().rstrip("=")
            secret_part = secrets.token_urlsafe(32)  # 256 bits of cryptographic entropy (industry benchmark)
            raw_token = f"{aa.config.token_prefix_connection}{url_part}.{secret_part}"

            now = datetime.utcnow()
            user_id = current_user.get(aa.config.user_lookup_field)
            role = aa._determine_role(current_user)

            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
            aa.storage.store_token({
                "token_hash": token_hash,
                "token": raw_token,
                "user_id": user_id,
                "scopes": scopes,
                "role": role,
                "duration_seconds": duration,
                "used": False,
                "created_at": now,
                "expires_at": now + timedelta(seconds=aa.config.connection_token_ttl),
            })

            return jsonify({
                "connection_token": raw_token,
                "expires_in": aa.config.connection_token_ttl,
                "scopes": scopes,
            })

        @bp.route("/token", methods=["POST"])
        def token_exchange():
            data = request.get_json()
            grant_type = data.get("grant_type")
            connection_token = data.get("connection_token")

            if grant_type != "connection_token":
                return jsonify({"error": "unsupported_grant_type"}), 400
            if not connection_token:
                return jsonify({"error": "invalid_request", "error_description": "connection_token required"}), 400

            token_hash = hashlib.sha256(connection_token.encode()).hexdigest()
            now = datetime.utcnow()
            token_doc = aa.storage.get_token(token_hash)

            if not token_doc or token_doc.get("used") or token_doc.get("expires_at", now) <= now:
                return jsonify({"error": "invalid_token", "error_description": "Token expired, used, or not found"}), 400

            aa.storage.mark_token_used(token_hash)

            connection_id = f"conn_{secrets.token_urlsafe(16)}"
            agent_label = data.get("agent_label", "Unknown Agent")
            token_duration = token_doc.get("duration_seconds", 2592000)

            aa.storage.store_connection({
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

            raw_jwt = aa._create_jwt(
                user_id=token_doc["user_id"],
                scopes=token_doc["scopes"],
                connection_id=connection_id,
                role=token_doc.get("role", "user"),
                agent_label=agent_label,
                lifetime=token_duration,
            )
            access_token = f"{aa.config.token_prefix_access}{raw_jwt}"

            return jsonify({
                "access_token": access_token,
                "token_type": "bearer",
                "expires_in": token_duration,
                "scopes": token_doc["scopes"],
                "role": token_doc.get("role", "user"),
                "connection_id": connection_id,
                "app_name": aa.config.app_name,
                "api_base_url": aa.config.api_base_url,
                "endpoints": aa._get_endpoints_for_scopes(token_doc["scopes"]),
            })

        @bp.route("/connections", methods=["GET"])
        def list_connections():
            if not aa._get_current_user:
                return jsonify({"error": "not_configured"}), 500
            current_user = aa._get_current_user()
            if not current_user:
                return jsonify({"error": "unauthorized"}), 401
            user_id = current_user.get(aa.config.user_lookup_field)
            connections = aa.storage.list_connections(user_id)
            return jsonify({"connections": connections, "total": len(connections)})

        @bp.route("/connections/<connection_id>", methods=["DELETE"])
        def delete_connection(connection_id):
            if not aa._get_current_user:
                return jsonify({"error": "not_configured"}), 500
            current_user = aa._get_current_user()
            if not current_user:
                return jsonify({"error": "unauthorized"}), 401
            user_id = current_user.get(aa.config.user_lookup_field)
            conn = aa.storage.get_connection(connection_id)
            if not conn or conn.get("user_id") != user_id:
                return jsonify({"error": "not_found"}), 404
            aa.storage.revoke_connection(connection_id)
            return jsonify({"revoked": True, "connection_id": connection_id})

        @bp.route("/durations", methods=["GET"])
        def durations():
            return jsonify({"durations": get_duration_options()})

        return bp
