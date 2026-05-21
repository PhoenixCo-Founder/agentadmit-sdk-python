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
import logging
from datetime import datetime
from typing import Callable, Optional

import requests as _requests
from flask import Blueprint, Flask, g, jsonify, request

from agentadmit.config import load_config, get_config, get_scope_metadata, get_duration_options, get_tier_limits
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
                    "Authorization": f"Bearer {self.config.api_key}",
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
                "agentadmit_service_url": aa.config.agentadmit_api_url,
                "token_endpoint": f"{base}{aa.config.route_prefix}/token",
                "revocation_endpoint": f"{base}{aa.config.route_prefix}/revoke",
                "scopes_endpoint": f"{base}{aa.config.route_prefix}/scopes",
                "scopes_supported": [s.name for s in aa.config.scopes],
                "roles_supported": list(set(s.role for s in aa.config.scopes)),
                "duration_options": get_duration_options(),
            })

        @bp.route("/scopes", methods=["GET"])
        def scopes_endpoint():
            return jsonify({"scopes": get_scope_metadata(), "roles": list(set(s.role for s in aa.config.scopes))})

        @bp.route("/connections/generate-token", methods=["POST"])
        def generate_token():
            """Generate a connection token via the AgentAdmit hosted service."""
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

            user_id = current_user.get(aa.config.user_lookup_field)
            role = aa._determine_role(current_user)

            try:
                resp = _requests.post(
                    f"{aa.config.agentadmit_api_url.rstrip('/')}/api/v1/apps/{aa.config.app_id}/token",
                    headers={
                        "Authorization": f"Bearer {aa.config.api_key}",
                        "Content-Type": "application/json",
                        "X-App-Id": aa.config.app_id,
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
                return jsonify({"error": "service_unavailable", "error_description": str(exc)}), 502

            if resp.status_code not in (200, 201):
                logger.error("Hosted token generation failed: %s %s", resp.status_code, resp.text[:500])
                return jsonify({"error": "token_generation_failed", "error_description": "Authorization service could not generate token"}), 502

            token_data = resp.json()
            return jsonify({
                "connection_token": token_data.get("token") or token_data.get("connection_token"),
                "expires_in": duration,
                "scopes": scopes,
            })

        @bp.route("/token", methods=["POST"])
        def token_exchange():
            """Exchange a connection token for an access token via the AgentAdmit hosted service."""
            data = request.get_json()
            grant_type = data.get("grant_type")
            connection_token = data.get("connection_token")

            if grant_type != "connection_token":
                return jsonify({"error": "unsupported_grant_type"}), 400
            if not connection_token:
                return jsonify({"error": "invalid_request", "error_description": "connection_token required"}), 400

            try:
                resp = _requests.post(
                    f"{aa.config.agentadmit_api_url.rstrip('/')}/api/v1/exchange",
                    headers={
                        "Authorization": f"Bearer {aa.config.api_key}",
                        "Content-Type": "application/json",
                        "X-App-Id": aa.config.app_id,
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
                return jsonify({"error": "service_unavailable", "error_description": str(exc)}), 502

            if resp.status_code != 200:
                try:
                    return jsonify(resp.json()), resp.status_code if resp.status_code < 500 else 502
                except Exception:
                    return jsonify({"error": "exchange_failed"}), 502

            exchange_data = resp.json()
            if aa._get_endpoints_for_scopes and exchange_data.get("scopes"):
                exchange_data["endpoints"] = aa._get_endpoints_for_scopes(exchange_data["scopes"])
            return jsonify(exchange_data)

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
            # Call hosted service to revoke
            try:
                _requests.post(
                    f"{aa.config.agentadmit_api_url.rstrip('/')}/api/v1/revoke",
                    headers={
                        "Authorization": f"Bearer {aa.config.api_key}",
                        "Content-Type": "application/json",
                        "X-App-Id": aa.config.app_id,
                    },
                    json={"connection_id": connection_id, "reason": "user_requested"},
                    timeout=10,
                )
            except Exception as exc:
                logger.warning("Hosted revoke failed for %s: %s (revoking locally anyway)", connection_id, exc)
            aa.storage.revoke_connection(connection_id)
            return jsonify({"revoked": True, "connection_id": connection_id})

        @bp.route("/durations", methods=["GET"])
        def durations():
            return jsonify({"durations": get_duration_options()})

        return bp
