"""Regression tests for the Flask integration's framework-parity fixes.

Covers: 429/unavailable introspection surfaces 502 (not 401), token exchange
omits absent optional fields (hosted service rejects explicit nulls), the
revoke route requires hosted success before claiming revoked, and token
generation stores a local connection record so /connections and revoke work.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
from flask import Flask

from agentadmit.exceptions import IntrospectionUnavailableError, RateLimitError
from agentadmit.integrations import flask_integration as fi


@pytest.fixture()
def aa_app(monkeypatch, tmp_path):
    config_file = tmp_path / "agentadmit.yaml"
    config_file.write_text("\n".join([
        "app_id: app_test",
        "app_name: Test App",
        "api_key: aa_test_dummy",
        "api_base_url: http://localhost:8000",
        "agentadmit_api_url: https://agentadmit.example",
        "storage:",
        "  backend: memory",
        "scopes:",
        "  - name: read:things",
        "    description: Read things",
        "    category: Things",
        "    role: user",
    ]))

    current_user = {"user_id": "u1"}
    aa = fi.AgentAdmitFlask(
        config_path=str(config_file),
        get_current_user=lambda: current_user,
    )
    aa.storage = MagicMock()
    aa.storage.get_connection.return_value = {
        "connection_id": "conn_1", "user_id": "u1", "status": "active",
    }

    app = Flask(__name__)
    aa.init_app(app)

    @app.route("/api/things")
    @aa.require_scope("read:things")
    def things():
        return {"ok": True}

    return aa, app.test_client()


def test_rate_limited_introspection_returns_502_not_401(aa_app, monkeypatch):
    aa, client = aa_app
    monkeypatch.setattr(
        fi, "_introspect_with_retry",
        MagicMock(side_effect=RateLimitError("budget exhausted")),
    )
    resp = client.get("/api/things", headers={"Authorization": "Bearer ag_at_x"})
    assert resp.status_code == 502
    assert resp.get_json()["error"] == "rate_limited"


def test_unreachable_introspection_returns_502(aa_app, monkeypatch):
    aa, client = aa_app
    monkeypatch.setattr(
        fi, "_introspect_with_retry",
        MagicMock(side_effect=ConnectionError("boom")),
    )
    resp = client.get("/api/things", headers={"Authorization": "Bearer ag_at_x"})
    assert resp.status_code == 502
    assert resp.get_json()["error"] == "service_unavailable"


def test_invalid_token_still_401(aa_app, monkeypatch):
    aa, client = aa_app
    monkeypatch.setattr(
        fi, "_introspect_with_retry",
        MagicMock(return_value=httpx.Response(200, json={"active": False, "error": "token_expired"})),
    )
    resp = client.get("/api/things", headers={"Authorization": "Bearer ag_at_x"})
    assert resp.status_code == 401
    assert "token_expired" in resp.get_json()["error_description"]


def test_exchange_omits_absent_optional_fields(aa_app, monkeypatch):
    aa, client = aa_app
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["json"] = json
        return httpx.Response(200, json={"access_token": "ag_at_t", "scopes": ["read:things"]})

    monkeypatch.setattr(fi.httpx, "post", fake_post)
    resp = client.post(
        f"{aa.config.route_prefix}/token",
        json={"grant_type": "connection_token", "connection_token": "ag_ct_abc"},
    )
    assert resp.status_code == 200
    assert captured["json"] == {"token": "ag_ct_abc"}
    assert None not in captured["json"].values()


def test_generate_token_stores_local_connection(aa_app, monkeypatch):
    aa, client = aa_app
    monkeypatch.setattr(fi.httpx, "post", lambda *a, **k: httpx.Response(
        200, json={"token": "ag_ct_new", "connection_id": "conn_9", "expires_in": 3600}))

    resp = client.post(
        f"{aa.config.route_prefix}/connections/generate-token",
        json={"scopes": ["read:things"]},
    )
    assert resp.status_code == 200
    stored = aa.storage.store_connection.call_args[0][0]
    assert stored["connection_id"] == "conn_9"
    assert stored["status"] == "active"


def test_revoke_fails_honestly_when_hosted_fails(aa_app, monkeypatch):
    aa, client = aa_app
    monkeypatch.setattr(fi.httpx, "post", lambda *a, **k: httpx.Response(500, json={}))

    resp = client.delete(f"{aa.config.route_prefix}/connections/conn_1")
    assert resp.status_code == 502
    assert resp.get_json()["revoked"] is False
    aa.storage.revoke_connection.assert_not_called()


def test_revoke_succeeds_and_revokes_locally(aa_app, monkeypatch):
    aa, client = aa_app
    monkeypatch.setattr(fi.httpx, "post", lambda *a, **k: httpx.Response(200, json={"revoked": True}))

    resp = client.delete(f"{aa.config.route_prefix}/connections/conn_1")
    assert resp.status_code == 200
    assert resp.get_json()["revoked"] is True
    aa.storage.revoke_connection.assert_called_once_with("conn_1")
