"""Regression tests for DELETE /connections/{id} (user revoke).

Enforcement happens at the hosted service — if the hosted revoke fails, the
agent's token still verifies. The route previously swallowed hosted failures
("revoking locally anyway") and reported revoked=True, which is false
comfort for the exact user action that most needs to be truthful.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from agentadmit import routes as routes_mod


@pytest.fixture()
def revoke_app(monkeypatch):
    """App with the SDK router mounted; hosted revoke returns a canned status."""
    fake_config = SimpleNamespace(
        app_id="app_test",
        app_name="Test App",
        api_key="aa_test_key",
        api_base_url="http://testserver",
        agentadmit_api_url="https://agentadmit.example",
        route_prefix="/agentadmit",
        default_tier="standard",
        user_lookup_field="user_id",
        token_prefix_access="ag_at_",
        scopes=[SimpleNamespace(name="read:things", description="d",
                                category="c", role="user")],
        tiers=[],
    )
    monkeypatch.setattr(routes_mod, "get_config", lambda: fake_config)

    storage = MagicMock()
    storage.get_connection.return_value = {
        "connection_id": "conn_1",
        "user_id": "u1",
        "status": "active",
    }
    monkeypatch.setattr(routes_mod, "_get_storage", lambda: storage)

    hosted = {"status": 200, "calls": 0}

    def fake_hosted(method, path, json=None, timeout=10.0, authenticated=True):
        hosted["calls"] += 1
        return httpx.Response(hosted["status"], json={"ok": hosted["status"] < 300})

    monkeypatch.setattr(routes_mod, "_call_hosted_service", fake_hosted)

    def fake_current_user():
        return {"user_id": "u1", "email": "u1@test"}

    _wellknown, router = routes_mod.create_agentadmit_router(
        get_current_user=fake_current_user,
    )
    app = FastAPI()
    app.include_router(router)
    delete_path = next(
        r.path for r in router.routes
        if r.path.endswith("/connections/{connection_id}") and "DELETE" in r.methods
    )
    return TestClient(app), delete_path.replace("{connection_id}", "conn_1"), storage, hosted


def test_revoke_success(revoke_app):
    client, path, storage, hosted = revoke_app
    hosted["status"] = 200

    resp = client.delete(path)

    assert resp.status_code == 200
    assert resp.json()["revoked"] is True
    storage.revoke_connection.assert_called_once_with("conn_1")


def test_hosted_failure_returns_502_and_leaves_connection(revoke_app):
    client, path, storage, hosted = revoke_app
    hosted["status"] = 500

    resp = client.delete(path)

    assert resp.status_code == 502
    assert resp.json()["detail"]["error"] == "revoke_failed"
    storage.revoke_connection.assert_not_called()


def test_hosted_404_still_revokes_locally(revoke_app):
    client, path, storage, hosted = revoke_app
    hosted["status"] = 404

    resp = client.delete(path)

    assert resp.status_code == 200
    assert resp.json()["revoked"] is True
    storage.revoke_connection.assert_called_once_with("conn_1")
