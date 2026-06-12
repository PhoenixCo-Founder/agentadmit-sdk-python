"""Regression tests for the /token exchange handler.

v1.1.0 forwarded optional agent fields as explicit JSON nulls, which the
hosted /api/v1/exchange rejects with HTTP 400 "Expected string, received
null". The handler must omit absent optional fields entirely.

Also pins version reporting: __version__ must come from package metadata,
not a hand-maintained string (v1.1.0 on PyPI reported "0.1.0").
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

import agentadmit
from agentadmit import routes as routes_mod


@pytest.fixture()
def exchange_app(monkeypatch):
    """App with the SDK router mounted; hosted calls captured, not sent."""
    fake_config = SimpleNamespace(
        app_id="app_test",
        app_name="Test App",
        api_key="aa_test_key",
        api_base_url="http://testserver",
        agentadmit_api_url="https://agentadmit.example",
        route_prefix="/agentadmit",
        default_tier="standard",
        scopes=[SimpleNamespace(name="read:things", description="d",
                                category="c", role="user")],
        tiers=[],
    )
    monkeypatch.setattr(routes_mod, "get_config", lambda: fake_config)
    monkeypatch.setattr(routes_mod, "_get_storage", lambda: MagicMock())

    captured = {}

    def fake_hosted(method, path, json=None, timeout=10.0, authenticated=True):
        captured["method"] = method
        captured["path"] = path
        captured["json"] = json
        captured["authenticated"] = authenticated
        return httpx.Response(
            200,
            json={"access_token": "ag_at_test", "token_type": "Bearer",
                  "scopes": ["read:things"], "connection_id": "conn_test"},
        )

    monkeypatch.setattr(routes_mod, "_call_hosted_service", fake_hosted)

    def fake_current_user():
        return {"user_id": "u1", "email": "u1@test"}

    _wellknown, router = routes_mod.create_agentadmit_router(
        get_current_user=fake_current_user,
    )
    app = FastAPI()
    app.include_router(router)
    token_path = next(r.path for r in router.routes if r.path.endswith("/token"))
    return TestClient(app), token_path, captured


def test_exchange_omits_absent_optional_fields(exchange_app):
    client, token_path, captured = exchange_app
    resp = client.post(token_path, json={
        "grant_type": "connection_token",
        "connection_token": "ag_ct_abc",
    })
    assert resp.status_code == 200
    assert captured["path"] == "/api/v1/exchange"
    assert captured["authenticated"] is False
    # The hosted service rejects explicit nulls — absent fields must be omitted
    assert captured["json"] == {"token": "ag_ct_abc"}
    assert None not in captured["json"].values()


def test_exchange_forwards_provided_optional_fields(exchange_app):
    client, token_path, captured = exchange_app
    resp = client.post(token_path, json={
        "grant_type": "connection_token",
        "connection_token": "ag_ct_abc",
        "agent_label": "My Agent",
        "agent_id": "agent_123",
        "agent_metadata": {"model": "claude"},
    })
    assert resp.status_code == 200
    assert captured["json"] == {
        "token": "ag_ct_abc",
        "agent_label": "My Agent",
        "agent_id": "agent_123",
        "agent_metadata": {"model": "claude"},
    }


def test_version_not_stale():
    # The published 1.1.0 wheel reported "0.1.0" — version must now come
    # from package metadata (one bump in pyproject.toml covers everything).
    assert agentadmit.__version__ != "0.1.0"
    assert routes_mod.AGENTADMIT_VERSION == agentadmit.__version__


def test_version_matches_installed_metadata():
    from importlib.metadata import PackageNotFoundError, version
    try:
        installed = version("agentadmit")
    except PackageNotFoundError:
        pytest.skip("agentadmit not installed in this environment")
    assert agentadmit.__version__ == installed
