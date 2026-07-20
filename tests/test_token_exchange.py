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
from fastapi import FastAPI, HTTPException
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


@pytest.fixture()
def generate_app(monkeypatch):
    """App with the SDK mint route mounted; hosted calls captured, not sent."""
    fake_config = SimpleNamespace(
        app_id="app_test",
        app_name="Test App",
        api_key="aa_test_key",
        api_base_url="http://testserver",
        agentadmit_api_url="https://agentadmit.example",
        route_prefix="/agentadmit",
        default_tier="standard",
        user_lookup_field="user_id",
        connection_token_ttl=3600,
        scopes=[SimpleNamespace(name="read:things", description="d",
                                category="c", role="user")],
        tiers=[],
    )
    monkeypatch.setattr(routes_mod, "get_config", lambda: fake_config)
    storage = MagicMock()
    monkeypatch.setattr(routes_mod, "_get_storage", lambda: storage)
    monkeypatch.setattr(routes_mod, "check_connection_cap", lambda *a, **k: None)

    captured = {}

    def fake_hosted(method, path, json=None, timeout=10.0, authenticated=True):
        captured["method"] = method
        captured["path"] = path
        captured["json"] = json
        captured["authenticated"] = authenticated
        return httpx.Response(
            201,
            json={"token": "ag_ct_new", "connection_id": "conn_1", "expires_in": 3600},
        )

    monkeypatch.setattr(routes_mod, "_call_hosted_service", fake_hosted)

    def make_client(require_token_mint_presence=None):
        def fake_current_user():
            return {"user_id": "u1", "email": "u1@test"}

        _wellknown, router = routes_mod.create_agentadmit_router(
            get_current_user=fake_current_user,
            require_token_mint_presence=require_token_mint_presence,
        )
        app = FastAPI()
        app.include_router(router)
        token_path = next(r.path for r in router.routes if r.path.endswith("/connections/generate-token"))
        return TestClient(app), token_path

    return make_client, captured, storage


def test_generate_token_without_presence_hook_stays_backward_compatible(generate_app):
    make_client, captured, storage = generate_app
    client, token_path = make_client()

    resp = client.post(token_path, json={"scopes": ["read:things"]})

    assert resp.status_code == 200
    assert captured["path"] == "/api/v1/apps/app_test/token"
    assert captured["json"] == {"user_id": "u1", "scopes": ["read:things"], "role": "user"}
    storage.store_connection.assert_called_once()


def test_generate_token_presence_hook_denial_blocks_hosted_mint_and_storage(generate_app):
    make_client, captured, storage = generate_app
    seen = {}

    def require_presence(*, request, current_user, body):
        seen["user"] = current_user["user_id"]
        seen["presence_attestation_id"] = body.presence_attestation_id
        raise HTTPException(
            status_code=403,
            detail={
                "error": "presence_attestation_required",
                "error_description": "Confirm human presence before generating a connection token.",
            },
        )

    client, token_path = make_client(require_presence)

    resp = client.post(token_path, json={"scopes": ["read:things"]})

    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "presence_attestation_required"
    assert seen == {"user": "u1", "presence_attestation_id": None}
    assert captured == {}
    storage.store_connection.assert_not_called()


def test_generate_token_presence_hook_acceptance_allows_hosted_mint(generate_app):
    make_client, captured, storage = generate_app
    seen = {}

    def require_presence(*, request, current_user, body):
        seen["user"] = current_user["user_id"]
        seen["presence_attestation_id"] = body.presence_attestation_id

    client, token_path = make_client(require_presence)

    resp = client.post(token_path, json={
        "scopes": ["read:things"],
        "presence_attestation_id": "patt_ok",
    })

    assert resp.status_code == 200
    assert seen == {"user": "u1", "presence_attestation_id": "patt_ok"}
    assert captured["path"] == "/api/v1/apps/app_test/token"
    storage.store_connection.assert_called_once()


def test_generate_token_misconfigured_hook_fails_closed_not_200(generate_app):
    """A hook that RETURNS a value instead of raising to deny must fail closed
    (500 + no mint), never let the truthy return pass through as a success."""
    make_client, captured, storage = generate_app

    def bad_hook(*, request, current_user, body):
        # Operator mistake: returns a dict thinking it denies, instead of raising.
        return {"error": "denied"}

    client, token_path = make_client(bad_hook)

    resp = client.post(token_path, json={"scopes": ["read:things"]})

    assert resp.status_code == 500
    assert resp.json()["detail"]["error"] == "presence_hook_misconfigured"
    assert captured == {}                      # hosted mint never called
    storage.store_connection.assert_not_called()
