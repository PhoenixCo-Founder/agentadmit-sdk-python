"""Declared purpose tests.

Declared purpose: the user-facing reason recorded on the grant at the
consent moment. Review-time record only, never an enforcement input;
authorization decisions ride scopes, connection status, and consent.

The mounted generate-token routes (FastAPI / Flask / Django) accept an
optional `purpose` (1-300 chars), forward it to the hosted mint when
provided, and OMIT it when absent (the hosted service rejects explicit
nulls). Over-long purposes are rejected locally with 400 invalid_request
before any hosted call. The hosted /verify response carries a nullable
`purpose`; it parses on the typed VerifyResponse model (None when absent)
and rides along on the agent context like consent/presence do.

The mint routes also persist `purpose` in the LOCAL connection store (the
record GET /connections is served from), so the admin panel listing can
surface it: present when declared, None when absent.
"""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import django
from django.conf import settings as dj_settings

if not dj_settings.configured:
    dj_settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], USE_TZ=True)
    django.setup()

import httpx
import pytest
from fastapi import FastAPI
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient

from agentadmit import auth as auth_mod
from agentadmit import routes as routes_mod
from agentadmit.integrations import django_integration as di
from agentadmit.integrations import flask_integration as fi
from agentadmit.models import VerifyResponse
from agentadmit.storage import MemoryStorage


PURPOSE = "Book my Tuesday workout sessions"
PURPOSE_301 = "p" * 301
PURPOSE_300 = "p" * 300


# ===========================================================================
# FastAPI router — /connections/generate-token forwards / omits / rejects
# ===========================================================================

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


def test_fastapi_generate_token_forwards_purpose(generate_app):
    make_client, captured, storage = generate_app
    client, token_path = make_client()

    resp = client.post(token_path, json={"scopes": ["read:things"], "purpose": PURPOSE})

    assert resp.status_code == 200
    assert captured["path"] == "/api/v1/apps/app_test/token"
    assert captured["json"]["purpose"] == PURPOSE
    storage.store_connection.assert_called_once()


def test_fastapi_generate_token_omits_absent_purpose(generate_app):
    make_client, captured, storage = generate_app
    client, token_path = make_client()

    resp = client.post(token_path, json={"scopes": ["read:things"]})

    assert resp.status_code == 200
    # The hosted service rejects explicit nulls — absent purpose must be omitted
    assert "purpose" not in captured["json"]
    assert captured["json"] == {"user_id": "u1", "scopes": ["read:things"], "role": "user"}


def test_fastapi_generate_token_omits_explicit_null_purpose(generate_app):
    make_client, captured, storage = generate_app
    client, token_path = make_client()

    resp = client.post(token_path, json={"scopes": ["read:things"], "purpose": None})

    assert resp.status_code == 200
    assert "purpose" not in captured["json"]


def test_fastapi_generate_token_accepts_300_char_purpose(generate_app):
    make_client, captured, storage = generate_app
    client, token_path = make_client()

    resp = client.post(token_path, json={"scopes": ["read:things"], "purpose": PURPOSE_300})

    assert resp.status_code == 200
    assert captured["json"]["purpose"] == PURPOSE_300


@pytest.mark.parametrize("bad_purpose", [PURPOSE_301, ""], ids=["301-chars", "empty"])
def test_fastapi_generate_token_rejects_out_of_range_purpose(generate_app, bad_purpose):
    make_client, captured, storage = generate_app
    client, token_path = make_client()

    resp = client.post(token_path, json={"scopes": ["read:things"], "purpose": bad_purpose})

    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "invalid_request"
    assert captured == {}                      # hosted mint never called
    storage.store_connection.assert_not_called()


def test_fastapi_purpose_does_not_interact_with_presence_hook(generate_app):
    """Purpose is carried on the same body but has no interaction with the
    presence machinery: the hook still runs, still allows, and the mint
    forwards purpose unchanged. An over-long purpose is rejected before the
    hook, so it never spends an attestation."""
    make_client, captured, storage = generate_app
    seen = {}

    def allow_hook(*, request, current_user, body):
        seen["purpose"] = body.purpose

    client, token_path = make_client(allow_hook)

    resp = client.post(token_path, json={
        "scopes": ["read:things"],
        "purpose": PURPOSE,
        "presence_attestation_id": "patt_ok",
    })
    assert resp.status_code == 200
    assert seen == {"purpose": PURPOSE}
    assert captured["json"]["purpose"] == PURPOSE

    # Over-long purpose: rejected before the hook runs
    seen.clear()
    resp = client.post(token_path, json={"scopes": ["read:things"], "purpose": PURPOSE_301})
    assert resp.status_code == 400
    assert seen == {}


# ===========================================================================
# Flask blueprint — /connections/generate-token forwards / omits / rejects
# ===========================================================================

@pytest.fixture()
def flask_app(monkeypatch, tmp_path):
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

    from flask import Flask

    aa = fi.AgentAdmitFlask(
        config_path=str(config_file),
        get_current_user=lambda: {"user_id": "u1"},
    )
    aa.storage = MagicMock()

    app = Flask(__name__)
    aa.init_app(app)
    return aa, app.test_client()


def test_flask_generate_token_forwards_purpose(flask_app, monkeypatch):
    aa, client = flask_app
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["json"] = json
        return httpx.Response(200, json={"token": "ag_ct_new", "connection_id": "conn_9", "expires_in": 3600})

    monkeypatch.setattr(fi.httpx, "post", fake_post)
    resp = client.post(
        f"{aa.config.route_prefix}/connections/generate-token",
        json={"scopes": ["read:things"], "purpose": PURPOSE},
    )
    assert resp.status_code == 200
    assert captured["json"]["purpose"] == PURPOSE


def test_flask_generate_token_omits_absent_purpose(flask_app, monkeypatch):
    aa, client = flask_app
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["json"] = json
        return httpx.Response(200, json={"token": "ag_ct_new", "connection_id": "conn_9", "expires_in": 3600})

    monkeypatch.setattr(fi.httpx, "post", fake_post)
    resp = client.post(
        f"{aa.config.route_prefix}/connections/generate-token",
        json={"scopes": ["read:things"]},
    )
    assert resp.status_code == 200
    assert "purpose" not in captured["json"]


@pytest.mark.parametrize("bad_purpose", [PURPOSE_301, "", 42], ids=["301-chars", "empty", "non-str"])
def test_flask_generate_token_rejects_bad_purpose(flask_app, monkeypatch, bad_purpose):
    aa, client = flask_app
    hosted_post = MagicMock()
    monkeypatch.setattr(fi.httpx, "post", hosted_post)

    resp = client.post(
        f"{aa.config.route_prefix}/connections/generate-token",
        json={"scopes": ["read:things"], "purpose": bad_purpose},
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_request"
    hosted_post.assert_not_called()
    aa.storage.store_connection.assert_not_called()


# ===========================================================================
# Django view — generate_token_view forwards / omits / rejects
# ===========================================================================

@pytest.fixture()
def django_env(monkeypatch):
    fake_config = SimpleNamespace(
        app_id="app_test",
        api_key="aa_test_dummy",
        agentadmit_api_url="https://agentadmit.example",
        agentadmit_verify_url="https://agentadmit.example/api/v1/verify",
        token_prefix_access="ag_at_",
        user_lookup_field="user_id",
        connection_token_ttl=3600,
    )
    storage = MagicMock()
    monkeypatch.setattr(di, "_init", lambda: None)
    monkeypatch.setattr(di, "_config", fake_config)
    monkeypatch.setattr(di, "_storage", storage)
    monkeypatch.setattr(di, "_get_current_user", lambda request: {"user_id": "u1"})
    monkeypatch.setattr(di, "_validate_scopes", lambda scopes, user: (True, []))
    monkeypatch.setattr(di, "_determine_role", lambda user: "user")
    monkeypatch.setattr(di, "_require_token_mint_presence", None)
    return storage


def _django_post(body: bytes):
    return SimpleNamespace(method="POST", body=body, META={})


def test_django_generate_token_forwards_purpose(django_env, monkeypatch):
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["json"] = json
        return httpx.Response(200, json={"token": "ag_ct_new", "connection_id": "conn_9", "expires_in": 3600})

    monkeypatch.setattr(di.httpx, "post", fake_post)

    response = di.generate_token_view(_django_post(
        b'{"scopes":["read:things"],"purpose":"Book my Tuesday workout sessions"}'))

    assert response.status_code == 200
    assert captured["json"]["purpose"] == PURPOSE


def test_django_generate_token_omits_absent_purpose(django_env, monkeypatch):
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["json"] = json
        return httpx.Response(200, json={"token": "ag_ct_new", "connection_id": "conn_9", "expires_in": 3600})

    monkeypatch.setattr(di.httpx, "post", fake_post)

    response = di.generate_token_view(_django_post(b'{"scopes":["read:things"]}'))

    assert response.status_code == 200
    assert "purpose" not in captured["json"]


def test_django_generate_token_rejects_301_char_purpose(django_env, monkeypatch):
    storage = django_env
    hosted_post = MagicMock()
    monkeypatch.setattr(di.httpx, "post", hosted_post)

    body = ('{"scopes":["read:things"],"purpose":"%s"}' % PURPOSE_301).encode()
    response = di.generate_token_view(_django_post(body))

    assert response.status_code == 400
    assert b"invalid_request" in response.content
    hosted_post.assert_not_called()
    storage.store_connection.assert_not_called()


# ===========================================================================
# Local connection store + GET /connections — purpose persisted at mint
# ===========================================================================
#
# The listing is served from LOCAL storage, not the hosted mint — so the
# store_connection write at mint time must carry the declared purpose for
# the admin panel to ever show it. End-to-end against a real MemoryStorage:
# mint with purpose → the local record and the listing carry it; mint
# without → None.

@pytest.fixture()
def generate_app_memory(monkeypatch):
    """FastAPI app with a real MemoryStorage backing mint + listing."""
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
    storage = MemoryStorage()
    monkeypatch.setattr(routes_mod, "_get_storage", lambda: storage)
    monkeypatch.setattr(routes_mod, "check_connection_cap", lambda *a, **k: None)

    counter = {"n": 0}

    def fake_hosted(method, path, json=None, timeout=10.0, authenticated=True):
        counter["n"] += 1
        return httpx.Response(
            201,
            json={"token": "ag_ct_new", "connection_id": f"conn_{counter['n']}",
                  "expires_in": 3600},
        )

    monkeypatch.setattr(routes_mod, "_call_hosted_service", fake_hosted)

    _wellknown, router = routes_mod.create_agentadmit_router(
        get_current_user=lambda: {"user_id": "u1"},
    )
    app = FastAPI()
    app.include_router(router)
    token_path = next(r.path for r in router.routes
                      if r.path.endswith("/connections/generate-token"))
    list_path = next(r.path for r in router.routes
                     if r.path.endswith("/connections") and "GET" in r.methods)
    return TestClient(app), token_path, list_path, storage


def test_fastapi_mint_persists_purpose_and_listing_surfaces_it(generate_app_memory):
    client, token_path, list_path, storage = generate_app_memory

    resp = client.post(token_path, json={"scopes": ["read:things"], "purpose": PURPOSE})
    assert resp.status_code == 200

    records = storage.list_connections("u1")
    assert len(records) == 1
    assert records[0]["purpose"] == PURPOSE

    listing = client.get(list_path).json()
    assert listing["total"] == 1
    assert listing["connections"][0]["purpose"] == PURPOSE


def test_fastapi_mint_without_purpose_lists_null(generate_app_memory):
    client, token_path, list_path, storage = generate_app_memory

    resp = client.post(token_path, json={"scopes": ["read:things"]})
    assert resp.status_code == 200

    assert storage.list_connections("u1")[0]["purpose"] is None
    listing = client.get(list_path).json()
    assert listing["connections"][0]["purpose"] is None


def _hosted_mint_ok(url, headers=None, json=None, timeout=None):
    return httpx.Response(
        200, json={"token": "ag_ct_new", "connection_id": "conn_9", "expires_in": 3600})


def test_flask_mint_persists_purpose_and_listing_surfaces_it(flask_app, monkeypatch):
    aa, client = flask_app
    aa.storage = MemoryStorage()
    monkeypatch.setattr(fi.httpx, "post", _hosted_mint_ok)

    resp = client.post(
        f"{aa.config.route_prefix}/connections/generate-token",
        json={"scopes": ["read:things"], "purpose": PURPOSE},
    )
    assert resp.status_code == 200

    records = aa.storage.list_connections("u1")
    assert len(records) == 1
    assert records[0]["purpose"] == PURPOSE

    listing = client.get(f"{aa.config.route_prefix}/connections").get_json()
    assert listing["total"] == 1
    assert listing["connections"][0]["purpose"] == PURPOSE


def test_flask_mint_without_purpose_lists_null(flask_app, monkeypatch):
    aa, client = flask_app
    aa.storage = MemoryStorage()
    monkeypatch.setattr(fi.httpx, "post", _hosted_mint_ok)

    resp = client.post(
        f"{aa.config.route_prefix}/connections/generate-token",
        json={"scopes": ["read:things"]},
    )
    assert resp.status_code == 200

    assert aa.storage.list_connections("u1")[0]["purpose"] is None
    listing = client.get(f"{aa.config.route_prefix}/connections").get_json()
    assert listing["connections"][0]["purpose"] is None


def test_django_mint_persists_purpose_and_listing_surfaces_it(django_env, monkeypatch):
    memory = MemoryStorage()
    monkeypatch.setattr(di, "_storage", memory)
    monkeypatch.setattr(di.httpx, "post", _hosted_mint_ok)

    response = di.generate_token_view(_django_post(
        b'{"scopes":["read:things"],"purpose":"Book my Tuesday workout sessions"}'))
    assert response.status_code == 200

    records = memory.list_connections("u1")
    assert len(records) == 1
    assert records[0]["purpose"] == PURPOSE

    listing = json.loads(di.connections_view(
        SimpleNamespace(method="GET", META={})).content)
    assert listing["total"] == 1
    assert listing["connections"][0]["purpose"] == PURPOSE


def test_django_mint_without_purpose_lists_null(django_env, monkeypatch):
    memory = MemoryStorage()
    monkeypatch.setattr(di, "_storage", memory)
    monkeypatch.setattr(di.httpx, "post", _hosted_mint_ok)

    response = di.generate_token_view(_django_post(b'{"scopes":["read:things"]}'))
    assert response.status_code == 200

    assert memory.list_connections("u1")[0]["purpose"] is None
    listing = json.loads(di.connections_view(
        SimpleNamespace(method="GET", META={})).content)
    assert listing["connections"][0]["purpose"] is None


# ===========================================================================
# VerifyResponse model — typed verify result parses purpose
# ===========================================================================

ACTIVE_PAYLOAD = {
    "active": True,
    "user_id": "user_123",
    "connection_id": "conn_1",
    "scopes": ["read:things"],
    "agent_label": "Test Agent",
}


def test_verify_response_model_parses_purpose():
    parsed = VerifyResponse.model_validate(dict(ACTIVE_PAYLOAD, purpose=PURPOSE))
    assert parsed.active is True
    assert parsed.purpose == PURPOSE
    assert parsed.scopes == ["read:things"]


def test_verify_response_model_purpose_defaults_none_when_absent():
    parsed = VerifyResponse.model_validate(dict(ACTIVE_PAYLOAD))
    assert parsed.active is True
    assert parsed.purpose is None


def test_verify_response_model_accepts_explicit_null_purpose():
    parsed = VerifyResponse.model_validate(dict(ACTIVE_PAYLOAD, purpose=None))
    assert parsed.purpose is None


def test_verify_response_model_ignores_unknown_fields():
    parsed = VerifyResponse.model_validate(dict(ACTIVE_PAYLOAD, some_future_field=1))
    assert parsed.active is True


# ===========================================================================
# Verify passthrough — context["purpose"] rides along (FastAPI/Flask/Django)
# ===========================================================================

def _call_verify(monkeypatch, introspection_payload):
    """Run get_agentadmit_user against a canned introspection payload."""
    fake_config = SimpleNamespace(
        app_id="app_test",
        api_key="aa_test_key",
        agentadmit_verify_url="https://agentadmit.example/api/v1/verify",
        token_prefix_access="ag_at_",
        user_lookup_field="user_id",
        max_retries=0,
    )
    monkeypatch.setattr(auth_mod, "get_config", lambda: fake_config)

    storage = MemoryStorage()
    storage.add_test_user("user_123", {"user_id": "user_123"})
    monkeypatch.setattr(auth_mod, "_get_storage", lambda: storage)

    monkeypatch.setattr(
        auth_mod, "_introspect_with_retry",
        lambda *a, **kw: httpx.Response(200, json=introspection_payload),
    )
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="ag_at_sometoken")
    return auth_mod.get_agentadmit_user(creds)


def test_fastapi_verify_attaches_purpose_to_context(monkeypatch):
    context = _call_verify(monkeypatch, dict(ACTIVE_PAYLOAD, purpose=PURPOSE))

    assert context["purpose"] == PURPOSE
    assert context["scopes"] == ["read:things"]


def test_fastapi_verify_without_purpose_has_no_purpose_key(monkeypatch):
    """Older servers / purposeless grants never send `purpose`."""
    context = _call_verify(monkeypatch, dict(ACTIVE_PAYLOAD))

    assert "purpose" not in context


@pytest.mark.parametrize("bad_purpose", [1, {"text": "x"}, ["x"], True],
                         ids=["int", "dict", "list", "bool"])
def test_fastapi_verify_drops_non_string_purpose_without_failing(monkeypatch, bad_purpose):
    """The token verdict must survive; junk purpose must not ride along."""
    context = _call_verify(monkeypatch, dict(ACTIVE_PAYLOAD, purpose=bad_purpose))

    assert context["connection"]["connection_id"] == "conn_1"
    assert "purpose" not in context


def test_flask_verify_attaches_purpose_to_context(flask_app, monkeypatch):
    aa, _client = flask_app
    aa.storage.get_user.return_value = {"user_id": "user_123"}
    monkeypatch.setattr(
        fi, "_introspect_with_retry",
        MagicMock(return_value=httpx.Response(200, json=dict(ACTIVE_PAYLOAD, purpose=PURPOSE))),
    )

    ctx = aa._validate_agent_token("ag_at_x")

    assert ctx["purpose"] == PURPOSE


def test_django_verify_attaches_purpose_to_context(django_env, monkeypatch):
    monkeypatch.setattr(
        di, "_introspect_with_retry",
        MagicMock(return_value=httpx.Response(200, json=dict(ACTIVE_PAYLOAD, purpose=PURPOSE))),
    )
    django_env.get_user.return_value = {"user_id": "user_123"}

    ctx = di._validate_agent_token("ag_at_x")

    assert ctx["purpose"] == PURPOSE
