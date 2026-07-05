"""Presence (WebAuthn human-presence step-up) tests.

The verify passthrough (context["presence"]) must tolerate an absent block
(old servers never send one) and must drop a type-malformed block without
failing the verify result; strictness mirrors the consent block and the
active flag: `verified` must be strictly a bool, never coerced.

presence_verified must be strict: only verified is True counts; absent or
malformed presence data is NOT verified. require_presence must fail closed:
403 presence_required on any agent connection whose presence is not
verified, including responses from servers that predate the feature.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import django
from django.conf import settings as dj_settings

if not dj_settings.configured:
    dj_settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], USE_TZ=True)
    django.setup()

import httpx
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from flask import Flask

from agentadmit import auth as auth_mod
from agentadmit.auth import presence_verified, require_presence
from agentadmit.integrations import django_integration as di
from agentadmit.integrations import flask_integration as fi
from agentadmit.storage import MemoryStorage


VERIFIED_PRESENCE = {
    "verified": True,
    "method": "webauthn",
    "uv": True,
    "verified_at": "2026-07-05T00:00:00Z",
}

UNVERIFIED_PRESENCE = {
    "verified": False,
    "method": None,
    "uv": None,
    "verified_at": None,
}


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


ACTIVE_PAYLOAD = {
    "active": True,
    "user_id": "user_123",
    "connection_id": "conn_1",
    "scopes": ["read:things"],
    "agent_label": "Test Agent",
}


# ===========================================================================
# Verify passthrough — context["presence"] from introspection (FastAPI path)
# ===========================================================================

def test_verify_attaches_well_formed_verified_presence_block(monkeypatch):
    payload = dict(ACTIVE_PAYLOAD, presence=dict(VERIFIED_PRESENCE))

    context = _call_verify(monkeypatch, payload)

    assert context["presence"] == VERIFIED_PRESENCE
    assert presence_verified(context) is True


def test_verify_attaches_unverified_presence_block_and_helper_is_false(monkeypatch):
    """A presence-off connection: the block rides along, but never verifies."""
    payload = dict(ACTIVE_PAYLOAD, presence=dict(UNVERIFIED_PRESENCE))

    context = _call_verify(monkeypatch, payload)

    assert context["presence"]["verified"] is False
    assert presence_verified(context) is False


def test_verify_without_presence_block_has_no_presence_key(monkeypatch):
    """Old servers never send `presence`; the SDK must not require it."""
    context = _call_verify(monkeypatch, dict(ACTIVE_PAYLOAD))

    assert context["scopes"] == ["read:things"]
    assert "presence" not in context
    assert presence_verified(context) is False


@pytest.mark.parametrize("bad_presence", [
    {"verified": "true", "method": "webauthn"},  # verified is a string
    {"verified": 1, "method": "webauthn"},  # verified is an int
    {"verified": {}, "method": "webauthn"},  # verified is a dict
    {"method": "webauthn", "uv": True},  # verified missing
    "verified",  # bare string
    1,  # number
    ["verified"],  # list
], ids=["verified-str", "verified-int", "verified-dict", "verified-missing",
        "bare-str", "number", "list"])
def test_verify_drops_type_malformed_presence_without_failing(monkeypatch, bad_presence):
    """The token verdict must survive; the junk presence must not ride along."""
    payload = dict(ACTIVE_PAYLOAD, presence=bad_presence)

    context = _call_verify(monkeypatch, payload)

    assert context["connection"]["connection_id"] == "conn_1"
    assert context["scopes"] == ["read:things"]
    assert "presence" not in context
    assert presence_verified(context) is False


# ===========================================================================
# presence_verified — strict helper semantics
# ===========================================================================

def test_presence_verified_true_only_for_boolean_true():
    assert presence_verified({"presence": {"verified": True}}) is True


@pytest.mark.parametrize("ctx", [
    None,
    {},
    {"presence": None},
    {"presence": {}},
    {"presence": {"verified": False}},
    {"presence": {"verified": "true"}},
    {"presence": {"verified": 1}},
    {"presence": "verified"},
], ids=["none-ctx", "empty-ctx", "presence-none", "presence-empty",
        "verified-false", "verified-str", "verified-int", "presence-str"])
def test_presence_verified_is_false_for_absent_or_malformed(ctx):
    assert presence_verified(ctx) is False


# ===========================================================================
# require_presence — FastAPI dependency (fail closed)
# ===========================================================================

def test_fastapi_require_presence_passes_through_verified_context(monkeypatch):
    payload = dict(ACTIVE_PAYLOAD, presence=dict(VERIFIED_PRESENCE))
    context = _call_verify(monkeypatch, payload)

    checker = require_presence()
    result = checker(agent_ctx=context)

    assert result is context
    assert result["presence"]["verified"] is True


@pytest.mark.parametrize("payload", [
    dict(ACTIVE_PAYLOAD, presence=dict(UNVERIFIED_PRESENCE)),
    dict(ACTIVE_PAYLOAD),  # pre-presence server: no block at all
    dict(ACTIVE_PAYLOAD, presence={"verified": "true"}),  # coerced flag
], ids=["unverified", "absent", "coerced"])
def test_fastapi_require_presence_403s_without_verified_presence(monkeypatch, payload):
    context = _call_verify(monkeypatch, payload)

    checker = require_presence()
    with pytest.raises(HTTPException) as exc_info:
        checker(agent_ctx=context)

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == {
        "error": "presence_required",
        "error_description": "This action requires a connection authorized with human presence verification.",
    }


# ===========================================================================
# require_presence — Flask decorator (fail closed)
# ===========================================================================

@pytest.fixture()
def flask_presence_app(tmp_path):
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

    aa = fi.AgentAdmitFlask(config_path=str(config_file))
    aa.storage = MagicMock()
    aa.storage.get_user.return_value = {"user_id": "user_123"}

    app = Flask(__name__)
    aa.init_app(app)

    @app.route("/api/transfers", methods=["POST"])
    @aa.require_presence()
    def transfers():
        return {"ok": True}

    return aa, app.test_client()


def _mock_flask_introspection(monkeypatch, payload):
    monkeypatch.setattr(
        fi, "_introspect_with_retry",
        MagicMock(return_value=httpx.Response(200, json=payload)),
    )


def test_flask_require_presence_passes_verified_connection(flask_presence_app, monkeypatch):
    aa, client = flask_presence_app
    _mock_flask_introspection(monkeypatch, dict(ACTIVE_PAYLOAD, presence=dict(VERIFIED_PRESENCE)))

    resp = client.post("/api/transfers", headers={"Authorization": "Bearer ag_at_x"})

    assert resp.status_code == 200
    assert resp.get_json() == {"ok": True}


@pytest.mark.parametrize("payload", [
    dict(ACTIVE_PAYLOAD, presence=dict(UNVERIFIED_PRESENCE)),
    dict(ACTIVE_PAYLOAD),  # pre-presence server: no block at all
    dict(ACTIVE_PAYLOAD, presence={"verified": 1}),  # coerced flag
], ids=["unverified", "absent", "coerced"])
def test_flask_require_presence_403s_without_verified_presence(flask_presence_app, monkeypatch, payload):
    aa, client = flask_presence_app
    _mock_flask_introspection(monkeypatch, payload)

    resp = client.post("/api/transfers", headers={"Authorization": "Bearer ag_at_x"})

    assert resp.status_code == 403
    assert resp.get_json() == {
        "error": "presence_required",
        "error_description": "This action requires a connection authorized with human presence verification.",
    }


def test_flask_require_presence_401s_on_missing_or_non_agent_token(flask_presence_app):
    """Mirrors require_scope: no token / non-agent token is 401, not 403."""
    aa, client = flask_presence_app

    resp = client.post("/api/transfers")
    assert resp.status_code == 401

    resp = client.post("/api/transfers", headers={"Authorization": "Bearer some_session_token"})
    assert resp.status_code == 401


# ===========================================================================
# require_presence — Django decorator (fail closed)
# ===========================================================================

@pytest.fixture()
def django_presence_env(monkeypatch):
    fake_config = SimpleNamespace(token_prefix_access="ag_at_")
    monkeypatch.setattr(di, "_config", fake_config)
    monkeypatch.setattr(di, "_init", lambda: None)

    @di.require_presence()
    def view(request):
        return "VIEW_RESPONSE"

    return view


def _django_request(auth=None):
    meta = {"HTTP_AUTHORIZATION": auth} if auth else {}
    return SimpleNamespace(META=meta)


def test_django_require_presence_passes_verified_connection(django_presence_env, monkeypatch):
    view = django_presence_env
    ctx = {
        "user": {"user_id": "u1"},
        "connection": {"connection_id": "c1"},
        "scopes": ["read:things"],
        "presence": dict(VERIFIED_PRESENCE),
    }
    monkeypatch.setattr(di, "_validate_agent_token", MagicMock(return_value=ctx))

    request = _django_request("Bearer ag_at_good")
    assert view(request) == "VIEW_RESPONSE"
    assert request.agentadmit_user["auth_type"] == "agent"
    assert request.agentadmit_user["presence"]["verified"] is True


@pytest.mark.parametrize("ctx", [
    {"user": {}, "connection": {}, "scopes": [], "presence": dict(UNVERIFIED_PRESENCE)},
    {"user": {}, "connection": {}, "scopes": []},  # pre-presence server
], ids=["unverified", "absent"])
def test_django_require_presence_403s_without_verified_presence(django_presence_env, monkeypatch, ctx):
    view = django_presence_env
    monkeypatch.setattr(di, "_validate_agent_token", MagicMock(return_value=ctx))

    response = view(_django_request("Bearer ag_at_x"))

    assert response.status_code == 403
    assert b"presence_required" in response.content


def test_django_require_presence_401s_on_missing_or_non_agent_token(django_presence_env):
    """Mirrors require_scope: no token / non-agent token is 401, not 403."""
    view = django_presence_env

    assert view(_django_request()).status_code == 401
    assert view(_django_request("Bearer some_session_token")).status_code == 401
