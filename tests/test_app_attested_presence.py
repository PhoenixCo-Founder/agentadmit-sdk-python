"""App-attested presence: typed forwarding at token issuance.

Apps that gate their mint flow with their own embedded passkey ceremony can
attest the ceremony fact at token issuance. The `require_token_mint_presence`
hook may now RETURN an `AppAttestedPresence` to allow the mint AND forward
the fact to the hosted service as
`presence: {verified: true, uv: true, method, verified_at}` (stored
provenance-marked `app:<method>`). Returning None still allows without a
fact; raising still denies; any OTHER return value still fails closed (500,
no mint) — the v1.6.0 misconfigured-hook contract is preserved.

The typed model prevents the proven production-outage class by construction:
`verified_at` must be timezone-aware (naive timestamps serialize without an
offset and the hosted mint rejects them with 400), and `method` is validated
against the hosted contract (`^[a-z0-9_]+$`, 1-60) before any hosted call.

The forwarded fact is persisted in the LOCAL connection store and surfaced
by GET /connections (whose FastAPI serializer is an explicit field
whitelist — the ride is explicit, not automatic).
"""

from datetime import datetime, timedelta, timezone
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
from fastapi.testclient import TestClient
from pydantic import ValidationError

from agentadmit import routes as routes_mod
from agentadmit.integrations import django_integration as di
from agentadmit.integrations import flask_integration as fi
from agentadmit.models import AppAttestedPresence
from agentadmit.storage import MemoryStorage


CEREMONY_AT = datetime(2026, 8, 13, 17, 0, 0, tzinfo=timezone.utc)
WIRE = {
    "verified": True,
    "uv": True,
    "method": "tt_webauthn",
    "verified_at": "2026-08-13T17:00:00+00:00",
}


def _fact() -> AppAttestedPresence:
    return AppAttestedPresence(method="tt_webauthn", verified_at=CEREMONY_AT)


# ===========================================================================
# The typed model — hosted contract enforced at construction
# ===========================================================================

def test_model_wire_shape_carries_literal_true_and_offset():
    assert _fact().to_wire() == WIRE


def test_model_defaults_verified_and_uv_true_and_cannot_be_false():
    fact = _fact()
    assert fact.verified is True and fact.uv is True
    with pytest.raises(ValidationError):
        AppAttestedPresence(verified=False, method="tt_webauthn", verified_at=CEREMONY_AT)
    with pytest.raises(ValidationError):
        AppAttestedPresence(uv=False, method="tt_webauthn", verified_at=CEREMONY_AT)


def test_model_rejects_naive_verified_at():
    """The proven prod-outage class: naive timestamps serialize without an
    offset and the hosted mint 400s. Must fail at construction."""
    with pytest.raises(ValidationError, match="timezone-aware"):
        AppAttestedPresence(method="tt_webauthn", verified_at=datetime(2026, 8, 13, 17, 0, 0))


def test_model_preserves_non_utc_offset():
    pacific = timezone(timedelta(hours=-7))
    fact = AppAttestedPresence(
        method="tt_webauthn",
        verified_at=datetime(2026, 8, 13, 10, 0, 0, tzinfo=pacific),
    )
    assert fact.to_wire()["verified_at"] == "2026-08-13T10:00:00-07:00"


@pytest.mark.parametrize(
    "bad_method",
    ["TT_WebAuthn", "tt webauthn", "tt-webauthn", "", "m" * 61],
    ids=["uppercase", "space", "hyphen", "empty", "61-chars"],
)
def test_model_rejects_out_of_contract_method(bad_method):
    with pytest.raises(ValidationError):
        AppAttestedPresence(method=bad_method, verified_at=CEREMONY_AT)


# ===========================================================================
# FastAPI router — hook return forwards / None omits / junk fails closed
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
    storage = MemoryStorage()
    monkeypatch.setattr(routes_mod, "_get_storage", lambda: storage)
    monkeypatch.setattr(routes_mod, "check_connection_cap", lambda *a, **k: None)

    captured = {}

    def fake_hosted(method, path, json=None, timeout=10.0, authenticated=True):
        captured["path"] = path
        captured["json"] = json
        return httpx.Response(
            201,
            json={"token": "ag_ct_new", "connection_id": "conn_1", "expires_in": 3600},
        )

    monkeypatch.setattr(routes_mod, "_call_hosted_service", fake_hosted)

    def make_client(require_token_mint_presence=None):
        _wellknown, router = routes_mod.create_agentadmit_router(
            get_current_user=lambda: {"user_id": "u1"},
            require_token_mint_presence=require_token_mint_presence,
        )
        app = FastAPI()
        app.include_router(router)
        token_path = next(r.path for r in router.routes
                          if r.path.endswith("/connections/generate-token"))
        list_path = next(r.path for r in router.routes
                         if r.path.endswith("/connections") and "GET" in r.methods)
        return TestClient(app), token_path, list_path

    return make_client, captured, storage


def test_fastapi_hook_returned_fact_is_forwarded_and_persisted(generate_app):
    make_client, captured, storage = generate_app

    def hook(*, request, current_user, body):
        return _fact()

    client, token_path, list_path = make_client(hook)
    resp = client.post(token_path, json={"scopes": ["read:things"]})

    assert resp.status_code == 200
    assert captured["json"]["presence"] == WIRE
    assert storage.list_connections("u1")[0]["presence"] == WIRE
    # GET /connections serializer is an explicit whitelist — the ride must
    # be explicit.
    listing = client.get(list_path).json()
    assert listing["connections"][0]["presence"] == WIRE


def test_fastapi_hook_returning_none_omits_presence(generate_app):
    make_client, captured, storage = generate_app
    client, token_path, list_path = make_client(lambda **kw: None)

    resp = client.post(token_path, json={"scopes": ["read:things"]})

    assert resp.status_code == 200
    assert "presence" not in captured["json"]
    assert storage.list_connections("u1")[0]["presence"] is None
    assert client.get(list_path).json()["connections"][0]["presence"] is None


def test_fastapi_no_hook_omits_presence(generate_app):
    make_client, captured, _storage = generate_app
    client, token_path, _list_path = make_client()

    resp = client.post(token_path, json={"scopes": ["read:things"]})

    assert resp.status_code == 200
    assert "presence" not in captured["json"]


def test_fastapi_hook_returning_plain_dict_still_fails_closed(generate_app):
    """The v1.6.0 contract survives: a raw dict — even one shaped exactly
    like the wire format — is NOT an AppAttestedPresence and fails closed."""
    make_client, captured, storage = generate_app
    client, token_path, _list_path = make_client(lambda **kw: dict(WIRE))

    resp = client.post(token_path, json={"scopes": ["read:things"]})

    assert resp.status_code == 500
    assert resp.json()["detail"]["error"] == "presence_hook_misconfigured"
    assert captured == {}                      # hosted mint never called
    assert storage.list_connections("u1") == []


# ===========================================================================
# Flask — same contract on the blueprint mint route
# ===========================================================================

@pytest.fixture()
def flask_app_factory(tmp_path):
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

    def make(require_token_mint_presence=None):
        aa = fi.AgentAdmitFlask(
            config_path=str(config_file),
            get_current_user=lambda: {"user_id": "u1"},
            require_token_mint_presence=require_token_mint_presence,
        )
        aa.storage = MemoryStorage()
        app = Flask(__name__)
        aa.init_app(app)
        return aa, app.test_client()

    return make


def test_flask_hook_returned_fact_is_forwarded_and_persisted(flask_app_factory, monkeypatch):
    aa, client = flask_app_factory(lambda **kw: _fact())
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
    assert captured["json"]["presence"] == WIRE
    assert aa.storage.list_connections("u1")[0]["presence"] == WIRE


def test_flask_hook_returning_none_omits_presence(flask_app_factory, monkeypatch):
    aa, client = flask_app_factory(lambda **kw: None)
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
    assert "presence" not in captured["json"]
    assert aa.storage.list_connections("u1")[0]["presence"] is None


def test_flask_hook_returning_plain_dict_still_fails_closed(flask_app_factory, monkeypatch):
    aa, client = flask_app_factory(lambda **kw: dict(WIRE))
    hosted_post = MagicMock()
    monkeypatch.setattr(fi.httpx, "post", hosted_post)

    resp = client.post(
        f"{aa.config.route_prefix}/connections/generate-token",
        json={"scopes": ["read:things"]},
    )
    assert resp.status_code == 500
    assert resp.get_json()["error"] == "presence_hook_misconfigured"
    hosted_post.assert_not_called()
    assert aa.storage.list_connections("u1") == []


# ===========================================================================
# Django — same contract on generate_token_view
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
    storage = MemoryStorage()
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


def test_django_hook_returned_fact_is_forwarded_and_persisted(django_env, monkeypatch):
    storage = django_env
    monkeypatch.setattr(di, "_require_token_mint_presence", lambda **kw: _fact())
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["json"] = json
        return httpx.Response(200, json={"token": "ag_ct_new", "connection_id": "conn_9", "expires_in": 3600})

    monkeypatch.setattr(di.httpx, "post", fake_post)
    response = di.generate_token_view(_django_post(b'{"scopes":["read:things"]}'))

    assert response.status_code == 200
    assert captured["json"]["presence"] == WIRE
    assert storage.list_connections("u1")[0]["presence"] == WIRE


def test_django_hook_returning_none_omits_presence(django_env, monkeypatch):
    storage = django_env
    monkeypatch.setattr(di, "_require_token_mint_presence", lambda **kw: None)
    captured = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        captured["json"] = json
        return httpx.Response(200, json={"token": "ag_ct_new", "connection_id": "conn_9", "expires_in": 3600})

    monkeypatch.setattr(di.httpx, "post", fake_post)
    response = di.generate_token_view(_django_post(b'{"scopes":["read:things"]}'))

    assert response.status_code == 200
    assert "presence" not in captured["json"]
    assert storage.list_connections("u1")[0]["presence"] is None


def test_django_hook_returning_plain_dict_still_fails_closed(django_env, monkeypatch):
    storage = django_env
    monkeypatch.setattr(di, "_require_token_mint_presence", lambda **kw: dict(WIRE))
    hosted_post = MagicMock()
    monkeypatch.setattr(di.httpx, "post", hosted_post)

    response = di.generate_token_view(_django_post(b'{"scopes":["read:things"]}'))

    assert response.status_code == 500
    assert b"presence_hook_misconfigured" in response.content
    hosted_post.assert_not_called()
    assert storage.list_connections("u1") == []
