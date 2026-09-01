"""1.10.0 — Per-call verification telemetry + active-error fail-closed.

Matrix (projects/agentadmit/sdk-1.10.0-semantic-matrix.md):
  §1  verify body gains optional scope_used / endpoint / method — omitted
      when unknown, never null; endpoint is path-only (no query), ≤500;
      method uppercase ≤20.
  §2  scope-aware entry points pass the enforced scope INTO the verify call.
  §4  active:true + error = per-call DENIAL (403), never pass-through:
      insufficient_scope → step-up shape; bound_exceeded → hosted fields
      pass through; unknown refusal class → generic 403 fail-closed.

Covers the FastAPI, Flask, and Django paths.
"""

import json
from types import SimpleNamespace

import httpx
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from agentadmit import auth as auth_mod
from agentadmit.exceptions import VerifyRefusedError
from agentadmit.integrations import django_integration as di
from agentadmit.integrations import flask_integration as fi
from agentadmit.storage import MemoryStorage


ACTIVE_OK = {
    "active": True,
    "user_id": "user_123",
    "connection_id": "conn_1",
    "agent_id": "agent_1",
    "scopes": ["read:orders", "write:orders"],
    "agent_label": "Test Agent",
}


def _fake_config():
    return SimpleNamespace(
        app_id="app_test",
        api_key="aa_test_key",
        agentadmit_verify_url="https://agentadmit.example/api/v1/verify",
        token_prefix_access="ag_at_",
        user_lookup_field="user_id",
        max_retries=0,
    )


@pytest.fixture
def captured(monkeypatch):
    """Patch the FastAPI-path introspection and capture its kwargs."""
    calls = []

    def fake_introspect(*args, **kwargs):
        calls.append(kwargs)
        return httpx.Response(200, json=dict(fake_introspect.payload))

    fake_introspect.payload = ACTIVE_OK
    monkeypatch.setattr(auth_mod, "get_config", _fake_config)
    storage = MemoryStorage()
    storage.add_test_user("user_123", {"user_id": "user_123"})
    monkeypatch.setattr(auth_mod, "_get_storage", lambda: storage)
    monkeypatch.setattr(auth_mod, "_introspect_with_retry", fake_introspect)
    monkeypatch.setattr(auth_mod, "log_agent_access", lambda **kw: None)
    return calls, fake_introspect


def _fastapi_client():
    app = FastAPI()

    @app.get("/api/orders")
    def orders(agent_ctx=Depends(auth_mod.require_scope("read:orders"))):
        return {"ok": True}

    @app.get("/api/whoami")
    def whoami(agent_ctx=Depends(auth_mod.get_agentadmit_user)):
        return {"ok": True}

    return TestClient(app)


# ---------------------------------------------------------------------------
# §1/§2 — FastAPI telemetry
# ---------------------------------------------------------------------------

def test_fastapi_require_scope_sends_scope_endpoint_method(captured):
    calls, _ = captured
    client = _fastapi_client()
    r = client.get("/api/orders", headers={"Authorization": "Bearer ag_at_tok"})
    assert r.status_code == 200
    assert calls[-1]["scope_used"] == "read:orders"
    assert calls[-1]["endpoint"] == "/api/orders"
    assert calls[-1]["method"] == "GET"


def test_fastapi_bare_dependency_omits_scope_but_sends_endpoint(captured):
    calls, _ = captured
    client = _fastapi_client()
    r = client.get("/api/whoami", headers={"Authorization": "Bearer ag_at_tok"})
    assert r.status_code == 200
    assert calls[-1]["scope_used"] is None
    assert calls[-1]["endpoint"] == "/api/whoami"
    assert calls[-1]["method"] == "GET"


def test_fastapi_endpoint_is_path_only_no_query(captured):
    calls, _ = captured
    client = _fastapi_client()
    client.get(
        "/api/orders?user_email=secret@example.com",
        headers={"Authorization": "Bearer ag_at_tok"},
    )
    assert calls[-1]["endpoint"] == "/api/orders"
    assert "secret" not in json.dumps(calls[-1].get("endpoint", ""))


def test_payload_omits_absent_fields():
    """§1: fields are OMITTED (not null) when unknown — checked at the wire layer."""
    seen = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        seen.update(json)
        return httpx.Response(200, json=dict(ACTIVE_OK))

    orig = auth_mod.httpx.post
    auth_mod.httpx.post = fake_post
    try:
        auth_mod._introspect_with_retry(
            "https://agentadmit.example/api/v1/verify", "ag_at_tok", "app", "key",
        )
    finally:
        auth_mod.httpx.post = orig
    assert seen == {"token": "ag_at_tok"}


def test_telemetry_caps_endpoint_and_method():
    fake_request = SimpleNamespace(
        url=SimpleNamespace(path="/x" * 600), method="g" * 30
    )
    endpoint, method = auth_mod._request_telemetry(fake_request)
    assert len(endpoint) == 500
    assert len(method) == 20
    assert method == "G" * 20


# ---------------------------------------------------------------------------
# §4 — active-error fail-closed (FastAPI)
# ---------------------------------------------------------------------------

def test_fastapi_bound_exceeded_denied_403(captured):
    calls, fake = captured
    fake.payload = {
        "active": True,
        "error": "bound_exceeded",
        "error_description": "The daily ceiling the user set (10 calls) has been reached.",
        "bound": {"window": "daily", "ceiling": 10, "level": "connection"},
        "renewal": "Additional budget requires a new user-authorized connection.",
    }
    client = _fastapi_client()
    r = client.get("/api/orders", headers={"Authorization": "Bearer ag_at_tok"})
    assert r.status_code == 403
    body = r.json()["detail"]
    assert body["error"] == "bound_exceeded"
    assert body["bound"]["ceiling"] == 10
    assert "renewal" in body


def test_fastapi_hosted_insufficient_scope_denied_step_up_shape(captured):
    calls, fake = captured
    fake.payload = {
        "active": True,
        "error": "insufficient_scope",
        "error_description": 'Scope "admin:all" was not granted for this connection.',
        "granted_scopes": ["read:orders"],
    }
    client = _fastapi_client()
    r = client.get("/api/orders", headers={"Authorization": "Bearer ag_at_tok"})
    assert r.status_code == 403
    body = r.json()["detail"]
    assert body["error"] == "insufficient_scope"
    assert body["required_scope"] == "read:orders"
    assert body["granted_scopes"] == ["read:orders"]


def test_fastapi_unknown_active_error_fails_closed(captured):
    calls, fake = captured
    fake.payload = {"active": True, "error": "future_refusal_class"}
    client = _fastapi_client()
    r = client.get("/api/orders", headers={"Authorization": "Bearer ag_at_tok"})
    assert r.status_code == 403
    assert r.json()["detail"]["error"] == "future_refusal_class"


def test_active_without_error_unchanged(captured):
    calls, _ = captured
    client = _fastapi_client()
    r = client.get("/api/orders", headers={"Authorization": "Bearer ag_at_tok"})
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Flask path
# ---------------------------------------------------------------------------

@pytest.fixture
def flask_env(monkeypatch):
    from flask import Flask

    calls = []

    def fake_introspect(*args, **kwargs):
        calls.append(kwargs)
        return httpx.Response(200, json=dict(fake_introspect.payload))

    fake_introspect.payload = ACTIVE_OK
    monkeypatch.setattr(fi, "_introspect_with_retry", fake_introspect)

    aa = fi.AgentAdmitFlask.__new__(fi.AgentAdmitFlask)
    aa.config = _fake_config()
    storage = MemoryStorage()
    storage.add_test_user("user_123", {"user_id": "user_123"})
    aa.storage = storage
    aa._verify_user_token = None
    monkeypatch.setattr(aa, "_log_access", lambda *a, **kw: None, raising=False)

    app = Flask(__name__)

    @app.get("/api/orders")
    @aa.require_scope("read:orders")
    def orders():
        return {"ok": True}

    return app.test_client(), calls, fake_introspect


def test_flask_require_scope_sends_telemetry(flask_env):
    client, calls, _ = flask_env
    r = client.get(
        "/api/orders?q=secret", headers={"Authorization": "Bearer ag_at_tok"}
    )
    assert r.status_code == 200
    assert calls[-1]["scope_used"] == "read:orders"
    assert calls[-1]["endpoint"] == "/api/orders"  # query stripped
    assert calls[-1]["method"] == "GET"


def test_flask_bound_exceeded_denied_403(flask_env):
    client, calls, fake = flask_env
    fake.payload = {
        "active": True,
        "error": "bound_exceeded",
        "error_description": "Ceiling reached.",
    }
    r = client.get("/api/orders", headers={"Authorization": "Bearer ag_at_tok"})
    assert r.status_code == 403
    assert r.get_json()["error"] == "bound_exceeded"


def test_flask_unknown_active_error_fails_closed(flask_env):
    client, calls, fake = flask_env
    fake.payload = {"active": True, "error": "future_refusal_class"}
    r = client.get("/api/orders", headers={"Authorization": "Bearer ag_at_tok"})
    assert r.status_code == 403
    assert r.get_json()["error"] == "future_refusal_class"


# ---------------------------------------------------------------------------
# Django path
# ---------------------------------------------------------------------------

def _django_request(path="/api/orders", method="GET", auth="Bearer ag_at_tok"):
    return SimpleNamespace(
        META={"HTTP_AUTHORIZATION": auth}, path=path, method=method
    )


@pytest.fixture
def django_env(monkeypatch):
    calls = []

    def fake_introspect(*args, **kwargs):
        calls.append(kwargs)
        return httpx.Response(200, json=dict(fake_introspect.payload))

    fake_introspect.payload = ACTIVE_OK
    monkeypatch.setattr(di, "_introspect_with_retry", fake_introspect)
    monkeypatch.setattr(di, "_init", lambda: None)
    monkeypatch.setattr(di, "_config", _fake_config())
    storage = MemoryStorage()
    storage.add_test_user("user_123", {"user_id": "user_123"})
    monkeypatch.setattr(di, "_storage", storage)
    monkeypatch.setattr(di, "_log_access", lambda *a, **kw: None)
    return calls, fake_introspect


def test_django_require_scope_sends_telemetry(django_env):
    calls, _ = django_env

    @di.require_scope("read:orders")
    def view(request):
        return "OK"

    assert view(_django_request()) == "OK"
    assert calls[-1]["scope_used"] == "read:orders"
    assert calls[-1]["endpoint"] == "/api/orders"
    assert calls[-1]["method"] == "GET"


def test_django_bound_exceeded_denied_403(django_env):
    calls, fake = django_env
    fake.payload = {
        "active": True,
        "error": "bound_exceeded",
        "error_description": "Ceiling reached.",
    }

    @di.require_scope("read:orders")
    def view(request):
        return "OK"

    resp = view(_django_request())
    assert resp.status_code == 403
    assert json.loads(resp.content)["error"] == "bound_exceeded"


def test_django_unknown_active_error_fails_closed(django_env):
    calls, fake = django_env
    fake.payload = {"active": True, "error": "future_refusal_class"}

    @di.require_scope("read:orders")
    def view(request):
        return "OK"

    resp = view(_django_request())
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Refusal-payload helper unit coverage
# ---------------------------------------------------------------------------

def test_refusal_helper_none_without_error():
    assert auth_mod._active_refusal_payload(dict(ACTIVE_OK), "read:orders") is None


def test_refusal_helper_insufficient_scope_shape():
    payload = auth_mod._active_refusal_payload(
        {"active": True, "error": "insufficient_scope", "granted_scopes": ["a"]},
        "read:orders",
    )
    assert payload == {
        "error": "insufficient_scope",
        "required_scope": "read:orders",
        "granted_scopes": ["a"],
    }
