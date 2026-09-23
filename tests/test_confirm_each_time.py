"""Confirm-each-time (1.11.0).

The hosted service refuses a designated scope with ``confirmation_required``
and stages a ceremony for the exact action. The SDK must (1) pass the
confirmation block through to the agent as a 403, typed on the exception,
(2) forward the agent's attestation header on the retry, (3) compute the
request digest and carry the app's action summary on the confirming
dependency, and (4) keep failing closed on every other refusal class.
"""

from types import SimpleNamespace

import httpx
import pytest
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient

from agentadmit import auth as auth_mod
from agentadmit.auth import (
    ACTION_ATTESTATION_HEADER,
    _active_refusal_payload,
    parse_action_confirmation,
    request_digest_for,
    require_scope,
)
from agentadmit.exceptions import ConfirmationRequiredError, VerifyRefusedError
from agentadmit.integrations import flask_integration as fi
from agentadmit.storage import MemoryStorage

CONFIRMATION = {
    "action_session_id": "asess_abc",
    "action_session_url": "https://agentadmit.com/confirm/action/asess_abc",
    "expires_at": "2026-09-02T18:30:00.000Z",
    "scope": "write:payments",
    "method": "POST",
    "endpoint": "/api/payments",
    "request_digest": "sha256:deadbeef",
    "summary": "Pay Alex $50",
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


def _patch(monkeypatch, payload, capture: dict):
    monkeypatch.setattr(auth_mod, "get_config", _fake_config)
    monkeypatch.setattr(auth_mod, "_get_storage", lambda: MemoryStorage())

    def fake_post(url, headers=None, json=None, timeout=None):
        capture["body"] = json
        return httpx.Response(200, json=payload, request=httpx.Request("POST", url))

    monkeypatch.setattr(auth_mod.httpx, "post", fake_post)


def test_refusal_payload_passes_the_staged_ceremony_through():
    payload = _active_refusal_payload(
        {
            "active": True,
            "error": "confirmation_required",
            "confirmation": CONFIRMATION,
            "attestation_status": "action_mismatch",
            "attestation_description": "That confirmation was for a different action.",
            "renewal": "The human confirms on the hosted page with their passkey.",
            "scopes": ["leak"],
        },
        "write:payments",
    )
    assert payload["error"] == "confirmation_required"
    assert payload["confirmation"] == CONFIRMATION
    assert payload["attestation_status"] == "action_mismatch"
    assert "different action" in payload["attestation_description"]
    assert "passkey" in payload["renewal"]
    assert "scopes" not in payload


def test_malformed_confirmation_block_is_dropped_and_unknown_class_fails_closed():
    payload = _active_refusal_payload({"active": True, "error": "confirmation_required", "confirmation": {"x": 1}}, "s")
    assert payload["error"] == "confirmation_required" and "confirmation" not in payload
    closed = _active_refusal_payload({"active": True, "error": "confirmation_policy_unavailable"}, "s")
    assert closed == {"error": "confirmation_policy_unavailable", "error_description": "Call refused by the authorization service."}
    assert parse_action_confirmation(None) is None
    assert parse_action_confirmation({"action_session_id": "a", "action_session_url": "u", "expires_at": "e", "scope": "s"}) == {
        "action_session_id": "a", "action_session_url": "u", "expires_at": "e", "scope": "s",
        "method": None, "endpoint": None, "request_digest": None, "summary": None,
    }


def test_fastapi_confirming_dependency_carries_digest_summary_and_attestation(monkeypatch):
    capture: dict = {}
    _patch(monkeypatch, {"active": True, "user_id": "u1", "connection_id": "c1", "scopes": ["write:payments"], "action_confirmation": {"action_session_id": "asess_abc", "consumed": True}}, capture)
    app = FastAPI()

    @app.post("/api/payments")
    async def pay(agent_ctx=Depends(require_scope("write:payments", action_summary=lambda body, req: f"Pay {body['trainer']} ${body['amount']}"))):
        return {"ok": True, "confirmation": agent_ctx.get("action_confirmation")}

    client = TestClient(app)
    body = {"trainer": "alex", "amount": 50}
    res = client.post(
        "/api/payments",
        json=body,
        headers={"Authorization": "Bearer ag_at_x", ACTION_ATTESTATION_HEADER: " asess_abc "},
    )
    assert res.status_code == 200
    assert res.json()["confirmation"] == {"action_session_id": "asess_abc", "consumed": True}
    sent = capture["body"]
    assert sent["scope_used"] == "write:payments"
    assert sent["method"] == "POST" and sent["endpoint"] == "/api/payments"
    assert sent["action_attestation_id"] == "asess_abc"
    assert sent["action_summary"] == "Pay alex $50"
    assert sent["request_digest"].startswith("sha256:") and len(sent["request_digest"]) == len("sha256:") + 64
    assert sent["request_digest"] == request_digest_for(res.request.content)


def test_fastapi_confirmation_required_is_a_403_with_the_link(monkeypatch):
    capture: dict = {}
    _patch(monkeypatch, {"active": True, "error": "confirmation_required", "confirmation": CONFIRMATION}, capture)
    app = FastAPI()

    @app.post("/api/payments")
    async def pay(agent_ctx=Depends(require_scope("write:payments", action_summary=lambda body, req: "Pay"))):
        return {"ok": True}

    res = TestClient(app).post("/api/payments", json={"a": 1}, headers={"Authorization": "Bearer ag_at_x"})
    assert res.status_code == 403
    detail = res.json()["detail"]
    assert detail["error"] == "confirmation_required"
    assert detail["confirmation"]["action_session_url"] == CONFIRMATION["action_session_url"]
    assert "action_attestation_id" not in capture["body"]


def test_plain_require_scope_omits_the_new_fields(monkeypatch):
    capture: dict = {}
    _patch(monkeypatch, {"active": True, "user_id": "u1", "connection_id": "c1", "scopes": ["read:x"]}, capture)
    app = FastAPI()

    @app.get("/api/x")
    async def get_x(agent_ctx=Depends(require_scope("read:x"))):
        return {"ok": True}

    res = TestClient(app).get("/api/x", headers={"Authorization": "Bearer ag_at_x"})
    assert res.status_code == 200
    for key in ("action_attestation_id", "request_digest", "action_summary"):
        assert key not in capture["body"]


def test_summary_callback_that_raises_never_blocks_the_call(monkeypatch):
    capture: dict = {}
    _patch(monkeypatch, {"active": True, "user_id": "u1", "connection_id": "c1", "scopes": ["write:payments"]}, capture)
    app = FastAPI()

    def boom(body, req):
        raise RuntimeError("boom")

    @app.post("/api/payments")
    async def pay(agent_ctx=Depends(require_scope("write:payments", action_summary=boom))):
        return {"ok": True}

    res = TestClient(app).post("/api/payments", json={"a": 1}, headers={"Authorization": "Bearer ag_at_x"})
    assert res.status_code == 200
    assert "action_summary" not in capture["body"]
    assert capture["body"]["request_digest"].startswith("sha256:")


def test_flask_forwards_the_attestation_header(monkeypatch):
    from flask import Flask

    captured: dict = {}

    def fake_introspect(url, token, app_id, api_key, **kwargs):
        captured.update(kwargs)
        return httpx.Response(
            200,
            json={"active": True, "user_id": "u1", "connection_id": "c1", "scopes": ["write:payments"]},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(fi, "_introspect_with_retry", fake_introspect)
    app = Flask(__name__)
    aa = fi.AgentAdmitFlask.__new__(fi.AgentAdmitFlask)
    aa.config = _fake_config()
    aa.storage = MemoryStorage()
    with app.test_request_context("/api/payments", method="POST", headers={ACTION_ATTESTATION_HEADER: "asess_abc"}):
        aa._validate_agent_token("ag_at_x", scope_used="write:payments")
    assert captured["action_attestation_id"] == "asess_abc"


def test_confirmation_required_error_type():
    err = ConfirmationRequiredError({"error": "confirmation_required"}, CONFIRMATION, "not_confirmed")
    assert isinstance(err, VerifyRefusedError)
    assert err.code == "confirmation_required"
    assert err.confirmation["action_session_id"] == "asess_abc"
    assert err.attestation_status == "not_confirmed"


def test_malformed_action_confirmation_is_dropped(monkeypatch):
    capture: dict = {}
    _patch(monkeypatch, {"active": True, "user_id": "u1", "connection_id": "c1", "scopes": ["read:x"], "action_confirmation": {"action_session_id": "asess_abc", "consumed": "yes"}}, capture)
    app = FastAPI()

    @app.get("/api/x")
    async def get_x(agent_ctx=Depends(require_scope("read:x"))):
        return {"has": "action_confirmation" in agent_ctx}

    res = TestClient(app).get("/api/x", headers={"Authorization": "Bearer ag_at_x"})
    assert res.status_code == 200 and res.json()["has"] is False


def test_get_agentadmit_user_accepts_custom_gate_telemetry(monkeypatch):
    from agentadmit.auth import get_agentadmit_user
    capture: dict = {}
    _patch(monkeypatch, {"active": True, "user_id": "u1", "connection_id": "c1", "scopes": ["write:payments"]}, capture)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="ag_at_x")
    ctx = get_agentadmit_user(creds, request=None, scope_used="write:payments", consent_first=True,
                              request_digest="sha256:" + "0" * 64, action_summary="Pay Alex $50")
    assert ctx["user"]["user_id"] == "u1"
    assert capture["body"]["request_digest"] == "sha256:" + "0" * 64
    assert capture["body"]["action_summary"] == "Pay Alex $50"
    assert capture["body"]["consent_first"] is True


def test_verify_refused_error_factory_types_only_confirmation_required():
    from agentadmit.exceptions import verify_refused_error

    typed = verify_refused_error({"error": "confirmation_required", "confirmation": CONFIRMATION, "attestation_status": "expired"})
    assert type(typed) is ConfirmationRequiredError
    assert typed.confirmation == CONFIRMATION and typed.attestation_status == "expired"
    assert typed.payload["confirmation"] == CONFIRMATION
    bare = verify_refused_error({"error": "confirmation_required"})
    assert type(bare) is ConfirmationRequiredError and bare.confirmation is None
    plain = verify_refused_error({"error": "bound_exceeded", "error_description": "x"})
    assert type(plain) is VerifyRefusedError and plain.code == "bound_exceeded"


def test_flask_confirmation_required_is_typed_and_returns_403_with_link(monkeypatch):
    from flask import Flask

    def fake_introspect(url, token, app_id, api_key, **kwargs):
        return httpx.Response(
            200,
            json={"active": True, "error": "confirmation_required", "confirmation": CONFIRMATION},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(fi, "_introspect_with_retry", fake_introspect)
    aa = fi.AgentAdmitFlask.__new__(fi.AgentAdmitFlask)
    aa.config = _fake_config()
    aa.storage = MemoryStorage()
    aa._verify_user_token = None
    app = Flask(__name__)

    # Custom gates get the typed exception (still a VerifyRefusedError).
    with app.test_request_context("/api/payments", method="POST"):
        with pytest.raises(VerifyRefusedError) as exc:
            aa._validate_agent_token("ag_at_x", scope_used="write:payments")
    assert isinstance(exc.value, ConfirmationRequiredError)
    assert exc.value.confirmation["action_session_url"] == CONFIRMATION["action_session_url"]

    # The decorator relays the link as a 403 and never runs the view.
    @app.post("/api/payments")
    @aa.require_scope("write:payments")
    def pay():
        raise AssertionError("view must not run")

    res = app.test_client().post("/api/payments", json={"a": 1}, headers={"Authorization": "Bearer ag_at_x"})
    assert res.status_code == 403
    body = res.get_json()
    assert body["error"] == "confirmation_required"
    assert body["confirmation"]["action_session_id"] == "asess_abc"


def test_django_confirmation_required_is_typed_and_returns_403_with_link(monkeypatch):
    import json as _json

    import django
    from django.conf import settings as dj_settings

    if not dj_settings.configured:
        dj_settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], USE_TZ=True)
        django.setup()
    from agentadmit.integrations import django_integration as di

    seen: dict = {}

    def fake_introspect(*args, **kwargs):
        seen.update(kwargs)
        return httpx.Response(200, json={"active": True, "error": "confirmation_required", "confirmation": CONFIRMATION})

    monkeypatch.setattr(di, "_introspect_with_retry", fake_introspect)
    monkeypatch.setattr(di, "_init", lambda: None)
    monkeypatch.setattr(di, "_config", _fake_config())
    monkeypatch.setattr(di, "_storage", MemoryStorage())
    monkeypatch.setattr(di, "_log_access", lambda *a, **kw: None)

    request = SimpleNamespace(
        META={"HTTP_AUTHORIZATION": "Bearer ag_at_x"},
        headers={ACTION_ATTESTATION_HEADER: "asess_abc"},
        path="/api/payments",
        method="POST",
    )
    with pytest.raises(VerifyRefusedError) as exc:
        di._validate_agent_token("ag_at_x", request=request, scope_used="write:payments")
    assert isinstance(exc.value, ConfirmationRequiredError)
    assert exc.value.confirmation["action_session_url"] == CONFIRMATION["action_session_url"]
    assert seen["action_attestation_id"] == "asess_abc"  # Django forwards the retry header too

    @di.require_scope("write:payments")
    def view(request):
        raise AssertionError("view must not run")

    resp = view(request)
    assert resp.status_code == 403
    body = _json.loads(resp.content)
    assert body["error"] == "confirmation_required"
    assert body["confirmation"]["action_session_id"] == "asess_abc"


def test_public_exports():
    import agentadmit

    assert agentadmit.ConfirmationRequiredError is ConfirmationRequiredError
    assert agentadmit.ACTION_ATTESTATION_HEADER == ACTION_ATTESTATION_HEADER
    assert agentadmit.request_digest_for is request_digest_for
    for name in ("ConfirmationRequiredError", "ACTION_ATTESTATION_HEADER", "request_digest_for"):
        assert name in agentadmit.__all__


# ---------------------------------------------------------------------------
# confirmation_declined (1.12.0): the user's explicit no, relayed typed
# ---------------------------------------------------------------------------

DECLINED = {
    "action_session_id": "asess_abc",
    "declined_at": "2026-09-22T21:35:42.000Z",
    "hold_until": "2026-09-22T21:50:42.000Z",
    "scope": "write:payments",
    "method": "POST",
    "endpoint": "/api/payments",
    "request_digest": "sha256:deadbeef",
    "summary": "Pay Alex $50",
}


def test_declined_refusal_payload_relays_the_decline_block():
    from agentadmit.auth import parse_action_decline

    payload = _active_refusal_payload(
        {
            "active": True,
            "error": "confirmation_declined",
            "error_description": "The user declined this action on the hosted confirmation page. Do not retry it unless the user asks you to; no new confirmation can be staged for this action until 2026-09-22T21:50:42.000Z.",
            "declined": DECLINED,
            "attestation_status": "declined",
            "attestation_description": "The user declined this action.",
            "renewal": "Only the user can lift a decline. After the hold ends, a retry stages a fresh confirmation for them to approve or decline again.",
            "scopes": ["leak"],
        },
        "write:payments",
    )
    assert payload["error"] == "confirmation_declined"
    assert payload["declined"] == DECLINED
    assert payload["attestation_status"] == "declined"
    assert "declined" in payload["attestation_description"]
    assert "Only the user" in payload["renewal"]
    assert "Do not retry" in payload["error_description"]
    assert "scopes" not in payload and "confirmation" not in payload
    # default description when the wire omits it
    bare = _active_refusal_payload({"active": True, "error": "confirmation_declined", "declined": DECLINED}, "s")
    assert "Do not retry it unless the user asks" in bare["error_description"]
    assert parse_action_decline({"action_session_id": "a", "declined_at": "d", "hold_until": "h", "scope": "s"}) == {
        "action_session_id": "a", "declined_at": "d", "hold_until": "h", "scope": "s",
        "method": None, "endpoint": None, "request_digest": None, "summary": None,
    }
    assert parse_action_decline({"action_session_id": "a", "declined_at": "d", "scope": "s"}) is None
    assert parse_action_decline("nope") is None


def test_malformed_declined_block_is_dropped_and_still_refused():
    payload = _active_refusal_payload({"active": True, "error": "confirmation_declined", "declined": {"action_session_id": "a", "hold_until": 7}}, "s")
    assert payload["error"] == "confirmation_declined" and "declined" not in payload


def test_verify_refused_error_factory_types_confirmation_declined():
    from agentadmit.exceptions import ConfirmationDeclinedError, verify_refused_error

    typed = verify_refused_error({"error": "confirmation_declined", "declined": DECLINED, "attestation_status": "declined"})
    assert type(typed) is ConfirmationDeclinedError and isinstance(typed, VerifyRefusedError)
    assert not isinstance(typed, ConfirmationRequiredError)
    assert typed.code == "confirmation_declined"
    assert typed.declined == DECLINED and typed.attestation_status == "declined"
    assert typed.payload["declined"] == DECLINED
    bare = verify_refused_error({"error": "confirmation_declined"})
    assert type(bare) is ConfirmationDeclinedError and bare.declined is None and bare.attestation_status is None


def test_fastapi_confirmation_declined_is_a_403_with_the_decline_block(monkeypatch):
    capture: dict = {}
    _patch(monkeypatch, {"active": True, "error": "confirmation_declined", "declined": DECLINED, "renewal": "Only the user can lift a decline."}, capture)
    app = FastAPI()

    @app.post("/api/payments")
    async def pay(agent_ctx=Depends(require_scope("write:payments", action_summary=lambda req, raw: "Pay Alex $50"))):
        return {"ok": True}

    res = TestClient(app).post("/api/payments", json={"amount": 50}, headers={"Authorization": "Bearer ag_at_x"})
    assert res.status_code == 403
    body = res.json()["detail"]
    assert body["error"] == "confirmation_declined" and body["declined"] == DECLINED
    assert "Only the user" in body["renewal"] and "confirmation" not in body


def test_public_exports_include_confirmation_declined():
    import agentadmit
    from agentadmit.exceptions import ConfirmationDeclinedError

    assert agentadmit.ConfirmationDeclinedError is ConfirmationDeclinedError
    assert "ConfirmationDeclinedError" in agentadmit.__all__
