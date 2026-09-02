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
