"""1.15.0: confirm-each-time when the user has no passkey yet.

Row A: ``confirmation.enrollment_required`` on the confirmation_required
refusal is kept strictly (bool only; anything else treated as absent) in the
typed copy and in the 403 body of all three framework integrations, and the
agent is told the link alone cannot be used when it is True.

Row B: ``create_owner_link`` posts to the hosted owner-link endpoint with the
API key and returns a typed result, never a partial one.
"""

import json as _json
import logging
import pathlib
from types import SimpleNamespace
from urllib.parse import quote

import httpx
import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

import agentadmit
from agentadmit import auth as auth_mod
from agentadmit import routes as routes_mod
from agentadmit.auth import ENROLLMENT_REQUIRED_DESCRIPTION, require_scope
from agentadmit.exceptions import ConfirmationRequiredError, OwnerLinkError, VerifyRefusedError
from agentadmit.integrations import flask_integration as fi
from agentadmit.owner_link import create_owner_link
from agentadmit.storage import MemoryStorage

OLD_DESCRIPTION = (
    "This action requires a fresh human confirmation. Give the confirmation "
    "link to the user, then retry with the X-AgentAdmit-Action-Attestation header."
)

BASE = {
    "action_session_id": "asess_abcdefghijklmnop",
    "action_session_url": "https://agentadmit.com/confirm/action/asess_abcdefghijklmnop",
    "expires_at": "2026-11-20T18:30:00.000Z",
    "scope": "write:payments",
    "method": "POST",
    "endpoint": "/api/payments",
    "request_digest": "sha256:deadbeef",
    "summary": "Pay Alex $50",
}

_ABSENT = object()


def _fake_config():
    return SimpleNamespace(
        app_id="app_test",
        api_key="aa_test_key",
        agentadmit_api_url="https://agentadmit.example/",
        agentadmit_verify_url="https://agentadmit.example/api/v1/verify",
        token_prefix_access="ag_at_",
        user_lookup_field="user_id",
        max_retries=0,
    )


def _confirmation(wire):
    c = dict(BASE)
    if wire is not _ABSENT:
        c["enrollment_required"] = wire
    return c


def _fastapi_403(monkeypatch, confirmation):
    monkeypatch.setattr(auth_mod, "get_config", _fake_config)
    monkeypatch.setattr(auth_mod, "_get_storage", lambda: MemoryStorage())

    def fake_post(url, headers=None, json=None, timeout=None):
        return httpx.Response(
            200,
            json={"active": True, "error": "confirmation_required", "confirmation": confirmation},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(auth_mod.httpx, "post", fake_post)
    app = FastAPI()

    @app.post("/api/payments")
    async def pay(agent_ctx=Depends(require_scope("write:payments"))):
        raise AssertionError("route must not run")

    res = TestClient(app).post("/api/payments", json={"a": 1}, headers={"Authorization": "Bearer ag_at_x"})
    assert res.status_code == 403
    return res.json()["detail"]


def _refusal(confirmation):
    payload = auth_mod._active_refusal_payload(
        {"active": True, "error": "confirmation_required", "confirmation": confirmation}, "write:payments"
    )
    from agentadmit.exceptions import verify_refused_error

    return verify_refused_error(payload)


# ---------------------------------------------------------------------------
# Row A
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("wire", [True, False])
def test_boolean_is_kept_in_typed_copy_and_403_body(monkeypatch, wire):
    err = _refusal(_confirmation(wire))
    assert isinstance(err, ConfirmationRequiredError)
    assert err.confirmation["enrollment_required"] is wire
    assert err.payload["confirmation"]["enrollment_required"] is wire
    body = _fastapi_403(monkeypatch, _confirmation(wire))
    assert body["confirmation"]["enrollment_required"] is wire


@pytest.mark.parametrize("wire", [_ABSENT, None, "true", 1, 0, {}, []], ids=["absent", "null", "string-true", "1", "0", "object", "array"])
def test_non_boolean_is_treated_as_absent(monkeypatch, wire):
    err = _refusal(_confirmation(wire))
    assert isinstance(err, ConfirmationRequiredError)
    assert "enrollment_required" not in err.confirmation
    assert err.confirmation == BASE
    body = _fastapi_403(monkeypatch, _confirmation(wire))
    assert body["confirmation"] == BASE
    assert "enrollment_required" not in body["confirmation"]
    assert body["error_description"] == OLD_DESCRIPTION


def test_block_missing_url_is_dropped_whole_even_with_enrollment_required(monkeypatch):
    c = _confirmation(True)
    del c["action_session_url"]
    err = _refusal(c)
    assert isinstance(err, VerifyRefusedError)
    assert err.confirmation is None
    assert "confirmation" not in err.payload
    body = _fastapi_403(monkeypatch, c)
    assert "confirmation" not in body
    assert body["error_description"] == OLD_DESCRIPTION


def test_sentence_only_when_true(monkeypatch):
    assert ENROLLMENT_REQUIRED_DESCRIPTION == (
        "This action requires a fresh human confirmation, and this user has no passkey on file "
        "for the app yet, so the confirmation link alone cannot be used. Ask the user to open the "
        "request from inside the app. After they confirm, retry with the "
        "X-AgentAdmit-Action-Attestation header."
    )
    assert _fastapi_403(monkeypatch, _confirmation(True))["error_description"] == ENROLLMENT_REQUIRED_DESCRIPTION
    assert _fastapi_403(monkeypatch, _confirmation(False))["error_description"] == OLD_DESCRIPTION
    assert _fastapi_403(monkeypatch, _confirmation(_ABSENT))["error_description"] == OLD_DESCRIPTION


def test_flask_403_carries_enrollment_required(monkeypatch):
    from flask import Flask

    def fake_introspect(url, token, app_id, api_key, **kwargs):
        return httpx.Response(
            200,
            json={"active": True, "error": "confirmation_required", "confirmation": _confirmation(True)},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(fi, "_introspect_with_retry", fake_introspect)
    aa = fi.AgentAdmitFlask.__new__(fi.AgentAdmitFlask)
    aa.config = _fake_config()
    aa.storage = MemoryStorage()
    aa._verify_user_token = None
    app = Flask(__name__)

    @app.post("/api/payments")
    @aa.require_scope("write:payments")
    def pay():
        raise AssertionError("view must not run")

    res = app.test_client().post("/api/payments", json={"a": 1}, headers={"Authorization": "Bearer ag_at_x"})
    assert res.status_code == 403
    body = res.get_json()
    assert body["confirmation"]["enrollment_required"] is True
    assert body["error_description"] == ENROLLMENT_REQUIRED_DESCRIPTION


def test_django_403_carries_enrollment_required(monkeypatch):
    import django
    from django.conf import settings as dj_settings

    if not dj_settings.configured:
        dj_settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], USE_TZ=True)
        django.setup()
    from agentadmit.integrations import django_integration as di

    def fake_introspect(*args, **kwargs):
        return httpx.Response(200, json={"active": True, "error": "confirmation_required", "confirmation": _confirmation("true")})

    monkeypatch.setattr(di, "_introspect_with_retry", fake_introspect)
    monkeypatch.setattr(di, "_init", lambda: None)
    monkeypatch.setattr(di, "_config", _fake_config())
    monkeypatch.setattr(di, "_storage", MemoryStorage())
    monkeypatch.setattr(di, "_log_access", lambda *a, **kw: None)
    request = SimpleNamespace(META={"HTTP_AUTHORIZATION": "Bearer ag_at_x"}, headers={}, path="/api/payments", method="POST")

    @di.require_scope("write:payments")
    def view(request):
        raise AssertionError("view must not run")

    resp = view(request)
    assert resp.status_code == 403
    body = _json.loads(resp.content)
    assert "enrollment_required" not in body["confirmation"]
    assert body["error_description"] == OLD_DESCRIPTION


# ---------------------------------------------------------------------------
# Row B
# ---------------------------------------------------------------------------

ID = "asess_abc-DEF_ghijklmnop"
OWNER_URL = "https://agentadmit.com/confirm/action/asess_abc-DEF_ghijklmnop#olt_secretsecret"


@pytest.fixture
def hosted(monkeypatch):
    """Route the SDK's hosted calls to an in-memory handler; record requests."""
    state = {"requests": [], "status": 201, "body": {}}

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"].append(request)
        body = state["body"]
        if isinstance(body, (bytes, str)):
            return httpx.Response(state["status"], content=body)
        return httpx.Response(state["status"], json=body)

    real_client = httpx.Client

    def client_factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(routes_mod, "get_config", _fake_config)
    monkeypatch.setattr(routes_mod.httpx, "Client", client_factory)
    return state


def test_exported_and_not_on_any_router():
    assert agentadmit.create_owner_link is create_owner_link
    assert "create_owner_link" in agentadmit.__all__
    pkg = pathlib.Path(agentadmit.__file__).parent
    for rel in ("routes.py", "middleware.py", "integrations/flask_integration.py", "integrations/django_integration.py"):
        assert "owner-link" not in (pkg / rel).read_text()
        assert "owner_link" not in (pkg / rel).read_text()


def test_request_shape_and_201_result(hosted, monkeypatch):
    seen = []
    import agentadmit.owner_link as ol_mod

    real_quote = ol_mod.quote
    monkeypatch.setattr(ol_mod, "quote", lambda v, safe="": seen.append(v) or real_quote(v, safe=safe))
    hosted["status"] = 201
    hosted["body"] = {
        "action_session_id": ID,
        "owner_session_url": OWNER_URL,
        "enrollment_required": True,
        "enrollment_reason": "no_passkey",
        "expires_at": "2026-11-20T18:30:00.000Z",
    }
    link = create_owner_link(ID, "user_42")
    assert seen == [ID]
    assert len(hosted["requests"]) == 1
    req = hosted["requests"][0]
    assert req.method == "POST"
    assert str(req.url) == f"https://agentadmit.example/api/v1/action-sessions/{quote(ID, safe='')}/owner-link"
    assert req.headers["Authorization"] == "Bearer aa_test_key"
    assert req.headers["Content-Type"] == "application/json"
    assert _json.loads(req.content) == {"app_user_id": "user_42"}
    assert link == {
        "action_session_id": ID,
        "owner_session_url": OWNER_URL,
        "enrollment_required": True,
        "enrollment_reason": "no_passkey",
        "expires_at": "2026-11-20T18:30:00.000Z",
    }


def test_id_is_url_encoded(hosted):
    hosted["status"] = 200
    hosted["body"] = {"action_session_id": "x", "owner_session_url": "u", "enrollment_required": False, "expires_at": "e"}
    create_owner_link("asess_a/b?c#d e_ghijklmn", "user_42")
    assert hosted["requests"][0].url.raw_path == b"/api/v1/action-sessions/asess_a%2Fb%3Fc%23d%20e_ghijklmn/owner-link"


def test_200_result_has_no_reason(hosted):
    hosted["status"] = 200
    hosted["body"] = {
        "action_session_id": ID,
        "owner_session_url": "https://agentadmit.com/confirm/action/" + ID,
        "enrollment_required": False,
        "expires_at": "2026-11-20T18:30:00.000Z",
    }
    link = create_owner_link(ID, "user_42")
    assert link["enrollment_required"] is False
    assert "enrollment_reason" not in link


@pytest.mark.parametrize(
    "status,code",
    [(401, "invalid_api_key"), (403, "api_key_not_app_linked"), (404, "not_found"), (409, "already_consumed"),
     (409, "already_verified"), (410, "session_expired"), (429, "rate_limited"), (500, "internal_error")],
)
def test_error_statuses_map_with_status_and_code_no_retry(hosted, status, code):
    hosted["status"] = status
    hosted["body"] = {"error": code}
    with pytest.raises(OwnerLinkError) as exc:
        create_owner_link(ID, "user_42")
    assert exc.value.status == status
    assert exc.value.code == code
    assert len(hosted["requests"]) == 1


@pytest.mark.parametrize(
    "sid,user",
    [("sess_abcdefghijklmnopqrst", "user_42"), ("asess_short", "user_42"), (42, "user_42"), (ID, ""), (ID, "u" * 256), (ID, None)],
    ids=["bad-prefix", "too-short", "not-a-string", "empty-user", "user-over-255", "user-none"],
)
def test_argument_errors_before_any_request(hosted, sid, user):
    with pytest.raises(ValueError):
        create_owner_link(sid, user)
    assert hosted["requests"] == []


def test_255_character_user_id_is_accepted(hosted):
    hosted["status"] = 200
    hosted["body"] = {"action_session_id": ID, "owner_session_url": "u", "enrollment_required": False, "expires_at": "e"}
    assert create_owner_link(ID, "u" * 255)["enrollment_required"] is False


@pytest.mark.parametrize(
    "body",
    [
        {"action_session_id": ID, "enrollment_required": True, "expires_at": "e"},
        {"action_session_id": ID, "owner_session_url": 7, "enrollment_required": True, "expires_at": "e"},
        {"action_session_id": ID, "owner_session_url": OWNER_URL, "expires_at": "e"},
        {"action_session_id": ID, "owner_session_url": OWNER_URL, "enrollment_required": "true", "expires_at": "e"},
        {"action_session_id": ID, "owner_session_url": OWNER_URL, "enrollment_required": 1, "expires_at": "e"},
        [OWNER_URL],
        b"not json " + OWNER_URL.encode(),
    ],
    ids=["no-url", "url-not-string", "no-flag", "flag-string", "flag-int", "array", "not-json"],
)
def test_malformed_2xx_is_an_error_never_partial(hosted, body):
    hosted["status"] = 201
    hosted["body"] = body
    with pytest.raises(OwnerLinkError) as exc:
        create_owner_link(ID, "user_42")
    assert "Malformed" in str(exc.value)
    assert exc.value.code is None
    assert "olt_" not in str(exc.value)


def test_owner_link_is_never_logged(hosted, caplog):
    caplog.set_level(logging.DEBUG)
    hosted["status"] = 201
    hosted["body"] = {"action_session_id": ID, "owner_session_url": OWNER_URL, "enrollment_required": True,
                      "enrollment_reason": "no_passkey", "expires_at": "e"}
    create_owner_link(ID, "user_42")
    hosted["body"] = {"action_session_id": ID, "owner_session_url": OWNER_URL, "expires_at": "e"}
    with pytest.raises(OwnerLinkError) as exc:
        create_owner_link(ID, "user_42")
    assert "olt_" not in str(exc.value)
    assert "olt_" not in caplog.text


def test_network_failure_is_the_sdk_502(monkeypatch):
    from fastapi import HTTPException

    def handler(request):
        raise httpx.ConnectError("down", request=request)

    real_client = httpx.Client
    monkeypatch.setattr(routes_mod, "get_config", _fake_config)
    monkeypatch.setattr(routes_mod.httpx, "Client", lambda *a, **kw: real_client(*a, **{**kw, "transport": httpx.MockTransport(handler)}))
    with pytest.raises(HTTPException) as exc:
        create_owner_link(ID, "user_42")
    assert exc.value.status_code == 502
