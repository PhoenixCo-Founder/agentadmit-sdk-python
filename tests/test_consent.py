"""Consent Ledger client tests.

check_consent must be fail-closed: any non-200 response or malformed body
must raise rather than default to a granted verdict. The verify passthrough
(context["consent"]) must tolerate an absent block (old servers never send
one) and must drop a type-malformed block without failing the verify result,
so junk in the consent field can never masquerade as a verdict.
"""

import json
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from agentadmit import auth as auth_mod
from agentadmit import consent as consent_mod
from agentadmit.consent import check_consent
from agentadmit.storage import MemoryStorage


GRANTED_VERDICT = {
    "caller_class": "in_app_ai",
    "granted": True,
    "scope_group": None,
    "source": "app_default",
    "evaluated_at": "2026-07-03T00:00:00Z",
}


def _patch_hosted_service(monkeypatch, response, capture=None):
    def fake_call(method, path, json=None, **kwargs):
        if capture is not None:
            capture.update({"method": method, "path": path, "json": json})
        return response

    monkeypatch.setattr(consent_mod, "_call_hosted_service", fake_call)


# ===========================================================================
# check_consent — hosted Consent Ledger endpoint
# ===========================================================================

def test_check_consent_returns_verdict_dict_on_200(monkeypatch):
    captured = {}
    _patch_hosted_service(monkeypatch, httpx.Response(200, json=GRANTED_VERDICT), captured)

    verdict = check_consent("user_8842", "in_app_ai", scope_group="financial")

    assert isinstance(verdict, dict)
    assert verdict["granted"] is True
    assert verdict["caller_class"] == "in_app_ai"
    assert verdict["source"] == "app_default"

    assert captured["method"] == "POST"
    assert captured["path"] == "/api/v1/consent/check"
    assert captured["json"] == {
        "app_user_id": "user_8842",
        "caller_class": "in_app_ai",
        "scope_group": "financial",
    }


def test_check_consent_omits_scope_group_when_not_given(monkeypatch):
    captured = {}
    _patch_hosted_service(monkeypatch, httpx.Response(200, json=GRANTED_VERDICT), captured)

    check_consent("user_8842", "human_session")

    assert "scope_group" not in captured["json"]


def test_check_consent_raises_on_non_200_with_error_detail(monkeypatch):
    """A denied HTTP response must raise — never return a default verdict."""
    _patch_hosted_service(monkeypatch, httpx.Response(
        400,
        json={"error": "invalid_request", "error_description": "unknown app_user_id"},
    ))

    with pytest.raises(RuntimeError, match="unknown app_user_id"):
        check_consent("nope", "in_app_ai")


def test_check_consent_raises_on_non_200_with_unparseable_body(monkeypatch):
    _patch_hosted_service(monkeypatch, httpx.Response(
        503,
        content=b"<html>Service Unavailable</html>",
        headers={"content-type": "text/html"},
    ))

    with pytest.raises(RuntimeError, match="HTTP 503"):
        check_consent("user_1", "external_agent")


def test_check_consent_raises_on_200_with_malformed_json(monkeypatch):
    """A 200 whose body is not valid JSON must raise, not return junk."""
    _patch_hosted_service(monkeypatch, httpx.Response(
        200,
        content=b"{granted: definitely",
        headers={"content-type": "application/json"},
    ))

    with pytest.raises((json.JSONDecodeError, ValueError)):
        check_consent("user_1", "in_app_ai")


def test_check_consent_rejects_unknown_caller_class():
    with pytest.raises(ValueError, match="caller_class"):
        check_consent("user_1", "root")


# ===========================================================================
# Verify passthrough — context["consent"] from introspection (FastAPI path)
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


ACTIVE_PAYLOAD = {
    "active": True,
    "user_id": "user_123",
    "connection_id": "conn_1",
    "scopes": ["read:things"],
    "agent_label": "Test Agent",
}


def test_verify_without_consent_block_parses_and_has_no_consent_key(monkeypatch):
    """Old servers never send `consent`; the SDK must not require it."""
    context = _call_verify(monkeypatch, dict(ACTIVE_PAYLOAD))

    assert context["scopes"] == ["read:things"]
    assert context["connection"]["connection_id"] == "conn_1"
    assert "consent" not in context


def test_verify_passes_through_well_formed_consent_block(monkeypatch):
    payload = dict(ACTIVE_PAYLOAD, consent=dict(GRANTED_VERDICT, caller_class="external_agent"))

    context = _call_verify(monkeypatch, payload)

    assert context["consent"]["granted"] is True
    assert context["consent"]["caller_class"] == "external_agent"


@pytest.mark.parametrize("bad_consent", [
    {"granted": "true", "caller_class": "in_app_ai"},  # granted is a string
    {"caller_class": "in_app_ai", "source": "app_default"},  # granted missing
    "granted",  # bare string
    1,  # number
    ["granted"],  # list
], ids=["granted-str", "granted-missing", "bare-str", "number", "list"])
def test_verify_drops_type_malformed_consent_without_failing(monkeypatch, bad_consent):
    """The token verdict must survive; the junk consent must not ride along."""
    payload = dict(ACTIVE_PAYLOAD, consent=bad_consent)

    context = _call_verify(monkeypatch, payload)

    assert context["connection"]["connection_id"] == "conn_1"
    assert context["scopes"] == ["read:things"]
    assert "consent" not in context


def test_verify_inactive_token_still_rejected_even_with_granted_consent(monkeypatch):
    """A granted consent block must never resurrect an inactive token."""
    payload = dict(ACTIVE_PAYLOAD, active=False, consent=dict(GRANTED_VERDICT))

    with pytest.raises(HTTPException) as exc_info:
        _call_verify(monkeypatch, payload)
    assert exc_info.value.status_code == 401
