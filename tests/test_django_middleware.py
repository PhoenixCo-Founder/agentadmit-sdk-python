"""Regression tests for the Django middleware's invalid-vs-absent fix.

The passive middleware used to swallow introspection failures and set
request.agentadmit_user = None — making a forged/revoked/expired agent token
indistinguishable from an anonymous request. A token that claims to be an
AgentAdmit token but fails introspection must be rejected with 401, and
service conditions must surface 502.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import django
from django.conf import settings as dj_settings

if not dj_settings.configured:
    dj_settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], USE_TZ=True)
    django.setup()

import pytest

from agentadmit.exceptions import IntrospectionUnavailableError, RateLimitError
from agentadmit.integrations import django_integration as di


@pytest.fixture()
def middleware(monkeypatch):
    fake_config = SimpleNamespace(token_prefix_access="ag_at_")
    monkeypatch.setattr(di, "_config", fake_config)
    monkeypatch.setattr(di, "_init", lambda: None)
    handled = {}

    def get_response(request):
        handled["reached_view"] = True
        return "VIEW_RESPONSE"

    return di.AgentAdmitMiddleware(get_response), handled


def make_request(auth=None):
    meta = {"HTTP_AUTHORIZATION": auth} if auth else {}
    return SimpleNamespace(META=meta)


def test_absent_token_passes_through_as_anonymous(middleware):
    mw, handled = middleware
    request = make_request()
    assert mw(request) == "VIEW_RESPONSE"
    assert request.agentadmit_user is None
    assert handled.get("reached_view") is True


def test_non_agentadmit_token_passes_through(middleware):
    mw, handled = middleware
    request = make_request("Bearer some_session_token")
    assert mw(request) == "VIEW_RESPONSE"
    assert request.agentadmit_user is None


def test_invalid_agent_token_is_rejected_with_401(middleware, monkeypatch):
    mw, handled = middleware
    monkeypatch.setattr(di, "_validate_agent_token",
                        MagicMock(side_effect=ValueError("Token is not active: token_expired")))
    request = make_request("Bearer ag_at_forged")
    response = mw(request)
    assert response.status_code == 401
    assert handled.get("reached_view") is None  # never reached the view


def test_rate_limited_introspection_surfaces_502(middleware, monkeypatch):
    mw, handled = middleware
    monkeypatch.setattr(di, "_validate_agent_token",
                        MagicMock(side_effect=RateLimitError("budget exhausted")))
    request = make_request("Bearer ag_at_x")
    response = mw(request)
    assert response.status_code == 502


def test_unavailable_introspection_surfaces_502(middleware, monkeypatch):
    mw, handled = middleware
    monkeypatch.setattr(di, "_validate_agent_token",
                        MagicMock(side_effect=IntrospectionUnavailableError("down")))
    request = make_request("Bearer ag_at_x")
    response = mw(request)
    assert response.status_code == 502


def test_valid_agent_token_attaches_context(middleware, monkeypatch):
    mw, handled = middleware
    ctx = {"user": {"user_id": "u1"}, "connection": {"connection_id": "c1"}, "scopes": ["read:things"]}
    monkeypatch.setattr(di, "_validate_agent_token", MagicMock(return_value=ctx))
    request = make_request("Bearer ag_at_good")
    assert mw(request) == "VIEW_RESPONSE"
    assert request.agentadmit_user["auth_type"] == "agent"
    assert request.agentadmit_user["scopes"] == ["read:things"]
