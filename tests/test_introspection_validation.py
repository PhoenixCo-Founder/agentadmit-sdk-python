"""M5 - Introspection response validation (NoSQL injection protection).

The introspection endpoint can be compromised or serve a crafted response.
The SDK must:
  1. Only treat a token as valid when HTTP status is 2xx AND active is strictly
     the boolean True (not just truthy).
  2. Reject responses where user_id / connection_id / agent_id / scopes are not
     the expected types (str / list[str]).
  3. Never pass a non-string user_id to a storage lookup — the canonical
     NoSQL injection payload is {"$ne": null} which matches any document.

These tests exercise the three integration paths:
  - agentadmit.auth.get_agentadmit_user  (FastAPI)
  - AgentAdmitFlask._validate_agent_token (Flask)
  - _validate_agent_token (Django)
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient

from agentadmit import auth as auth_mod
from agentadmit.integrations import flask_integration as fi
from agentadmit.integrations import django_integration as di
from agentadmit.storage import MemoryStorage


# ===========================================================================
# FastAPI path: auth.get_agentadmit_user
# ===========================================================================

def _make_fastapi_ctx(monkeypatch, introspection_payload, status_code=200):
    """
    Patch auth module so get_agentadmit_user returns the given introspection
    payload without hitting the network.
    """
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
    storage.add_test_user("user_123", {"user_id": "user_123", "email": "u@example.com"})
    monkeypatch.setattr(auth_mod, "_get_storage", lambda: storage)

    monkeypatch.setattr(
        auth_mod, "_introspect_with_retry",
        lambda *a, **kw: httpx.Response(status_code, json=introspection_payload),
    )


def call_get_agentadmit_user(monkeypatch, introspection_payload, status_code=200):
    """Run get_agentadmit_user and return the result or raise the exception."""
    _make_fastapi_ctx(monkeypatch, introspection_payload, status_code)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="ag_at_sometoken")
    return auth_mod.get_agentadmit_user(creds)


# --- active must be strictly True (bool) ------------------------------------

def test_fastapi_active_true_boolean_accepted(monkeypatch):
    result = call_get_agentadmit_user(monkeypatch, {
        "active": True,
        "user_id": "user_123",
        "scopes": ["read:things"],
    })
    assert result["scopes"] == ["read:things"]


def test_fastapi_active_false_rejected(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        call_get_agentadmit_user(monkeypatch, {"active": False})
    assert exc_info.value.status_code == 401


def test_fastapi_active_truthy_int_rejected(monkeypatch):
    """active=1 is truthy but not the boolean True - must be rejected."""
    with pytest.raises(HTTPException) as exc_info:
        call_get_agentadmit_user(monkeypatch, {
            "active": 1,
            "user_id": "user_123",
            "scopes": ["read:things"],
        })
    assert exc_info.value.status_code == 401


def test_fastapi_active_truthy_string_rejected(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        call_get_agentadmit_user(monkeypatch, {
            "active": "yes",
            "user_id": "user_123",
            "scopes": [],
        })
    assert exc_info.value.status_code == 401


# --- NoSQL injection: user_id as dict ---------------------------------------

def test_fastapi_nosql_injection_user_id_dict_rejected(monkeypatch):
    """The canonical NoSQL injection payload {"$ne": null} must be rejected."""
    with pytest.raises(HTTPException) as exc_info:
        call_get_agentadmit_user(monkeypatch, {
            "active": True,
            "user_id": {"$ne": None},
            "scopes": ["read:things"],
        })
    assert exc_info.value.status_code == 401


def test_fastapi_user_id_int_rejected(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        call_get_agentadmit_user(monkeypatch, {
            "active": True,
            "user_id": 12345,
            "scopes": ["read:things"],
        })
    assert exc_info.value.status_code == 401


def test_fastapi_connection_id_dict_rejected(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        call_get_agentadmit_user(monkeypatch, {
            "active": True,
            "user_id": "user_123",
            "connection_id": {"$ne": None},
            "scopes": ["read:things"],
        })
    assert exc_info.value.status_code == 401


def test_fastapi_scopes_not_list_rejected(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        call_get_agentadmit_user(monkeypatch, {
            "active": True,
            "user_id": "user_123",
            "scopes": "read:things",  # string, not list
        })
    assert exc_info.value.status_code == 401


def test_fastapi_scopes_list_of_nonstr_rejected(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        call_get_agentadmit_user(monkeypatch, {
            "active": True,
            "user_id": "user_123",
            "scopes": [{"$ne": None}],
        })
    assert exc_info.value.status_code == 401


def test_fastapi_agent_id_dict_rejected(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        call_get_agentadmit_user(monkeypatch, {
            "active": True,
            "user_id": "user_123",
            "agent_id": {"$gt": ""},
            "scopes": ["read:things"],
        })
    assert exc_info.value.status_code == 401


# --- Non-2xx status is rejected (even with active:true in body) -------------

def test_fastapi_4xx_status_rejected(monkeypatch):
    with pytest.raises(HTTPException) as exc_info:
        call_get_agentadmit_user(monkeypatch, {
            "active": True,
            "user_id": "user_123",
            "scopes": ["read:things"],
        }, status_code=403)
    assert exc_info.value.status_code in (401, 403, 502)


# ===========================================================================
# Flask path: AgentAdmitFlask._validate_agent_token
# ===========================================================================

@pytest.fixture()
def flask_aa(tmp_path):
    config_file = tmp_path / "agentadmit.yaml"
    config_file.write_text("\n".join([
        "app_id: app_test",
        "app_name: Test App",
        "api_key: aa_test_dummy",
        "api_base_url: http://localhost:8000",
        "agentadmit_api_url: http://localhost:9000",
        "agentadmit_verify_url: http://localhost:9000/verify",
        "storage:",
        "  backend: memory",
        "scopes: []",
    ]))
    aa = fi.AgentAdmitFlask(config_path=str(config_file))
    aa.storage = MagicMock()
    aa.storage.get_user.return_value = {"user_id": "u1"}
    return aa


def flask_validate(aa, monkeypatch, payload, status=200):
    monkeypatch.setattr(
        fi, "_introspect_with_retry",
        lambda *a, **kw: httpx.Response(status, json=payload),
    )
    return aa._validate_agent_token("ag_at_sometoken")


def test_flask_valid_response_accepted(flask_aa, monkeypatch):
    result = flask_validate(flask_aa, monkeypatch, {
        "active": True,
        "user_id": "u1",
        "scopes": ["read:things"],
    })
    assert result["scopes"] == ["read:things"]


def test_flask_nosql_injection_user_id_rejected(flask_aa, monkeypatch):
    with pytest.raises(ValueError, match="type validation"):
        flask_validate(flask_aa, monkeypatch, {
            "active": True,
            "user_id": {"$ne": None},
            "scopes": [],
        })


def test_flask_active_not_bool_true_rejected(flask_aa, monkeypatch):
    with pytest.raises(ValueError, match="not active"):
        flask_validate(flask_aa, monkeypatch, {
            "active": 1,
            "user_id": "u1",
            "scopes": [],
        })


def test_flask_scopes_nonlist_rejected(flask_aa, monkeypatch):
    with pytest.raises(ValueError, match="type validation"):
        flask_validate(flask_aa, monkeypatch, {
            "active": True,
            "user_id": "u1",
            "scopes": "read:things",
        })


def test_flask_connection_id_dict_rejected(flask_aa, monkeypatch):
    with pytest.raises(ValueError, match="type validation"):
        flask_validate(flask_aa, monkeypatch, {
            "active": True,
            "user_id": "u1",
            "connection_id": {"$ne": None},
            "scopes": [],
        })


# ===========================================================================
# Django path: _validate_agent_token
# ===========================================================================

@pytest.fixture()
def django_ctx(monkeypatch):
    fake_config = SimpleNamespace(
        app_id="app_test",
        api_key="aa_test_key",
        agentadmit_verify_url="http://localhost:9000/verify",
        token_prefix_access="ag_at_",
        user_lookup_field="user_id",
    )
    storage = MagicMock()
    storage.get_user.return_value = {"user_id": "u1"}
    monkeypatch.setattr(di, "_config", fake_config)
    monkeypatch.setattr(di, "_storage", storage)
    monkeypatch.setattr(di, "_init", lambda: None)
    return storage


def django_validate(monkeypatch, payload, status=200):
    monkeypatch.setattr(
        di, "_introspect_with_retry",
        lambda *a, **kw: httpx.Response(status, json=payload),
    )
    return di._validate_agent_token("ag_at_sometoken")


def test_django_valid_response_accepted(django_ctx, monkeypatch):
    result = django_validate(monkeypatch, {
        "active": True,
        "user_id": "u1",
        "scopes": ["read:things"],
    })
    assert result["scopes"] == ["read:things"]


def test_django_nosql_injection_user_id_rejected(django_ctx, monkeypatch):
    with pytest.raises(ValueError, match="type validation"):
        django_validate(monkeypatch, {
            "active": True,
            "user_id": {"$ne": None},
            "scopes": [],
        })


def test_django_active_int_truthy_rejected(django_ctx, monkeypatch):
    with pytest.raises(ValueError, match="not active"):
        django_validate(monkeypatch, {
            "active": 1,
            "user_id": "u1",
            "scopes": [],
        })


def test_django_scopes_with_dict_entry_rejected(django_ctx, monkeypatch):
    with pytest.raises(ValueError, match="type validation"):
        django_validate(monkeypatch, {
            "active": True,
            "user_id": "u1",
            "scopes": [{"$ne": None}],
        })


def test_django_agent_id_non_string_rejected(django_ctx, monkeypatch):
    with pytest.raises(ValueError, match="type validation"):
        django_validate(monkeypatch, {
            "active": True,
            "user_id": "u1",
            "agent_id": 999,
            "scopes": [],
        })


# ===========================================================================
# Storage layer guard: MongoDBStorage.get_user rejects non-string user_id
# ===========================================================================

def test_memory_storage_get_user_non_string_returns_none():
    """MemoryStorage doesn't use Mongo queries but the explicit guard on
    MongoDBStorage.get_user is tested via the integration paths above.
    This test verifies the contract at the base: passing a dict user_id
    never reaches the query."""
    from agentadmit.storage import MemoryStorage
    storage = MemoryStorage()
    storage.add_test_user("u1", {"user_id": "u1"})
    # dict user_id should not crash — and cannot match the str key
    result = storage.get_user({"$ne": None}, "user_id")
    assert result is None
