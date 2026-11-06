"""
Tests for agent designation on the verify context (v1.14.0).

On AgentAdmit's consent page the user says which agent app a connection is
for and, optionally, which AI model family it mainly uses. Separately, the
agent may report its own platform and model when it redeems the connection
token. The hosted /verify response carries both:

    designated_agent: {agent_id, name, source: "user_declared", model} | null
    agent_reported:   {platform, model: {id, version}} | null

Semantic matrix (identical in every server SDK):
  - a well-formed designated_agent reaches the context unchanged
  - null / absent / malformed (no name, wrong source, not a dict) ->
    context key absent, never coerced
  - a typed name has agent_id None; a model with no listed id has model_id
    None; a malformed model is dropped and the app is kept
  - agent_reported reaches the context when it has a string platform or a
    model with a string id; version is None when not a string
  - agent_reported with neither is absent
  - both are review-time records: nothing in the SDK branches on them
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
from fastapi.security import HTTPAuthorizationCredentials

import agentadmit
from agentadmit import auth as auth_mod
from agentadmit import parse_agent_reported, parse_designated_agent
from agentadmit.integrations import django_integration as di
from agentadmit.integrations import flask_integration as fi
from agentadmit.models import VerifyResponse
from agentadmit.storage import MemoryStorage


ACTIVE_PAYLOAD = {
    "active": True,
    "user_id": "user_123",
    "connection_id": "conn_1",
    "scopes": ["read:things"],
    "agent_label": "Test Agent",
}
LISTED = {
    "agent_id": "agt_openclaw",
    "name": "OpenClaw",
    "source": "user_declared",
    "model": {"model_id": "agt_claude", "name": "Claude (Anthropic)"},
}
REPORTED = {"platform": "OpenClaw 2026.6", "model": {"id": "example-model", "version": "2026-01"}}
BAD_DESIGNATIONS = [
    "OpenClaw", 7, [], {}, {"name": ""}, {"name": 5, "source": "user_declared"},
    {"name": "OpenClaw"}, {"name": "OpenClaw", "source": "operator_verified"},
]


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


# ===========================================================================
# FastAPI context
# ===========================================================================

def test_verify_attaches_the_user_designation_to_context(monkeypatch):
    context = _call_verify(monkeypatch, dict(ACTIVE_PAYLOAD, designated_agent=LISTED))

    assert context["designated_agent"] == LISTED
    assert context["scopes"] == ["read:things"]


def test_agent_label_stays_separate_from_the_designation(monkeypatch):
    context = _call_verify(
        monkeypatch, dict(ACTIVE_PAYLOAD, agent_label="Claude Code 2.1", designated_agent=LISTED))

    assert context["connection"]["agent_label"] == "Claude Code 2.1"
    assert context["designated_agent"]["name"] == "OpenClaw"


def test_typed_name_has_no_agent_id_and_no_model(monkeypatch):
    typed = {"agent_id": None, "name": "My research agent", "source": "user_declared", "model": None}
    context = _call_verify(monkeypatch, dict(ACTIVE_PAYLOAD, designated_agent=typed))

    assert context["designated_agent"] == typed


def test_wire_null_means_no_designation(monkeypatch):
    context = _call_verify(
        monkeypatch, dict(ACTIVE_PAYLOAD, designated_agent=None, agent_reported=None))

    assert "designated_agent" not in context
    assert "agent_reported" not in context


def test_older_servers_send_neither(monkeypatch):
    context = _call_verify(monkeypatch, dict(ACTIVE_PAYLOAD))

    assert "designated_agent" not in context
    assert "agent_reported" not in context


def test_verify_attaches_what_the_agent_reported(monkeypatch):
    context = _call_verify(monkeypatch, dict(ACTIVE_PAYLOAD, agent_reported=REPORTED))

    assert context["agent_reported"] == REPORTED


def test_both_records_ride_independently(monkeypatch):
    reported = {"platform": None, "model": {"id": "gpt-x", "version": None}}
    context = _call_verify(
        monkeypatch, dict(ACTIVE_PAYLOAD, designated_agent=LISTED, agent_reported=reported))

    assert context["designated_agent"]["model"]["name"] == "Claude (Anthropic)"
    assert context["agent_reported"] == reported


@pytest.mark.parametrize("bad", BAD_DESIGNATIONS)
def test_malformed_designation_is_dropped_without_failing(monkeypatch, bad):
    """The token verdict must survive; a junk designation must not ride along."""
    context = _call_verify(monkeypatch, dict(ACTIVE_PAYLOAD, designated_agent=bad))

    assert context["connection"]["connection_id"] == "conn_1"
    assert "designated_agent" not in context


# ===========================================================================
# Readers
# ===========================================================================

def test_parse_designated_agent_reads_a_listed_app_and_model():
    assert parse_designated_agent(dict(LISTED, extra="dropped")) == LISTED


@pytest.mark.parametrize("bad_model", ["Grok", 3, {}, {"name": ""}, {"name": 9}, {"model_id": "agt_x"}])
def test_malformed_model_is_dropped_and_the_app_is_kept(bad_model):
    out = parse_designated_agent(
        {"agent_id": "agt_1", "name": "Hermes", "source": "user_declared", "model": bad_model})

    assert out == {"agent_id": "agt_1", "name": "Hermes", "source": "user_declared", "model": None}


def test_model_named_without_a_listed_id_has_no_model_id():
    out = parse_designated_agent(
        {"agent_id": "agt_1", "name": "OpenClaw", "source": "user_declared", "model": {"name": "Mistral"}})

    assert out["model"] == {"model_id": None, "name": "Mistral"}


@pytest.mark.parametrize("bad", [None, "x", 1, [], {}, {"name": "x"}, {"name": "x", "source": "agent_reported"}])
def test_parse_designated_agent_rejects_anything_else(bad):
    assert parse_designated_agent(bad) is None


def test_parse_agent_reported_reads_platform_and_model():
    assert parse_agent_reported(dict(REPORTED)) == REPORTED


def test_parse_agent_reported_partial_values():
    assert parse_agent_reported({"platform": "ExampleAgent"}) == {"platform": "ExampleAgent", "model": None}
    assert parse_agent_reported({"model": {"id": "m1"}}) == {"platform": None, "model": {"id": "m1", "version": None}}
    assert parse_agent_reported({"model": {"id": "m1", "version": 3}}) == {
        "platform": None, "model": {"id": "m1", "version": None}}


@pytest.mark.parametrize("bad", [
    None, "x", 1, [], {}, {"platform": 5}, {"platform": ""}, {"model": {}},
    {"model": {"version": "1"}}, {"platform": None, "model": None},
])
def test_parse_agent_reported_returns_none_without_platform_or_model_id(bad):
    assert parse_agent_reported(bad) is None


def test_readers_are_exported_from_the_package():
    assert agentadmit.parse_designated_agent is parse_designated_agent
    assert "parse_designated_agent" in agentadmit.__all__
    assert "parse_agent_reported" in agentadmit.__all__


# ===========================================================================
# Typed VerifyResponse model
# ===========================================================================

def test_verify_response_model_parses_both_fields():
    parsed = VerifyResponse.model_validate(
        dict(ACTIVE_PAYLOAD, designated_agent=LISTED, agent_reported=REPORTED))

    assert parsed.designated_agent == LISTED
    assert parsed.agent_reported == REPORTED


def test_verify_response_model_defaults_none_and_accepts_null():
    assert VerifyResponse.model_validate(dict(ACTIVE_PAYLOAD)).designated_agent is None
    parsed = VerifyResponse.model_validate(
        dict(ACTIVE_PAYLOAD, designated_agent=None, agent_reported=None))
    assert parsed.designated_agent is None
    assert parsed.agent_reported is None


# ===========================================================================
# Flask and Django contexts
# ===========================================================================

@pytest.fixture()
def flask_app(tmp_path):
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
    return aa


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
    return storage


def test_flask_verify_attaches_both_records(flask_app, monkeypatch):
    flask_app.storage.get_user.return_value = {"user_id": "user_123"}
    monkeypatch.setattr(
        fi, "_introspect_with_retry",
        MagicMock(return_value=httpx.Response(
            200, json=dict(ACTIVE_PAYLOAD, designated_agent=LISTED, agent_reported=REPORTED))),
    )

    ctx = flask_app._validate_agent_token("ag_at_x")

    assert ctx["designated_agent"] == LISTED
    assert ctx["agent_reported"] == REPORTED


def test_flask_verify_without_designation_has_neither_key(flask_app, monkeypatch):
    flask_app.storage.get_user.return_value = {"user_id": "user_123"}
    monkeypatch.setattr(
        fi, "_introspect_with_retry",
        MagicMock(return_value=httpx.Response(200, json=dict(ACTIVE_PAYLOAD, designated_agent="junk"))),
    )

    ctx = flask_app._validate_agent_token("ag_at_x")

    assert "designated_agent" not in ctx
    assert "agent_reported" not in ctx


def test_django_verify_attaches_both_records(django_env, monkeypatch):
    monkeypatch.setattr(
        di, "_introspect_with_retry",
        MagicMock(return_value=httpx.Response(
            200, json=dict(ACTIVE_PAYLOAD, designated_agent=LISTED, agent_reported=REPORTED))),
    )
    django_env.get_user.return_value = {"user_id": "user_123"}

    ctx = di._validate_agent_token("ag_at_x")

    assert ctx["designated_agent"] == LISTED
    assert ctx["agent_reported"] == REPORTED


def test_django_verify_without_designation_has_neither_key(django_env, monkeypatch):
    monkeypatch.setattr(
        di, "_introspect_with_retry",
        MagicMock(return_value=httpx.Response(200, json=dict(ACTIVE_PAYLOAD))),
    )
    django_env.get_user.return_value = {"user_id": "user_123"}

    ctx = di._validate_agent_token("ag_at_x")

    assert "designated_agent" not in ctx
    assert "agent_reported" not in ctx
