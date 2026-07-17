"""
Caller-Identity Consent dependency tests.

caller_consent must: classify the caller from credential structure before any
consent check; route each class to its OWN isolated path; fail closed on a
denied verdict or an unreachable ledger; and never let one class inherit
another's decision.
"""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from agentadmit.config import load_config
from agentadmit import callerconsent as cc_mod
from agentadmit.callerconsent import caller_consent, classify_caller


@pytest.fixture(autouse=True)
def _config(tmp_path):
    cfg = tmp_path / "agentadmit.yaml"
    cfg.write_text(
        "app_id: app_test\n"
        "app_name: Test App\n"
        "api_key: aa_test_dummy\n"
        "api_base_url: http://localhost\n"
        "storage:\n"
        "  backend: memory\n"
        "scopes:\n"
        "  - name: read:things\n"
        "    description: Read things\n"
        "    category: Things\n"
        "    role: user\n"
    )
    load_config(str(cfg))


def _creds(token):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _req(headers=None, path_params=None):
    return SimpleNamespace(headers=headers or {}, path_params=path_params or {})


AGENT_CTX = {
    "user": {"user_id": "user_1"},
    "connection": {"connection_id": "conn_1"},
    "scopes": ["read:things"],
    "consent": {"caller_class": "external_agent", "granted": True, "source": "app_default"},
}

# Introspection context WITHOUT a consent verdict (the hosted service omits the
# block when its consent read fails — the SDK must resolve via the ledger).
AGENT_CTX_NO_VERDICT = {k: v for k, v in AGENT_CTX.items() if k != "consent"}


# --- classify_caller -------------------------------------------------------

def test_classify_external_agent():
    assert classify_caller(_creds("ag_at_abc.def")) == "external_agent"


def test_classify_defaults_to_human():
    assert classify_caller(_creds("session_jwt")) == "human_session"


def test_classify_honors_non_agent_classifier():
    req = _req(headers={"x-internal-ai": "secret"})
    cls = classify_caller(
        _creds("session_jwt"),
        classify_non_agent=lambda r: "in_app_ai" if r.headers.get("x-internal-ai") == "secret" else "human_session",
        request=req,
    )
    assert cls == "in_app_ai"


# --- external_agent path ---------------------------------------------------

def test_external_allows_with_scope(monkeypatch):
    monkeypatch.setattr(cc_mod, "get_agentadmit_user", lambda creds: dict(AGENT_CTX))
    dep = caller_consent(required_scope="read:things")
    ctx = dep(request=_req(), credentials=_creds("ag_at_tok"))
    assert ctx["caller_class"] == "external_agent"
    assert ctx["auth_type"] == "agent"


def test_external_denies_missing_scope(monkeypatch):
    monkeypatch.setattr(cc_mod, "get_agentadmit_user", lambda creds: dict(AGENT_CTX))
    dep = caller_consent(required_scope="write:things")
    with pytest.raises(HTTPException) as ei:
        dep(request=_req(), credentials=_creds("ag_at_tok"))
    assert ei.value.status_code == 403
    assert ei.value.detail["error"] == "insufficient_scope"


def test_external_denies_when_consent_denied(monkeypatch):
    ctx = dict(AGENT_CTX, consent={"caller_class": "external_agent", "granted": False, "source": "setting"})
    monkeypatch.setattr(cc_mod, "get_agentadmit_user", lambda creds: ctx)
    dep = caller_consent()
    with pytest.raises(HTTPException) as ei:
        dep(request=_req(), credentials=_creds("ag_at_tok"))
    assert ei.value.status_code == 403
    assert ei.value.detail["error"] == "consent_not_granted"
    assert ei.value.detail["caller_class"] == "external_agent"


def test_external_consent_checked_before_scope(monkeypatch):
    """FIG. 3: denied consent wins over missing scope — the caller must not
    learn scope state (insufficient_scope + granted_scopes) when its class
    consent is denied."""
    ctx = dict(AGENT_CTX, consent={"caller_class": "external_agent", "granted": False, "source": "setting"})
    monkeypatch.setattr(cc_mod, "get_agentadmit_user", lambda creds: ctx)
    dep = caller_consent(required_scope="write:things")  # scope ALSO missing
    with pytest.raises(HTTPException) as ei:
        dep(request=_req(), credentials=_creds("ag_at_tok"))
    assert ei.value.detail["error"] == "consent_not_granted"
    assert "granted_scopes" not in ei.value.detail


def test_external_absent_verdict_resolved_via_ledger_allow(monkeypatch):
    """Absent verdict is never a grant: the SDK resolves it via check_consent."""
    monkeypatch.setattr(cc_mod, "get_agentadmit_user", lambda creds: dict(AGENT_CTX_NO_VERDICT))
    calls = []
    def ledger(owner, cls, sg=None):
        calls.append((owner, cls, sg))
        return {"caller_class": "external_agent", "granted": True, "source": "app_default"}
    monkeypatch.setattr(cc_mod, "check_consent", ledger)
    ctx = caller_consent()(request=_req(), credentials=_creds("ag_at_tok"))
    assert ctx["caller_class"] == "external_agent"
    assert calls == [("user_1", "external_agent", None)]
    assert ctx["consent"]["granted"] is True  # resolved verdict lands on the context


def test_external_absent_verdict_ledger_denies(monkeypatch):
    monkeypatch.setattr(cc_mod, "get_agentadmit_user", lambda creds: dict(AGENT_CTX_NO_VERDICT))
    monkeypatch.setattr(cc_mod, "check_consent", lambda o, c, sg=None: {"caller_class": "external_agent", "granted": False, "source": "setting"})
    with pytest.raises(HTTPException) as ei:
        caller_consent()(request=_req(), credentials=_creds("ag_at_tok"))
    assert ei.value.status_code == 403
    assert ei.value.detail["error"] == "consent_not_granted"


def test_external_absent_verdict_ledger_error_fails_closed(monkeypatch):
    monkeypatch.setattr(cc_mod, "get_agentadmit_user", lambda creds: dict(AGENT_CTX_NO_VERDICT))
    def boom(o, c, sg=None):
        raise RuntimeError("ledger unreachable")
    monkeypatch.setattr(cc_mod, "check_consent", boom)
    with pytest.raises(HTTPException) as ei:
        caller_consent()(request=_req(), credentials=_creds("ag_at_tok"))
    assert ei.value.status_code == 503
    assert ei.value.detail["error"] == "consent_unavailable"


def test_external_malformed_verdict_treated_as_absent(monkeypatch):
    """granted must be a real boolean — a truthy string is not a verdict."""
    ctx = dict(AGENT_CTX, consent={"caller_class": "external_agent", "granted": "yes", "source": "setting"})
    monkeypatch.setattr(cc_mod, "get_agentadmit_user", lambda creds: ctx)
    monkeypatch.setattr(cc_mod, "check_consent", lambda o, c, sg=None: {"caller_class": "external_agent", "granted": False, "source": "setting"})
    with pytest.raises(HTTPException) as ei:
        caller_consent()(request=_req(), credentials=_creds("ag_at_tok"))
    assert ei.value.detail["error"] == "consent_not_granted"


def test_external_absent_verdict_no_owner_fails_closed(monkeypatch):
    """No verdict AND no resolvable owner (deleted/stub user) — cannot resolve,
    so deny with 503 rather than allow."""
    ctx = {"user": {}, "scopes": ["read:things"]}
    monkeypatch.setattr(cc_mod, "get_agentadmit_user", lambda creds: ctx)
    with pytest.raises(HTTPException) as ei:
        caller_consent()(request=_req(), credentials=_creds("ag_at_tok"))
    assert ei.value.status_code == 503
    assert ei.value.detail["error"] == "consent_unavailable"


# --- in_app_ai path --------------------------------------------------------

def _as_internal_ai(**kw):
    return caller_consent(
        classify_non_agent=lambda r: "in_app_ai",
        resolve_data_owner_id=lambda r: "user_8842",
        **kw,
    )


def test_in_app_ai_allows_when_granted(monkeypatch):
    monkeypatch.setattr(cc_mod, "check_consent", lambda owner, cls, sg=None: {"caller_class": "in_app_ai", "granted": True, "source": "setting"})
    ctx = _as_internal_ai()(request=_req(), credentials=None)
    assert ctx["caller_class"] == "in_app_ai"


def test_in_app_ai_denies_when_denied(monkeypatch):
    monkeypatch.setattr(cc_mod, "check_consent", lambda owner, cls, sg=None: {"caller_class": "in_app_ai", "granted": False, "source": "setting"})
    with pytest.raises(HTTPException) as ei:
        _as_internal_ai()(request=_req(), credentials=None)
    assert ei.value.status_code == 403
    assert ei.value.detail["caller_class"] == "in_app_ai"


def test_in_app_ai_fails_closed_on_ledger_error(monkeypatch):
    def boom(owner, cls, sg=None):
        raise RuntimeError("ledger unreachable")
    monkeypatch.setattr(cc_mod, "check_consent", boom)
    with pytest.raises(HTTPException) as ei:
        _as_internal_ai()(request=_req(), credentials=None)
    assert ei.value.status_code == 503
    assert ei.value.detail["error"] == "consent_unavailable"


def test_in_app_ai_requires_owner_resolver():
    dep = caller_consent(classify_non_agent=lambda r: "in_app_ai")
    with pytest.raises(HTTPException) as ei:
        dep(request=_req(), credentials=None)
    assert ei.value.status_code == 500


# --- human_session path ----------------------------------------------------

def test_human_defers_without_ledger_call(monkeypatch):
    called = {"n": 0}
    def spy(*a, **k):
        called["n"] += 1
        return {"granted": True}
    monkeypatch.setattr(cc_mod, "check_consent", spy)
    ctx = caller_consent()(request=_req(), credentials=_creds("session_jwt"))
    assert ctx["caller_class"] == "human_session"
    assert called["n"] == 0  # Branch A is the app's own model; no ledger call


def test_human_gated_when_gate_human(monkeypatch):
    monkeypatch.setattr(cc_mod, "check_consent", lambda owner, cls, sg=None: {"caller_class": "human_session", "granted": False, "source": "setting"})
    dep = caller_consent(gate_human=True, resolve_data_owner_id=lambda r: "user_1")
    with pytest.raises(HTTPException) as ei:
        dep(request=_req(), credentials=_creds("session_jwt"))
    assert ei.value.status_code == 403
    assert ei.value.detail["caller_class"] == "human_session"
