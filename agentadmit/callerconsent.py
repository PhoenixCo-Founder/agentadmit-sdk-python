"""
agentadmit.callerconsent
------------------------
Caller-Identity Consent as a FastAPI dependency: the "classify caller, then
gate the right independent path" recipe in one dependency, so an app owner
does not have to hand-roll it.

One endpoint serves every caller class. On each request the dependency:
  1. classifies the caller from the STRUCTURE of the credential (a class the
     caller cannot self-select), before any consent check;
  2. routes to that class's ISOLATED consent path; no path reads or inherits
     another class's preference;
  3. permits or denies, and returns the resolved context.

  external_agent : an ``ag_at_`` access token -> hosted introspection, which
                   returns the external-agent consent verdict inline plus the
                   granted scopes. Enforced here directly.
  in_app_ai      : your application's own server-side AI code path -> the
                   Consent Ledger ``/consent/check`` for the in-app-AI class.
  human_session  : your application's own permission model (sharing, roles,
                   grants). Deferred to your existing authorization by default;
                   opt in to a stored human-session switch with ``gate_human``.

The three decisions are independent: granting one never grants another.

SECURITY: this is a consent gate, not an authenticator. It classifies the
caller and enforces the per-class CONSENT decision; it does not by itself
authenticate a human session. Use it after your own authentication. On the
human_session path it defers to your permission model and returns without
re-authenticating, so a request carrying no agent token resolves as a human
session for your own authorization to judge. The external_agent path is always
authenticated (hosted introspection); the in_app_ai path always evaluates the
ledger.
"""

from typing import Callable, Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials

from agentadmit.config import get_config
from agentadmit.auth import get_agentadmit_user, security
from agentadmit.consent import check_consent

NON_AGENT_CLASSES = ("human_session", "in_app_ai")


def classify_caller(
    credentials: Optional[HTTPAuthorizationCredentials],
    classify_non_agent: Optional[Callable[[Request], str]] = None,
    request: Optional[Request] = None,
) -> str:
    """
    Classify the caller from credential structure, before any consent check.

    An ``ag_at_`` access token is an external agent; anything else is resolved
    by ``classify_non_agent`` (default: "human_session"). The class is derived,
    never self-selected by the caller.
    """
    config = get_config()
    token = credentials.credentials if credentials is not None else None
    if token and token.startswith(config.token_prefix_access):
        return "external_agent"
    if classify_non_agent is not None and request is not None:
        return classify_non_agent(request)
    return "human_session"


def caller_consent(
    resolve_data_owner_id: Optional[Callable[[Request], str]] = None,
    classify_non_agent: Optional[Callable[[Request], str]] = None,
    required_scope: Optional[str] = None,
    scope_group: Optional[str] = None,
    gate_human: bool = False,
):
    """
    FastAPI dependency factory enforcing caller-identity consent at one endpoint.

    Args:
        resolve_data_owner_id: Given the request, return your app's identifier
            for the data owner whose resource is accessed. Required for the
            in_app_ai path, and for human_session when ``gate_human`` is set.
            For external_agent the owner comes from the token, so it is not used.
        classify_non_agent: Given the request, return "in_app_ai" or
            "human_session" for a non-agent caller, derived from the structure
            of the credential (for example an internal service token), never a
            value the caller can set. Defaults to "human_session".
        required_scope: For the external_agent path, require this scope.
        scope_group: Optional finer-than-class consent group for the ledger.
        gate_human: Also gate the human_session class against a stored switch.

    Usage:
        @app.get("/api/records/{owner_id}")
        async def get_record(
            ctx=Depends(caller_consent(
                classify_non_agent=lambda r: "in_app_ai" if r.headers.get("x-internal-ai") == SECRET else "human_session",
                resolve_data_owner_id=lambda r: r.path_params["owner_id"],
                required_scope="read:records",
            )),
        ):
            ...
    """

    def dependency(
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(security),
    ) -> dict:
        caller_class = classify_caller(credentials, classify_non_agent, request)

        # ── external_agent: hosted introspection carries the verdict + scopes ──
        if caller_class == "external_agent":
            agent_ctx = get_agentadmit_user(credentials)
            if required_scope and required_scope not in agent_ctx.get("scopes", []):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "insufficient_scope",
                        "required_scope": required_scope,
                        "granted_scopes": agent_ctx.get("scopes", []),
                    },
                )
            consent = agent_ctx.get("consent")
            if isinstance(consent, dict) and consent.get("granted") is False:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "consent_not_granted",
                        "caller_class": "external_agent",
                        "source": consent.get("source"),
                    },
                )
            return {"auth_type": "agent", "caller_class": "external_agent", **agent_ctx}

        # ── in_app_ai: your own AI code path, gated on the ledger ─────────────
        if caller_class == "in_app_ai":
            owner = resolve_data_owner_id(request) if resolve_data_owner_id else None
            if not owner:
                raise HTTPException(
                    status_code=500,
                    detail={"error": "server_error", "error_description": "resolve_data_owner_id is required for the in_app_ai path"},
                )
            try:
                verdict = check_consent(owner, "in_app_ai", scope_group)
            except Exception as exc:
                # Fail closed: an unreachable or erroring ledger denies, never allows.
                raise HTTPException(status_code=503, detail={"error": "consent_unavailable", "error_description": str(exc)})
            if not verdict.get("granted"):
                raise HTTPException(
                    status_code=403,
                    detail={"error": "consent_not_granted", "caller_class": "in_app_ai", "source": verdict.get("source")},
                )
            return {"auth_type": "in_app_ai", "caller_class": "in_app_ai", "consent": verdict}

        # ── human_session: your own permission model (Branch A) ───────────────
        if gate_human:
            owner = resolve_data_owner_id(request) if resolve_data_owner_id else None
            if not owner:
                raise HTTPException(
                    status_code=500,
                    detail={"error": "server_error", "error_description": "resolve_data_owner_id is required when gate_human is set"},
                )
            try:
                verdict = check_consent(owner, "human_session", scope_group)
            except Exception as exc:
                raise HTTPException(status_code=503, detail={"error": "consent_unavailable", "error_description": str(exc)})
            if not verdict.get("granted"):
                raise HTTPException(
                    status_code=403,
                    detail={"error": "consent_not_granted", "caller_class": "human_session", "source": verdict.get("source")},
                )
            return {"auth_type": "user", "caller_class": "human_session", "consent": verdict}

        # Default: defer the human path to the app's existing authorization.
        return {"auth_type": "user", "caller_class": "human_session"}

    return dependency
