"""
agentadmit.owner_link
---------------------
Owner link for a pending confirm-each-time action (1.15.0).

When a scope needs a fresh human confirmation and the user has no passkey on
file for the app yet, the link the agent holds cannot be used alone. The
app's backend asks the hosted service for an owner link for its own
signed-in user and sends that user to ``owner_session_url``. On that page the
user creates a passkey and confirms the action; on a computer the page can
show a QR code to continue on the user's phone.

Two rules:

1. Call :func:`create_owner_link` only from a route your signed-in human
   uses, passing that user's id.
2. Never return ``owner_session_url`` to an agent. Whoever opens it can create
   the passkey that confirms the action.

This module is not mounted on the SDK router on purpose: the router serves
agent-facing routes.
"""

from urllib.parse import quote

from agentadmit.exceptions import OwnerLinkError
from agentadmit.routes import _call_hosted_service

_ACTION_SESSION_ID_MIN = 20
_APP_USER_ID_MAX = 255


def create_owner_link(action_session_id: str, app_user_id: str) -> dict:
    """Open a pending confirmation for your own signed-in user.

    ``POST /api/v1/action-sessions/{action_session_id}/owner-link`` with the
    app's API key and ``{"app_user_id": ...}``. ``action_session_id`` is the
    ``confirmation["action_session_id"]`` from the ``confirmation_required``
    refusal; ``app_user_id`` is the id of the user your backend has signed
    in, and it must be the user the confirmation is for.

    Call it only from a route your signed-in human uses; never return
    ``owner_session_url`` to an agent, and never log it.

    Returns:
        dict with ``action_session_id``, ``owner_session_url``,
        ``enrollment_required`` (bool), ``expires_at``, and
        ``enrollment_reason`` (``no_passkey`` or ``no_eligible_authenticator``)
        only when ``enrollment_required`` is True.

    Raises:
        ValueError: a bad argument, before any network call.
        OwnerLinkError: any non-2xx answer (no retry), or a malformed 2xx body.
        fastapi.HTTPException: 502 when the hosted service cannot be reached
            (the same as the SDK's other hosted calls).
    """
    if (
        not isinstance(action_session_id, str)
        or not action_session_id.startswith("asess_")
        or len(action_session_id) < _ACTION_SESSION_ID_MIN
    ):
        raise ValueError("action_session_id must be the action_session_id from the confirmation block (asess_...)")
    if not isinstance(app_user_id, str) or not app_user_id or len(app_user_id) > _APP_USER_ID_MAX:
        raise ValueError(f"app_user_id must be a non-empty string of at most {_APP_USER_ID_MAX} characters")

    path = f"/api/v1/action-sessions/{quote(action_session_id, safe='')}/owner-link"
    resp = _call_hosted_service("POST", path, json={"app_user_id": app_user_id})

    try:
        data = resp.json()
    except ValueError:
        data = None
    body = data if isinstance(data, dict) else {}

    if not 200 <= resp.status_code < 300:
        code = body.get("error") if isinstance(body.get("error"), str) else None
        suffix = f" {code}" if code else ""
        raise OwnerLinkError(f"Owner link request failed: HTTP {resp.status_code}{suffix}", resp.status_code, code)

    if not (
        isinstance(body.get("owner_session_url"), str)
        and isinstance(body.get("enrollment_required"), bool)
        and isinstance(body.get("action_session_id"), str)
        and isinstance(body.get("expires_at"), str)
    ):
        raise OwnerLinkError("Malformed owner link response from the authorization service", resp.status_code, None)

    link = {
        "action_session_id": body["action_session_id"],
        "owner_session_url": body["owner_session_url"],
        "enrollment_required": body["enrollment_required"],
        "expires_at": body["expires_at"],
    }
    if body["enrollment_required"] and isinstance(body.get("enrollment_reason"), str):
        link["enrollment_reason"] = body["enrollment_reason"]
    return link
