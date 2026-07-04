"""
Consent Ledger client — hosted caller-identity consent verdicts.

External agents get their verdict inline in the verify response (the
``consent`` key on the introspection payload / agent context). The two
token-less caller classes (human sessions and your app's own in-app AI)
ask this endpoint.

Consent is orthogonal to token revocation: on a denied verdict your app
returns its own 403; nothing is revoked. Every evaluation is appended to
the exportable consent trail.
"""

from typing import Optional

from agentadmit.routes import _call_hosted_service

CALLER_CLASSES = ("human_session", "in_app_ai", "external_agent")


def check_consent(
    app_user_id: str,
    caller_class: str,
    scope_group: Optional[str] = None,
) -> dict:
    """
    Ask the Consent Ledger whether a caller class may act on a user's data.

    Args:
        app_user_id: Your app's identifier for the data owner.
        caller_class: One of "human_session", "in_app_ai", "external_agent".
        scope_group: Optional finer-than-class consent group.

    Returns:
        Verdict dict: {"granted": bool, "caller_class": str,
        "scope_group": str | None, "source": str, "evaluated_at": str}.
        ``source`` is which layer resolved it: "setting", "scope_setting",
        "app_default", or "platform_default".

    Raises:
        ValueError: caller_class is not one of the three classes.
        RuntimeError: the hosted service rejected the request.
    """
    if caller_class not in CALLER_CLASSES:
        raise ValueError(
            f"caller_class must be one of {CALLER_CLASSES}, got {caller_class!r}"
        )

    body = {"app_user_id": app_user_id, "caller_class": caller_class}
    if scope_group is not None:
        body["scope_group"] = scope_group

    resp = _call_hosted_service("POST", "/api/v1/consent/check", json=body)
    if resp.status_code != 200:
        try:
            data = resp.json()
        except Exception:
            data = {}
        raise RuntimeError(
            data.get("error_description")
            or data.get("error")
            or f"Consent check failed: HTTP {resp.status_code}"
        )
    return resp.json()
