"""
agentadmit.webhooks
-------------------
Verification for inbound AgentAdmit alert webhooks.

AgentAdmit signs every alert webhook delivery with the app's webhook signing
secret (`whsec_…`, returned once when the webhook URL is configured). The
signature is sent in the `X-AgentAdmit-Signature` header:

    X-AgentAdmit-Signature: t=<unix_ts>,v1=<hex hmac-sha256>

where the HMAC input is `"{t}.{raw_body}"` keyed with the full whsec_ secret.
Always verify against the raw request body bytes, before any JSON parsing.

Usage (FastAPI):
    from agentadmit.webhooks import verify_webhook_signature

    @app.post("/agentadmit/alerts")
    async def alerts(request: Request):
        payload = await request.body()
        verify_webhook_signature(
            payload,
            request.headers.get("X-AgentAdmit-Signature", ""),
            secret=os.environ["AGENTADMIT_WEBHOOK_SECRET"],
        )
        event = json.loads(payload)
        ...
"""

import hashlib
import hmac
import time
from typing import Optional, Union

from agentadmit.exceptions import WebhookSignatureError

SIGNATURE_HEADER = "X-AgentAdmit-Signature"
DEFAULT_TOLERANCE_SECONDS = 300


def verify_webhook_signature(
    payload: Union[bytes, str],
    signature_header: str,
    secret: str,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: Optional[int] = None,
) -> None:
    """
    Verify the X-AgentAdmit-Signature header on an inbound alert webhook.

    Args:
        payload: The raw request body (bytes preferred; str is encoded UTF-8).
        signature_header: The X-AgentAdmit-Signature header value.
        secret: The app's webhook signing secret (whsec_…).
        tolerance_seconds: Maximum allowed clock skew between the signature
            timestamp and now. Deliveries outside the window are rejected to
            prevent replay. Set to 0 to disable the timestamp check.
        now: Override the current unix timestamp (for tests).

    Raises:
        WebhookSignatureError: If the header is missing/malformed, the
            timestamp is outside the tolerance window, or no v1 signature
            matches. The message never includes the secret or the payload.
    """
    if not secret:
        raise WebhookSignatureError("Webhook signing secret is required")
    if not signature_header:
        raise WebhookSignatureError("Missing X-AgentAdmit-Signature header")

    if isinstance(payload, str):
        payload = payload.encode("utf-8")

    timestamp: Optional[int] = None
    candidates: list[str] = []
    for part in signature_header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            try:
                timestamp = int(value)
            except ValueError:
                raise WebhookSignatureError("Malformed signature header")
        elif key == "v1":
            candidates.append(value)

    if timestamp is None or not candidates:
        raise WebhookSignatureError("Malformed signature header")

    if tolerance_seconds:
        current = int(time.time()) if now is None else now
        if abs(current - timestamp) > tolerance_seconds:
            raise WebhookSignatureError("Signature timestamp outside tolerance window")

    expected = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.".encode("utf-8") + payload,
        hashlib.sha256,
    ).hexdigest()

    if not any(hmac.compare_digest(expected, candidate) for candidate in candidates):
        raise WebhookSignatureError("Signature verification failed")


def is_valid_webhook_signature(
    payload: Union[bytes, str],
    signature_header: str,
    secret: str,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: Optional[int] = None,
) -> bool:
    """Boolean form of verify_webhook_signature()."""
    try:
        verify_webhook_signature(payload, signature_header, secret, tolerance_seconds, now)
        return True
    except WebhookSignatureError:
        return False
