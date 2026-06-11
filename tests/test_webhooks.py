"""Tests for agentadmit.webhooks — X-AgentAdmit-Signature verification."""

import hashlib
import hmac

import pytest

from agentadmit.exceptions import WebhookSignatureError
from agentadmit.webhooks import is_valid_webhook_signature, verify_webhook_signature

SECRET = "whsec_test123"
PAYLOAD = b'{"event":"agentadmit.alert","alert_type":"usage_spike"}'
NOW = 1750000000


def sign(payload: bytes, secret: str = SECRET, timestamp: int = NOW) -> str:
    digest = hmac.new(
        secret.encode(), f"{timestamp}.".encode() + payload, hashlib.sha256
    ).hexdigest()
    return f"t={timestamp},v1={digest}"


def test_valid_signature_passes():
    verify_webhook_signature(PAYLOAD, sign(PAYLOAD), SECRET, now=NOW)


def test_str_payload_passes():
    verify_webhook_signature(PAYLOAD.decode(), sign(PAYLOAD), SECRET, now=NOW)


def test_tampered_payload_fails():
    with pytest.raises(WebhookSignatureError, match="verification failed"):
        verify_webhook_signature(PAYLOAD + b" ", sign(PAYLOAD), SECRET, now=NOW)


def test_wrong_secret_fails():
    with pytest.raises(WebhookSignatureError, match="verification failed"):
        verify_webhook_signature(
            PAYLOAD, sign(PAYLOAD, secret="whsec_other456"), SECRET, now=NOW
        )


def test_stale_timestamp_fails():
    header = sign(PAYLOAD, timestamp=NOW - 600)
    with pytest.raises(WebhookSignatureError, match="tolerance"):
        verify_webhook_signature(PAYLOAD, header, SECRET, now=NOW)


def test_future_timestamp_fails():
    header = sign(PAYLOAD, timestamp=NOW + 600)
    with pytest.raises(WebhookSignatureError, match="tolerance"):
        verify_webhook_signature(PAYLOAD, header, SECRET, now=NOW)


def test_within_tolerance_passes():
    verify_webhook_signature(PAYLOAD, sign(PAYLOAD, timestamp=NOW - 200), SECRET, now=NOW)


def test_tolerance_disabled_allows_old_timestamp():
    header = sign(PAYLOAD, timestamp=NOW - 99999)
    verify_webhook_signature(PAYLOAD, header, SECRET, tolerance_seconds=0, now=NOW)


def test_missing_header_fails():
    with pytest.raises(WebhookSignatureError, match="Missing"):
        verify_webhook_signature(PAYLOAD, "", SECRET, now=NOW)


@pytest.mark.parametrize("header", ["nonsense", "t=,v1=abc", "t=123", "v1=abc"])
def test_malformed_header_fails(header):
    with pytest.raises(WebhookSignatureError, match="Malformed"):
        verify_webhook_signature(PAYLOAD, header, SECRET, now=NOW)


def test_missing_secret_fails():
    with pytest.raises(WebhookSignatureError, match="secret"):
        verify_webhook_signature(PAYLOAD, sign(PAYLOAD), "", now=NOW)


def test_multiple_v1_candidates_any_match_passes():
    header = f"{sign(PAYLOAD)},v1=deadbeef"
    verify_webhook_signature(PAYLOAD, header, SECRET, now=NOW)


def test_boolean_form():
    assert is_valid_webhook_signature(PAYLOAD, sign(PAYLOAD), SECRET, now=NOW)
    assert not is_valid_webhook_signature(PAYLOAD + b"x", sign(PAYLOAD), SECRET, now=NOW)
